package directory

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/pilab-dev/shadow-sso/domain"
	accountsv1 "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/accounts/v1"
	credentialsv1 "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/credentials/v1"
	"github.com/pilab-dev/shadow-sso/internal/identity"
)

// IdentitySource is implemented by Source.
var _ identity.IdentitySource = (*Source)(nil)

// Resolve implements identity.IdentitySource. It is the only call made before
// authentication and returns identity only: accounts.ResolveLogin is
// service-only, so it needs no acting principal and no privileged lookup
// account.
func (s *Source) Resolve(ctx context.Context, login string) (*identity.Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := s.accounts.ResolveLogin(ctx, connect.NewRequest(&accountsv1.ResolveLoginRequest{
		Login: strings.TrimSpace(login),
	}))
	if err != nil {
		return nil, mapError(err)
	}
	m := resp.Msg
	return &identity.Identity{
		ID:     m.GetId(),
		DN:     m.GetDn(),
		Class:  m.GetClass(),
		Status: statusOf(m.GetEnabled()),
		Login:  m.GetLogin(),
		UPN:    m.GetUpn(),
		Email:  m.GetMail(),
	}, nil
}

// Authenticate implements identity.IdentitySource. The password goes to
// pir-credentials and never comes back: there is no hash here to leak.
func (s *Source) Authenticate(ctx context.Context, ident *identity.Identity, password string) (*identity.AuthResult, error) {
	if ident == nil || ident.ID == "" {
		// An unknown principal is reported exactly like a wrong password.
		return &identity.AuthResult{Code: identity.CodeInvalid}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := s.credentials.VerifyPassword(ctx, connect.NewRequest(&credentialsv1.VerifyPasswordRequest{
		PrincipalId: ident.ID,
		Password:    password,
		Context:     &credentialsv1.AuthContext{Protocol: "oidc"},
	}))
	if err != nil {
		return nil, mapError(err)
	}
	m := resp.Msg
	res := &identity.AuthResult{MustChange: m.GetMustChange()}
	if until := m.GetLockedUntil(); until != nil {
		res.LockedUntil = until.AsTime()
	}
	switch m.GetResult() {
	case credentialsv1.VerifyResult_VERIFY_RESULT_OK:
		res.Code = identity.CodeOK
	case credentialsv1.VerifyResult_VERIFY_RESULT_LOCKED:
		res.Code = identity.CodeLocked
	case credentialsv1.VerifyResult_VERIFY_RESULT_EXPIRED:
		res.Code = identity.CodeExpired
	default:
		res.Code = identity.CodeInvalid
	}
	return res, nil
}

// ChangePassword implements identity.PasswordChanger. The directory checks the
// current password, applies its policy and history, and derives its keys.
func (s *Source) ChangePassword(ctx context.Context, id, oldPassword, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := s.credentials.ChangePassword(ctx, connect.NewRequest(&credentialsv1.ChangePasswordRequest{
		PrincipalId: id,
		OldPassword: oldPassword,
		NewPassword: newPassword,
		Context:     &credentialsv1.AuthContext{Protocol: "oidc"},
	}))
	if err != nil {
		return mapError(err)
	}
	switch resp.Msg.GetResult() {
	case credentialsv1.VerifyResult_VERIFY_RESULT_OK:
	case credentialsv1.VerifyResult_VERIFY_RESULT_LOCKED:
		return identity.ErrLocked
	default:
		return domain.ErrIncorrectPassword
	}
	if v := resp.Msg.GetPolicyViolations(); len(v) > 0 {
		return &domain.PasswordPolicyError{Violations: v}
	}
	return nil
}

// CompleteForcedChange implements identity.PasswordChanger. The directory
// allows the SSO to set a password only for an account flagged must_change.
func (s *Source) CompleteForcedChange(ctx context.Context, id, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := s.credentials.SetPassword(ctx, connect.NewRequest(&credentialsv1.SetPasswordRequest{
		PrincipalId: id,
		NewPassword: newPassword,
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodePermissionDenied {
			return domain.ErrPasswordChangeNotAllowed
		}
		return mapError(err)
	}
	if v := resp.Msg.GetPolicyViolations(); len(v) > 0 {
		return &domain.PasswordPolicyError{Violations: v}
	}
	return nil
}

// Get implements identity.IdentitySource. It reads as the identity itself, so
// the directory's object ACLs decide what the SSO may see of it.
func (s *Source) Get(ctx context.Context, id string) (*identity.Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := s.accounts.Get(withPrincipal(ctx, id), connect.NewRequest(&accountsv1.GetRequest{
		Key: &accountsv1.GetRequest_Id{Id: id},
	}))
	if err != nil {
		return nil, mapError(err)
	}
	obj := resp.Msg.GetObject()
	if obj == nil {
		return nil, identity.ErrNotFound
	}
	attrs := attributes(obj)
	ident := &identity.Identity{
		ID:         obj.GetId(),
		DN:         obj.GetDn(),
		Class:      obj.GetClass(),
		Status:     statusOf(enabled(attrs)),
		Attributes: attrs,
		USN:        resp.Msg.GetAppliedUsn(),
	}
	ident.Login = first(attrs, "sAMAccountName")
	ident.UPN = first(attrs, "userPrincipalName")
	ident.Email = first(attrs, "mail")
	ident.GivenName = first(attrs, "givenName")
	ident.Surname = first(attrs, "sn")
	return ident, nil
}

// Memberships implements identity.IdentitySource. It is transitive when asked
// for, and reads as the identity itself.
func (s *Source) Memberships(ctx context.Context, id string, transitive bool) ([]identity.Group, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := s.accounts.ResolveMembership(withPrincipal(ctx, id), connect.NewRequest(&accountsv1.ResolveMembershipRequest{
		Id:         id,
		Transitive: transitive,
	}))
	if err != nil {
		return nil, mapError(err)
	}
	refs := resp.Msg.GetGroups()
	groups := make([]identity.Group, 0, len(refs))
	for _, ref := range refs {
		groups = append(groups, identity.Group{
			ID:    ref.GetId(),
			Name:  commonName(ref.GetDn()),
			SID:   ref.GetSid(),
			DN:    ref.GetDn(),
			Depth: int(ref.GetDepth()),
		})
	}
	return groups, nil
}

// mapError folds a Connect error onto the port's failures. Anything that is
// not "no such identity" is a source failure and is never reported as a
// credential problem: a directory outage must not read as a wrong password.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	switch connect.CodeOf(err) {
	case connect.CodeNotFound, connect.CodeInvalidArgument:
		return identity.ErrNotFound
	default:
		return fmt.Errorf("%w: %v", identity.ErrUnavailable, err)
	}
}

func statusOf(enabled bool) domain.UserStatus {
	if enabled {
		return domain.UserStatusActive
	}
	return domain.UserStatusLocked
}

// enabled reads the `enabled` attribute. A directory without it (or an object
// that does not carry it) counts as enabled, which is what ResolveLogin
// reports too.
func enabled(attrs map[string][]string) bool {
	v, ok := first2(attrs, "enabled")
	if !ok {
		return true
	}
	return !strings.EqualFold(v, "false")
}

func attributes(obj *accountsv1.Object) map[string][]string {
	out := make(map[string][]string, len(obj.GetAttributes()))
	for _, attr := range obj.GetAttributes() {
		values := make([]string, 0, len(attr.GetValues()))
		for _, v := range attr.GetValues() {
			if s := valueString(v); s != "" {
				values = append(values, s)
			}
		}
		if len(values) > 0 {
			out[attr.GetName()] = values
		}
	}
	return out
}

func valueString(v *accountsv1.Value) string {
	switch k := v.GetKind().(type) {
	case *accountsv1.Value_StringValue:
		return k.StringValue
	case *accountsv1.Value_IntValue:
		return strconv.FormatInt(k.IntValue, 10)
	case *accountsv1.Value_BoolValue:
		return strconv.FormatBool(k.BoolValue)
	case *accountsv1.Value_BytesValue:
		return string(k.BytesValue)
	case *accountsv1.Value_TimeValue:
		return k.TimeValue.AsTime().UTC().Format(time.RFC3339)
	default:
		return ""
	}
}

// first is a case-insensitive attribute lookup: the directory answers with
// the schema's spelling, callers ask for the one they know.
func first(attrs map[string][]string, name string) string {
	if v, ok := first2(attrs, name); ok {
		return v
	}
	return ""
}

func first2(attrs map[string][]string, name string) (string, bool) {
	for k, values := range attrs {
		if strings.EqualFold(k, name) && len(values) > 0 {
			return values[0], true
		}
	}
	return "", false
}

// commonName is the value of the first RDN of a DN, which is how a group's
// name is spelled for a claim: "cn=engineering,cn=Users,dc=pi,dc=lab" is
// "engineering". Escaped separators are honoured; a DN whose first RDN has no
// attribute yields the DN itself.
func commonName(dn string) string {
	rdn, ok := firstRDN(dn)
	if !ok {
		return dn
	}
	for i := 0; i < len(rdn); i++ {
		if rdn[i] == '\\' {
			i++ // the next byte is escaped and literal
			continue
		}
		if rdn[i] == '=' {
			return unescape(rdn[i+1:])
		}
	}
	return dn
}

// firstRDN returns the component of dn before its first unescaped comma.
func firstRDN(dn string) (string, bool) {
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++ // the next byte is escaped and literal
		case ',':
			return dn[:i], true
		}
	}
	return dn, dn != ""
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
