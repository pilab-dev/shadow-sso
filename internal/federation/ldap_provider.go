package federation

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-ldap/ldap/v3"
	"github.com/pilab-dev/shadow-sso/domain"
	"golang.org/x/oauth2" // Required for the interface, but not heavily used by LDAP
)

// LDAPProvider implements the OAuth2Provider interface for LDAP authentication.
// Note: LDAP is not an OAuth2 protocol, so some methods of OAuth2Provider will be
// adapted or will not be applicable.
type LDAPProvider struct {
	Config     *domain.IdentityProvider
	ldapClient LDAPClient // Interface for mockable LDAP operations
}

// NewLDAPProvider creates a new LDAPProvider.
// It requires an IdentityProvider configuration of type LDAP.
// If no LDAPClient is provided, a RealLDAPClient will be used.
func NewLDAPProvider(idpConfig *domain.IdentityProvider, client LDAPClient) (*LDAPProvider, error) {
	if idpConfig.Type != domain.IdPTypeLDAP {
		return nil, fmt.Errorf("cannot create LDAPProvider with IdP type %s", idpConfig.Type)
	}
	effectiveClient := client
	if effectiveClient == nil {
		effectiveClient = NewRealLDAPClient()
	}
	return &LDAPProvider{
		Config:     idpConfig,
		ldapClient: effectiveClient,
	}, nil
}

// Name returns the name of the provider.
func (p *LDAPProvider) Name() string {
	return p.Config.Name
}

// GetType returns the type of the provider.
func (p *LDAPProvider) GetType() domain.IdPType {
	return domain.IdPTypeLDAP
}

// GetOAuth2Config is not applicable to LDAP in the traditional sense.
func (p *LDAPProvider) GetOAuth2Config(redirectURL string) (*oauth2.Config, error) {
	return nil, fmt.Errorf("GetOAuth2Config is not applicable for LDAP provider type")
}

// GetAuthCodeURL is not applicable to LDAP.
func (p *LDAPProvider) GetAuthCodeURL(state, redirectURL string, opts ...oauth2.AuthCodeOption) (string, error) {
	return "", fmt.Errorf("GetAuthCodeURL is not applicable for LDAP provider type")
}

// ExchangeCode is not applicable to LDAP.
func (p *LDAPProvider) ExchangeCode(ctx context.Context, redirectURL string, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return nil, fmt.Errorf("ExchangeCode is not applicable for LDAP provider type")
}

// GetHttpClient is not applicable for LDAP.
func (p *LDAPProvider) GetHttpClient(ctx context.Context, token *oauth2.Token) *http.Client {
	return nil
}

// AuthenticateAndFetchUser performs LDAP authentication and retrieves user attributes.
func (p *LDAPProvider) AuthenticateAndFetchUser(ctx context.Context, username, password string) (*ExternalUserInfo, error) {
	if p.Config.LDAP.ServerURL == "" || p.Config.LDAP.UserBaseDN == "" || p.Config.LDAP.UserFilter == "" {
		return nil, ErrProviderMisconfigured
	}

	if p.ldapClient == nil {
		p.ldapClient = NewRealLDAPClient()
	}

	err := p.ldapClient.Connect(p.Config.LDAP.ServerURL, p.Config.LDAP.StartTLS, p.Config.LDAP.SkipTLSVerify)
	if err != nil {
		return nil, fmt.Errorf("ldap connection failed: %w", err)
	}
	defer p.ldapClient.Close()

	userDN := ""
	var entry *ldap.Entry
	attributesToFetch := p.collectAttributesToFetch()
	searchFilter := fmt.Sprintf(p.Config.LDAP.UserFilter, ldap.EscapeFilter(username))

	if p.Config.LDAP.BindDN != "" && p.Config.LDAP.BindPassword != "" {
		err = p.ldapClient.Bind(p.Config.LDAP.BindDN, p.Config.LDAP.BindPassword)
		if err != nil {
			return nil, fmt.Errorf("ldap admin bind failed: %w", err)
		}
		entry, err = p.ldapClient.SearchUser(p.Config.LDAP.UserBaseDN, searchFilter, attributesToFetch)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				return nil, ErrUserNotFound
			}
			return nil, fmt.Errorf("ldap user search after admin bind failed: %w", err)
		}
		userDN = entry.DN
		err = p.ldapClient.Bind(userDN, password)
		if err != nil {
			return p.handleBindError(err, userDN)
		}
	} else {
		errDirectBind := p.ldapClient.Bind(username, password)
		if errDirectBind == nil {
			entry, err = p.ldapClient.SearchUser(p.Config.LDAP.UserBaseDN, searchFilter, attributesToFetch)
			if err != nil {
				return nil, fmt.Errorf("ldap search for self failed after direct bind (username: %s, filter: %s): %w", username, searchFilter, err)
			}
			userDN = entry.DN
		} else {
			if errAnonBind := p.ldapClient.Bind("", ""); errAnonBind != nil {
				return p.handleBindError(errDirectBind, username)
			}
			entry, err = p.ldapClient.SearchUser(p.Config.LDAP.UserBaseDN, searchFilter, attributesToFetch)
			if err != nil {
				if errors.Is(err, ErrUserNotFound) {
					return nil, ErrUserNotFound
				}
				return nil, fmt.Errorf("ldap user search (anonymous) failed (direct bind also failed: %v): %w", errDirectBind, err)
			}
			userDN = entry.DN
			err = p.ldapClient.Bind(userDN, password)
			if err != nil {
				return p.handleBindError(err, userDN)
			}
		}
	}

	if entry == nil {
		return nil, ErrUserNotFound
	}
	if userDN == "" {
		return nil, fmt.Errorf("user DN not found after successful authentication steps (filter: %s)", searchFilter)
	}

	return p.populateExternalUserInfo(entry, username), nil
}

func (p *LDAPProvider) handleBindError(err error, userIdentifier string) (*ExternalUserInfo, error) {
	if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
		return nil, ErrInvalidCredentials
	}
	return nil, fmt.Errorf("ldap bind for user [%s] failed: %w", userIdentifier, err)
}

func (p *LDAPProvider) collectAttributesToFetch() []string {
	attrs := make(map[string]struct{})

	if p.Config.LDAP.AttributeUsername != "" && p.Config.LDAP.AttributeUsername != "dn" {
		attrs[p.Config.LDAP.AttributeUsername] = struct{}{}
	}
	if p.Config.LDAP.AttributeEmail != "" {
		attrs[p.Config.LDAP.AttributeEmail] = struct{}{}
	}
	if p.Config.LDAP.AttributeFirstName != "" {
		attrs[p.Config.LDAP.AttributeFirstName] = struct{}{}
	}
	if p.Config.LDAP.AttributeLastName != "" {
		attrs[p.Config.LDAP.AttributeLastName] = struct{}{}
	}
	if p.Config.LDAP.AttributeGroups != "" {
		attrs[p.Config.LDAP.AttributeGroups] = struct{}{}
	}

	result := make([]string, 0, len(attrs))
	for attr := range attrs {
		result = append(result, attr)
	}
	return result
}

func (p *LDAPProvider) populateExternalUserInfo(entry *ldap.Entry, loginUsername string) *ExternalUserInfo {
	userInfo := &ExternalUserInfo{
		ProviderUserID: entry.DN,
		RawData:        make(map[string]interface{}),
	}

	if p.Config.LDAP.AttributeEmail != "" {
		userInfo.Email = entry.GetAttributeValue(p.Config.LDAP.AttributeEmail)
	}
	if p.Config.LDAP.AttributeFirstName != "" {
		userInfo.FirstName = entry.GetAttributeValue(p.Config.LDAP.AttributeFirstName)
	}
	if p.Config.LDAP.AttributeLastName != "" {
		userInfo.LastName = entry.GetAttributeValue(p.Config.LDAP.AttributeLastName)
	}

	if p.Config.LDAP.AttributeUsername != "" && p.Config.LDAP.AttributeUsername != "dn" {
		ldapUsernameVal := entry.GetAttributeValue(p.Config.LDAP.AttributeUsername)
		if ldapUsernameVal != "" {
			userInfo.Username = ldapUsernameVal
		} else {
			userInfo.Username = loginUsername
		}
	} else {
		userInfo.Username = loginUsername
	}

	for _, attr := range entry.Attributes {
		if len(attr.Values) == 1 {
			userInfo.RawData[attr.Name] = attr.Values[0]
		} else if len(attr.Values) > 1 {
			userInfo.RawData[attr.Name] = attr.Values
		}
	}
	return userInfo
}

func (p *LDAPProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*ExternalUserInfo, error) {
	return nil, fmt.Errorf("FetchUserInfo is not directly applicable to LDAP provider using username/password. Use AuthenticateAndFetchUser.")
}

var _ OAuth2Provider = (*LDAPProvider)(nil)

type LDAPClient interface {
	Connect(url string, startTLS bool, skipTLSVerify bool) error
	Bind(username, password string) error
	SearchUser(baseDN, filter string, attributes []string) (*ldap.Entry, error)
	Close()
}

type RealLDAPClient struct {
	conn *ldap.Conn
}

func NewRealLDAPClient() LDAPClient {
	return &RealLDAPClient{}
}

func (r *RealLDAPClient) Connect(url string, startTLS bool, skipTLSVerify bool) error {
	var err error
	tlsCfg := &tls.Config{InsecureSkipVerify: skipTLSVerify}

	r.conn, err = ldap.DialURL(url)
	if err != nil {
		return fmt.Errorf("ldap connection to %s failed: %w", url, err)
	}

	if startTLS && r.conn != nil && !r.conn.IsClosing() {
		if errTLS := r.conn.StartTLS(tlsCfg); errTLS != nil {
			r.conn.Close()
			r.conn = nil
			return fmt.Errorf("ldap starttls for %s failed: %w", url, errTLS)
		}
	}
	return nil
}

func (r *RealLDAPClient) Bind(username, password string) error {
	if r.conn == nil {
		return fmt.Errorf("ldap connection not established for bind")
	}
	return r.conn.Bind(username, password)
}

func (r *RealLDAPClient) SearchUser(baseDN, filter string, attributes []string) (*ldap.Entry, error) {
	if r.conn == nil {
		return nil, fmt.Errorf("ldap connection not established for search")
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	sr, err := r.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("ldap search failed (filter: %s): %w", filter, err)
	}

	if len(sr.Entries) == 0 {
		return nil, ErrUserNotFound
	}
	if len(sr.Entries) > 1 {
		return nil, fmt.Errorf("ldap search returned %d entries for filter '%s', expected 1", len(sr.Entries), filter)
	}

	return sr.Entries[0], nil
}

func (r *RealLDAPClient) Close() {
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
	}
}

// Ensure RealLDAPClient satisfies the LDAPClient interface (compile-time check)
var _ LDAPClient = (*RealLDAPClient)(nil)
