package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/browserpolicy"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BrowserPolicyServer manages the realm's browser baseline policy.
type BrowserPolicyServer struct {
	ssov1connect.UnimplementedBrowserPolicyServiceHandler
	realmSettingsRepo domain.RealmSettingsRepository
	provider          *browserpolicy.Provider
}

// NewBrowserPolicyServer creates the policy service. provider is shared with
// the HTTP middleware so updates take effect without a restart.
func NewBrowserPolicyServer(repo domain.RealmSettingsRepository, provider *browserpolicy.Provider) *BrowserPolicyServer {
	return &BrowserPolicyServer{realmSettingsRepo: repo, provider: provider}
}

func (s *BrowserPolicyServer) GetBrowserPolicy(ctx context.Context, _ *connect.Request[ssov1.GetBrowserPolicyRequest]) (*connect.Response[ssov1.GetBrowserPolicyResponse], error) {
	settings, err := s.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to load realm settings: %w", err))
	}
	resp := &ssov1.GetBrowserPolicyResponse{Defaults: browserpolicy.DefaultMinVersions()}
	if settings != nil && settings.BrowserPolicy != nil {
		resp.Policy = toBrowserPolicyProto(settings.BrowserPolicy)
	}
	return connect.NewResponse(resp), nil
}

func (s *BrowserPolicyServer) UpdateBrowserPolicy(ctx context.Context, req *connect.Request[ssov1.UpdateBrowserPolicyRequest]) (*connect.Response[ssov1.UpdateBrowserPolicyResponse], error) {
	settings, err := s.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to load realm settings: %w", err))
	}
	if settings == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("realm settings are not initialized"))
	}

	if req.Msg.GetReset_() {
		settings.BrowserPolicy = nil
	} else {
		policy := fromBrowserPolicyProto(req.Msg.GetPolicy())
		if err := validateBrowserPolicy(policy); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		policy.UpdatedAt = time.Now().UTC()
		settings.BrowserPolicy = policy
	}
	if err := s.realmSettingsRepo.UpdateRealmSettings(ctx, settings); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update realm settings: %w", err))
	}
	if s.provider != nil {
		s.provider.Invalidate()
	}

	action := "BrowserPolicyUpdated"
	if settings.BrowserPolicy == nil {
		action = "BrowserPolicyReset"
	}
	audit.Log("BrowserPolicy", action, "", "browser-policy", summarizePolicy(settings.BrowserPolicy), true, nil)
	return connect.NewResponse(&ssov1.UpdateBrowserPolicyResponse{
		Policy: toBrowserPolicyProto(settings.BrowserPolicy),
	}), nil
}

func (s *BrowserPolicyServer) CheckBrowser(ctx context.Context, req *connect.Request[ssov1.CheckBrowserRequest]) (*connect.Response[ssov1.CheckBrowserResponse], error) {
	var policy *domain.BrowserPolicy
	if s.provider != nil {
		policy = s.provider.Policy(ctx)
	}
	d := browserpolicy.Evaluate(req.Msg.GetUserAgent(), policy)
	return connect.NewResponse(&ssov1.CheckBrowserResponse{
		Allowed:         d.Allowed && !d.Blocked(),
		Reason:          d.Reason,
		Browser:         d.Info.Browser,
		BrowserVersion:  d.Info.Version,
		Os:              d.Info.OS,
		DeviceType:      d.Info.DeviceType,
		IsBot:           d.Info.IsBot,
		RequiredVersion: d.Required,
		Enforcement:     d.Enforcement,
	}), nil
}

func validateBrowserPolicy(policy *domain.BrowserPolicy) error {
	if policy == nil {
		return nil
	}
	switch policy.Enforcement {
	case "", domain.BrowserPolicyEnforcementBlock, domain.BrowserPolicyEnforcementWarn:
	default:
		return fmt.Errorf("enforcement must be %q or %q", domain.BrowserPolicyEnforcementBlock, domain.BrowserPolicyEnforcementWarn)
	}
	for browser, version := range policy.MinVersions {
		if strings.TrimSpace(browser) == "" {
			return errors.New("min_versions contains an empty browser name")
		}
		if !isNumericVersion(version) {
			return fmt.Errorf("min_versions[%s] must be a numeric major version, got %q", browser, version)
		}
	}
	for _, exempt := range policy.ExemptUserAgents {
		if len(strings.TrimSpace(exempt)) < 2 {
			return fmt.Errorf("exempt_user_agents entry %q is too short", exempt)
		}
	}
	return nil
}

func isNumericVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return false
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func toBrowserPolicyProto(p *domain.BrowserPolicy) *ssov1.BrowserPolicy {
	if p == nil {
		return nil
	}
	minVersions := make(map[string]string, len(p.MinVersions))
	for k, v := range p.MinVersions {
		minVersions[k] = v
	}
	out := &ssov1.BrowserPolicy{
		Enabled:          p.Enabled,
		Enforcement:      p.Enforcement,
		BlockUnknown:     p.BlockUnknown,
		BlockBots:        p.BlockBots,
		MinVersions:      minVersions,
		ExemptUserAgents: append([]string(nil), p.ExemptUserAgents...),
		UpdatedAt:        timestamppb.New(p.UpdatedAt),
	}
	return out
}

func fromBrowserPolicyProto(p *ssov1.BrowserPolicy) *domain.BrowserPolicy {
	if p == nil {
		return nil
	}
	minVersions := make(map[string]string, len(p.GetMinVersions()))
	for k, v := range p.GetMinVersions() {
		minVersions[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	out := &domain.BrowserPolicy{
		Enabled:          p.GetEnabled(),
		Enforcement:      strings.ToLower(strings.TrimSpace(p.GetEnforcement())),
		BlockUnknown:     p.GetBlockUnknown(),
		BlockBots:        p.GetBlockBots(),
		MinVersions:      minVersions,
		ExemptUserAgents: append([]string(nil), p.GetExemptUserAgents()...),
	}
	if out.Enforcement == "" {
		out.Enforcement = domain.BrowserPolicyEnforcementBlock
	}
	return out
}

func summarizePolicy(p *domain.BrowserPolicy) string {
	if p == nil {
		return "policy reset"
	}
	keys := make([]string, 0, len(p.MinVersions))
	for k := range p.MinVersions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+p.MinVersions[k])
	}
	return fmt.Sprintf("enabled=%t enforcement=%s block_unknown=%t block_bots=%t min_versions=[%s]",
		p.Enabled, p.Enforcement, p.BlockUnknown, p.BlockBots, strings.Join(pairs, ","))
}
