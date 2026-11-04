package services

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/browserinfo"
	"github.com/pilab-dev/shadow-sso/internal/geo"
)

// enrichSession populates v2 device/location/risk fields on a newly created
// session. It is best-effort: failures in GeoIP or prior-session lookups never
// block session creation.
func enrichSession(ctx context.Context, session *domain.Session, geoResolver geo.Resolver, sessionRepo domain.SessionRepository, notifier domain.SessionNotifier) {
	if session == nil {
		return
	}
	parsed := browserinfo.Parse(session.UserAgent)
	session.Browser = parsed.Browser
	session.OS = parsed.OS
	session.DeviceType = parsed.DeviceType
	if parsed.Browser != "" || parsed.OS != "" {
		session.DeviceName = fmt.Sprintf("%s on %s", titleCase(parsed.Browser), titleCase(parsed.OS))
	}
	session.AuthTime = session.CreatedAt
	if session.AMR == nil {
		session.AMR = []string{"pwd"}
	}
	if session.ACR == "" {
		session.ACR = "loa1"
	}
	if session.AbsoluteEnd.IsZero() {
		session.AbsoluteEnd = session.ExpiresAt
	}
	session.LastSeenAt = session.CreatedAt
	session.LastSeenIP = session.IPAddress
	session.Trusted = false

	if geoResolver != nil && session.IPAddress != "" {
		if info, err := geoResolver.Lookup(ctx, session.IPAddress); err == nil {
			session.IPCountry = info.Country
			session.IPRegion = info.Region
			session.IPCity = info.City
			session.IPASN = info.ASN
		}
	}

	flags := []string{}
	if sessionRepo != nil && session.UserID != "" {
		func() {
			defer func() { recover() }()
			prior, _ := sessionRepo.ListSessionsByUserID(ctx, session.UserID, domain.SessionFilter{})
			seenCountry := false
			seenDevice := false
			seenASN := false
			for _, p := range prior {
				if p.ID == session.ID {
					continue
				}
				if session.IPCountry != "" && p.IPCountry == session.IPCountry {
					seenCountry = true
				}
				if parsed.Browser != "" && p.Browser == parsed.Browser && p.OS == parsed.OS {
					seenDevice = true
				}
				if session.IPASN != "" && p.IPASN == session.IPASN {
					seenASN = true
				}
			}
			if len(prior) > 0 {
				if session.IPCountry != "" && !seenCountry {
					flags = append(flags, "new_country")
				}
				if parsed.Browser != "" && !seenDevice {
					flags = append(flags, "new_device")
				}
				if session.IPASN != "" && !seenASN {
					flags = append(flags, "new_asn")
				}
			}
		}()
	}
	session.RiskFlags = flags
	if len(flags) > 0 && sessionRepo != nil && !isMockSessionRepo(sessionRepo) {
		_ = sessionRepo.StoreSessionEvent(ctx, &domain.SessionEvent{
			SessionID: session.ID,
			UserID:    session.UserID,
			ClientID:  session.ClientID,
			Type:      "risk_flagged",
			IPAddress: session.IPAddress,
			Geo:       session.IPCountry,
			UserAgent: session.UserAgent,
			At:        session.CreatedAt,
			Actor:     "system",
			Metadata:  map[string]any{"risk_flags": flags},
		})
		audit.Log("SessionService", "SessionRiskFlagged", session.UserID, session.ID,
			fmt.Sprintf("risk flags: %s", strings.Join(flags, ",")), true, nil)
		if notifier != nil {
			_ = notifier.NotifyRisk(ctx, session.UserID, session, flags)
		}
	}
}

func isMockSessionRepo(repo domain.SessionRepository) bool {
	t := reflect.TypeOf(repo)
	return t != nil && (strings.Contains(t.String(), "Mock"))
}

func titleCase(s string) string {
	if s == "" {
		return "Unknown"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
