package domain

import (
	"context"
	"encoding/json"
)

// GrantTypeCIBA is the OpenID Connect CIBA token endpoint grant type.
const GrantTypeCIBA = "urn:openid:params:grant-type:ciba"

// CIBA specific OAuth error code (CIBA Core §13).
const UnknownUserID = "unknown_user_id"

// CIBAMeta is stored in DeviceCode.DeviceCodeData.Claims to mark a stored
// authorization request as a CIBA request and to bind it to the user the
// client asked to authenticate.
type CIBAMeta struct {
	CIBA           bool   `json:"ciba"`
	Subject        string `json:"sub"`
	BindingMessage string `json:"binding_message,omitempty"`
}

// ParseCIBAMeta returns the CIBA metadata of a stored request, or nil for
// plain device authorization requests.
func ParseCIBAMeta(d *DeviceCode) *CIBAMeta {
	if d == nil || d.DeviceCodeData.Claims == "" {
		return nil
	}
	var m CIBAMeta
	if err := json.Unmarshal([]byte(d.DeviceCodeData.Claims), &m); err != nil || !m.CIBA {
		return nil
	}
	return &m
}

// CIBANotifier tells the authentication device of a user that a backchannel
// authentication request awaits approval.
type CIBANotifier interface {
	NotifyAuthenticationRequest(ctx context.Context, req CIBANotification) error
}

// CIBANotification is the payload handed to a CIBANotifier.
type CIBANotification struct {
	AuthReqID      string `json:"auth_req_id"`
	UserID         string `json:"user_id"`
	ClientID       string `json:"client_id"`
	ClientName     string `json:"client_name,omitempty"`
	Scope          string `json:"scope"`
	BindingMessage string `json:"binding_message,omitempty"`
	ExpiresIn      int    `json:"expires_in"`
}
