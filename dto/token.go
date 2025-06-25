package dto

import (
	"time"
)

// TokenInfoResponse defines the structure for API responses containing token metadata.
// This mirrors ssso.TokenInfo but is part of the DTO layer.
type TokenInfoResponse struct {
	ID        string    `json:"id"`              // Unique token identifier
	TokenType string    `json:"token_type"`      // "access_token" or "refresh_token"
	ClientID  string    `json:"client_id"`       // Client that the token was issued to
	UserID    string    `json:"user_id"`         // User that authorized the token
	Scope     string    `json:"scope"`           // Authorized scopes
	IssuedAt  time.Time `json:"issued_at"`       // When the token was issued (maps from CreatedAt of ssso.Token)
	ExpiresAt time.Time `json:"expires_at"`      // When the token expires
	IsRevoked bool      `json:"is_revoked"`      // Whether token has been revoked
	Roles     []string  `json:"roles,omitempty"` // Roles associated with the token
}

// FromDomainToken converts an ssso.Token to a TokenInfoResponse.
// It intentionally omits fields like TokenValue for security in API responses.
// func FromDomainToken(token *ssso.Token) *TokenInfoResponse {
// 	if token == nil {
// 		return nil
// 	}
// 	return &TokenInfoResponse{
// 		ID:        token.ID,
// 		TokenType: token.TokenType,
// 		ClientID:  token.ClientID,
// 		UserID:    token.UserID,
// 		Scope:     token.Scope,
// 		IssuedAt:  token.CreatedAt, // Mapping CreatedAt to IssuedAt for the response context
// 		ExpiresAt: token.ExpiresAt,
// 		IsRevoked: token.IsRevoked,
// 		Roles:     token.Roles,
// 	}
// }

// FromDomainTokens converts a slice of ssso.Token to a slice of TokenInfoResponse.
// func FromDomainTokens(tokens []*ssso.Token) []*TokenInfoResponse {
// 	if tokens == nil {
// 		return nil
// 	}
// 	responses := make([]*TokenInfoResponse, len(tokens))
// 	for i, token := range tokens {
// 		responses[i] = FromDomainToken(token)
// 	}
// 	return responses
// }

// FromDomainTokenInfo converts an ssso.TokenInfo to a TokenInfoResponse.
// This is useful if the service layer already has an ssso.TokenInfo object.
// func FromDomainTokenInfo(tokenInfo *ssso.TokenInfo) *TokenInfoResponse {
// 	if tokenInfo == nil {
// 		return nil
// 	}
// 	return &TokenInfoResponse{
// 		ID:        tokenInfo.ID,
// 		TokenType: tokenInfo.TokenType,
// 		ClientID:  tokenInfo.ClientID,
// 		UserID:    tokenInfo.UserID,
// 		Scope:     tokenInfo.Scope,
// 		IssuedAt:  tokenInfo.IssuedAt,
// 		ExpiresAt: tokenInfo.ExpiresAt,
// 		IsRevoked: tokenInfo.IsRevoked,
// 		Roles:     tokenInfo.Roles,
// 	}
// }

// FromDomainTokenInfos converts a slice of ssso.TokenInfo to a slice of TokenInfoResponse.
// func FromDomainTokenInfos(tokenInfos []*ssso.TokenInfo) []*TokenInfoResponse {
// 	if tokenInfos == nil {
// 		return nil
// 	}
// 	responses := make([]*TokenInfoResponse, len(tokenInfos))
// 	for i, tokenInfo := range tokenInfos {
// 		responses[i] = FromDomainTokenInfo(tokenInfo)
// 	}
// 	return responses
// }
