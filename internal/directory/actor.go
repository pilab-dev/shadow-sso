package directory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/common/v1"
)

// Header is the ActorContext header PiRectory's gateways use.
const Header = "Pirectory-Actor"

// nonceSize matches PiRectory's actor.NonceSize.
const nonceSize = 16

// signer signs ActorContexts as this gateway. The wire format is a public
// contract of accounts.v1, so message() is a faithful copy of PiRectory's
// pkg/actor: the bytes are the ones pir-accounts verifies, and a change on
// either side breaks every call.
type signer struct {
	id  string
	key ed25519.PrivateKey
}

// principal is the directory principal an outgoing call is made for.
type principal struct{ id string }

type principalKey struct{}

// withPrincipal returns ctx carrying the principal the next outgoing call is
// made for. The adapter sets it to the identity it reads on behalf of; calls
// without it go out service-only, which is all ResolveLogin and
// VerifyPassword need.
func withPrincipal(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, principalKey{}, principal{id: id})
}

func fromPrincipal(ctx context.Context) (string, bool) {
	p, ok := ctx.Value(principalKey{}).(principal)
	return p.id, ok && p.id != ""
}

// interceptor attaches a freshly signed ActorContext to every outgoing call
// whose context carries a principal.
func (s *signer) interceptor() connect.Interceptor { return signing{s} }

type signing struct{ s *signer }

func (g signing) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		id, ok := fromPrincipal(ctx)
		if ok {
			header, err := g.s.header(req.Spec().Procedure, id)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			req.Header().Set(Header, header)
		}
		return next(ctx, req)
	}
}

func (g signing) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec) // the adapter only makes unary calls
	}
}

func (g signing) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// header is the base64 ActorContext of id for one procedure.
func (s *signer) header(procedure, id string) (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("directory: nonce: %w", err)
	}
	a := &commonv1.ActorContext{
		PrincipalId: id,
		AuthMethod:  "oidc",
		IssuedAt:    timestamppb.New(time.Now()),
		Nonce:       nonce,
		Signer:      s.id,
	}
	a.Signature = ed25519.Sign(s.key, message(procedure, a))
	raw, err := proto.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("directory: actor context: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// message is the byte string that is signed: a domain tag, the procedure and
// every field, length-prefixed so no two contexts share an encoding.
func message(procedure string, a *commonv1.ActorContext) []byte {
	b := []byte("pirectory-actor-v1")
	add := func(p []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p))) //nolint:gosec // G115: header-sized fields
		b = append(b, p...)
	}
	add([]byte(procedure))
	add([]byte(a.GetPrincipalId()))
	add([]byte(a.GetAuthMethod()))
	add([]byte(a.GetSessionId()))
	add(binary.BigEndian.AppendUint64(nil, uint64(a.GetIssuedAt().AsTime().UnixNano()))) //nolint:gosec // G115: a post-1970 instant
	add(a.GetNonce())
	add([]byte(a.GetSigner()))
	return b
}
