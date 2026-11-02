package graphql

import (
	"net/http"
	"time"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/gorilla/websocket"
)

// gorillaWebsocketImplementation adapts gorilla/websocket to the gqlgen
// transport.WebsocketImplementation interface. This keeps the existing
// gorilla-based server while using gqlgen's newer websocket transport API.
type gorillaWebsocketImplementation struct {
	upgrader websocket.Upgrader
}

var _ transport.WebsocketImplementation = gorillaWebsocketImplementation{}

func (u gorillaWebsocketImplementation) Accept(
	w http.ResponseWriter,
	r *http.Request,
	options transport.WebsocketAcceptOptions,
) (transport.WebsocketConn, error) {
	for key, values := range options.ResponseHeader {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	upgrader := u.upgrader
	upgrader.Subprotocols = append([]string(nil), u.upgrader.Subprotocols...)
	for _, subprotocol := range options.Subprotocols {
		if !containsString(upgrader.Subprotocols, subprotocol) {
			upgrader.Subprotocols = append(upgrader.Subprotocols, subprotocol)
		}
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	return gorillaWebsocketConn{Conn: conn}, nil
}

type gorillaWebsocketConn struct {
	*websocket.Conn
}

var (
	_ transport.WebsocketConn          = gorillaWebsocketConn{}
	_ transport.WebsocketReadLimiter   = gorillaWebsocketConn{}
	_ transport.WebsocketReadDeadliner = gorillaWebsocketConn{}
)

func (c gorillaWebsocketConn) WriteClose(closeCode int, message string) error {
	return c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(closeCode, message))
}

func (c gorillaWebsocketConn) SetReadLimit(limit int64) {
	c.Conn.SetReadLimit(limit)
}

func (c gorillaWebsocketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}
