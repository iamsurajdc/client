package service

import (
	"net"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/go-framed-msgpack-rpc/rpc"
	"golang.org/x/net/context"
)

// connTransport implements rpc.ConnectionTransport
type connTransport struct {
	libkb.Contextified
	host            string
	maxFrameLength  int32
	conn            net.Conn
	transport       rpc.Transporter
	stagedTransport rpc.Transporter
}

var _ rpc.ConnectionTransport = (*connTransport)(nil)

func newConnTransport(g *libkb.GlobalContext, host string, maxFrameLength int32) *connTransport {
	return &connTransport{
		Contextified:   libkb.NewContextified(g),
		host:           host,
		maxFrameLength: maxFrameLength,
	}
}

func (t *connTransport) Dial(context.Context) (rpc.Transporter, error) {
	var err error
	t.conn, err = net.Dial("tcp", t.host)
	if err != nil {
		return nil, err
	}
	t.stagedTransport = rpc.NewTransport(t.conn, libkb.NewRPCLogFactory(t.G()), libkb.MakeWrapError(t.G()), t.maxFrameLength)
	return t.stagedTransport, nil
}

func (t *connTransport) IsConnected() bool {
	return t.transport != nil && t.transport.IsConnected()
}

func (t *connTransport) Finalize() {
	t.transport = t.stagedTransport
	t.stagedTransport = nil
}

func (t *connTransport) Close() {
	t.conn.Close()
}

func (t *connTransport) Reset() {
	t.transport = nil
}
