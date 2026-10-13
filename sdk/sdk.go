// Package sdk is the Go client for gatekeeper. The RPC surface (Client's
// embedded GatekeeperClient and every request/response type) is generated
// from api/gatekeeper/v1/gatekeeper.proto; this package only adds dialing and
// bearer auth. gkctl and the Terraform provider are built on it.
package sdk

import (
	"context"
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
)

type Client struct {
	pb.GatekeeperClient
	conn *grpc.ClientConn
}

type Options struct {
	Token string
	// TLS nil means plaintext (local dev, sidecar on localhost).
	TLS *tls.Config
}

// Dial connects lazily; the first RPC surfaces connection errors.
func Dial(addr string, o Options) (*Client, error) {
	creds := insecure.NewCredentials()
	if o.TLS != nil {
		creds = credentials.NewTLS(o.TLS)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds), grpc.WithUnaryInterceptor(bearer(o.Token)))
	if err != nil {
		return nil, err
	}
	return &Client{GatekeeperClient: pb.NewGatekeeperClient(conn), conn: conn}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func bearer(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, inv grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		}
		return inv(ctx, method, req, reply, cc, opts...)
	}
}

func IsNotFound(err error) bool { return status.Code(err) == codes.NotFound }
