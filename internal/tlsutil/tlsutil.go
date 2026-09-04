// Package tlsutil builds the gRPC listener's TLS config, optionally
// requiring client certificates (mTLS).
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ServerConfig returns a TLS 1.3+ config. When clientCAFile is set, clients
// must present a certificate signed by that CA.
func ServerConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		cfg.ClientCAs = x509.NewCertPool()
		if !cfg.ClientCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("client CA file contains no certificates")
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
