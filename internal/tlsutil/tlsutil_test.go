package tlsutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type pki struct{ ca, server, client string } // PEM file paths (key next to cert as .key)

// genPKI writes a CA, a server cert for 127.0.0.1 and a client cert to dir.
func genPKI(t *testing.T, dir string) pki {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	write := func(name string, tmpl, parent *x509.Certificate, key, parentKey *ecdsa.PrivateKey) string {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		kb, _ := x509.MarshalECPrivateKey(key)
		p := filepath.Join(dir, name)
		os.WriteFile(p+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
		os.WriteFile(p+".key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
		return p
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: now, NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caKey := newKey()
	ca := write("ca", caTmpl, caTmpl, caKey, caKey)
	leaf := func(serial int64, cn string, usage x509.ExtKeyUsage) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: now, NotAfter: now.Add(time.Hour),
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
	}
	return pki{ca: ca, server: write("server", leaf(2, "gatekeeper", x509.ExtKeyUsageServerAuth), caTmpl, newKey(), caKey),
		client: write("client", leaf(3, "svc-a", x509.ExtKeyUsageClientAuth), caTmpl, newKey(), caKey)}
}

func TestMTLSRequiresClientCert(t *testing.T) {
	k := genPKI(t, t.TempDir())
	cfg, err := ServerConfig(k.server+".crt", k.server+".key", k.ca+".crt")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	healthpb.RegisterHealthServer(gs, health.NewServer())
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	go gs.Serve(lis)
	defer gs.Stop()

	caPEM, _ := os.ReadFile(k.ca + ".crt")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	call := func(certs []tls.Certificate) error {
		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS13})))
		if err != nil {
			return err
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
		return err
	}
	if err := call(nil); err == nil {
		t.Fatal("connection without client cert must be rejected")
	}
	clientCert, err := tls.LoadX509KeyPair(k.client+".crt", k.client+".key")
	if err != nil {
		t.Fatal(err)
	}
	if err := call([]tls.Certificate{clientCert}); err != nil {
		t.Fatalf("connection with client cert failed: %v", err)
	}
	if _, err := ServerConfig(k.server+".crt", k.server+".key", k.server+".key"); err == nil {
		t.Fatal("non-cert PEM as client CA must be rejected")
	}
}
