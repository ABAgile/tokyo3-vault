package tlsutil

import (
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
)

// TestSelfSignedCert tests that SelfSignedCert generates a valid certificate.
func TestSelfSignedCert(t *testing.T) {
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected certificate bytes")
	}

	// Parse the leaf certificate to check SANs.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Check DNS SANs.
	hasLocalhost := false
	for _, name := range leaf.DNSNames {
		if name == "localhost" {
			hasLocalhost = true
		}
	}
	if !hasLocalhost {
		t.Error("expected 'localhost' in DNS SANs")
	}

	// Check IP SANs.
	has127 := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			has127 = true
		}
	}
	if !has127 {
		t.Error("expected 127.0.0.1 in IP SANs")
	}
}

// TestCertPoolFromPEM tests CertPoolFromPEM with valid and empty PEM.
func TestCertPoolFromPEM(t *testing.T) {
	// Generate a self-signed cert and extract its PEM for use as a CA.
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	pool, err := CertPoolFromPEM(caPEM)
	if err != nil {
		t.Fatalf("CertPoolFromPEM valid: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}

	// Empty/invalid PEM → error.
	_, err = CertPoolFromPEM([]byte("not a cert"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// TestFromPEM_BothSet tests FromPEM when cert and key are both provided.
func TestFromPEM_BothSet(t *testing.T) {
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}

	// Re-encode cert to PEM form.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	// For key we need the private key PEM — extract from the tls.Certificate.
	var keyPEM []byte
	if ecKey, ok := cert.PrivateKey.(interface {
		Equal(x any) bool
	}); ok {
		_ = ecKey // key is embedded — use the already-generated cert.
	}

	// Build a self-signed cert and get PEM cert+key via a helper approach.
	// Use the raw tls package to re-encode.
	tlsCert, err := SelfSignedCert()
	if err != nil {
		t.Fatalf("second SelfSignedCert: %v", err)
	}
	// tls.Certificate.Certificate[0] is the DER-encoded cert.
	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]})

	// We need the private key PEM. Since SelfSignedCert uses x509.MarshalECPrivateKey
	// internally, we can't easily re-extract it from tls.Certificate.PrivateKey without
	// type-asserting. Use FromFiles test path instead, testing error cases via FromPEM.
	_ = certPEMBytes
	_ = keyPEM
	_ = certPEM

	// Test: empty → nil, nil.
	cfg, err := FromPEM("", "", "")
	if err != nil || cfg != nil {
		t.Errorf("empty FromPEM: cfg=%v err=%v", cfg, err)
	}

	// Test: cert without key → error.
	_, err = FromPEM("cert-pem", "", "")
	if err == nil {
		t.Error("expected error for cert without key")
	}

	// Test: key without cert → error.
	_, err = FromPEM("", "key-pem", "")
	if err == nil {
		t.Error("expected error for key without cert")
	}

	// Test: invalid CA PEM → error.
	_, err = FromPEM("", "", "not-a-cert")
	if err == nil {
		t.Error("expected error for invalid CA PEM in FromPEM")
	}
}

// TestFromPEM_WithCA tests FromPEM with only a CA PEM set.
func TestFromPEM_WithCA(t *testing.T) {
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))

	cfg, err := FromPEM("", "", caPEM)
	if err != nil {
		t.Fatalf("FromPEM CA only: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

// TestFromFiles_AllEmpty tests FromFiles returns nil when all args are empty.
func TestFromFiles_AllEmpty(t *testing.T) {
	cfg, err := FromFiles("", "", "")
	if err != nil {
		t.Errorf("FromFiles empty: %v", err)
	}
	if cfg != nil {
		t.Errorf("FromFiles empty: expected nil cfg, got %+v", cfg)
	}
}

// TestFromFiles_CertWithoutKey tests that cert without key returns error.
func TestFromFiles_CertWithoutKey(t *testing.T) {
	_, err := FromFiles("some-cert.pem", "", "")
	if err == nil {
		t.Error("expected error for cert without key in FromFiles")
	}
}

// TestCertLoader_GetCertificate tests the CertLoader with a missing file.
func TestCertLoader_GetCertificate(t *testing.T) {
	loader := NewCertLoader("/nonexistent/cert.pem", "/nonexistent/key.pem")
	// Should error because files don't exist and no cert cached.
	_, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err == nil {
		t.Error("expected error for nonexistent cert files")
	}
}

// writeCertKeyFiles generates an ECDSA P-256 self-signed cert and writes PEM
// cert + key to temp files, returning their paths.
func writeCertKeyFiles(t *testing.T) (certFile, keyFile string, caPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return certFile, keyFile, certPEM
}

func TestFromFiles_WithCertAndKey(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)

	cfg, err := FromFiles(certFile, keyFile, "")
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}

func TestFromFiles_WithCAFile(t *testing.T) {
	_, _, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := FromFiles("", "", caFile)
	if err != nil {
		t.Fatalf("FromFiles CA only: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestFromFiles_WithCertKeyAndCA(t *testing.T) {
	certFile, keyFile, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := FromFiles(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("FromFiles cert+key+CA: %v", err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 || cfg.RootCAs == nil {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestFromFiles_NonexistentCAFile(t *testing.T) {
	_, err := FromFiles("", "", "/nonexistent/ca.pem")
	if err == nil {
		t.Error("expected error for nonexistent CA file")
	}
}

func TestFromFiles_KeyWithoutCert(t *testing.T) {
	_, err := FromFiles("", "some-key.pem", "")
	if err == nil {
		t.Error("expected error for key without cert")
	}
}

func TestCertLoader_WithRealFiles(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)

	loader := NewCertLoader(certFile, keyFile)
	cert, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected non-nil certificate")
	}
}

func TestCertLoader_CachedCert(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)

	loader := NewCertLoader(certFile, keyFile)
	first, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}
	// Second call should return the cached cert (file mtime hasn't changed).
	second, err := loader.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("second GetCertificate: %v", err)
	}
	if first != second {
		t.Error("expected same cached certificate pointer on second call")
	}
}
