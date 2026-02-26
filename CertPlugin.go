package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/log"
)

var logger = log.Get()

const (
	// DefaultCertHeader is the default HTTP header containing the PEM-encoded client certificate.
	DefaultCertHeader = "X-Client-Cert"

	// EnvCertHeader overrides the header name used to read the client certificate.
	EnvCertHeader = "TYK_CERT_HEADER"

	// EnvCABundlePath sets the file path to the trusted CA certificate bundle (PEM).
	EnvCABundlePath = "TYK_CA_BUNDLE_PATH"
)

var (
	// caPool is lazily loaded and cached.
	caPool     *x509.CertPool
	caPoolOnce sync.Once
	caPoolErr  error
)

// loadCAPool reads the CA bundle from disk and returns a CertPool.
// The result is cached after the first successful (or failed) load.
func loadCAPool() (*x509.CertPool, error) {
	caPoolOnce.Do(func() {
		caPath := os.Getenv(EnvCABundlePath)
		if caPath == "" {
			caPoolErr = fmt.Errorf("environment variable %s is not set", EnvCABundlePath)
			return
		}

		caBundlePEM, err := os.ReadFile(caPath)
		if err != nil {
			caPoolErr = fmt.Errorf("failed to read CA bundle from %s: %w", caPath, err)
			return
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBundlePEM) {
			caPoolErr = fmt.Errorf("CA bundle at %s contains no valid certificates", caPath)
			return
		}

		caPool = pool
		logger.Infof("loaded CA bundle from %s", caPath)
	})

	return caPool, caPoolErr
}

// certHeader returns the configured header name for the client certificate.
func certHeader() string {
	if h := os.Getenv(EnvCertHeader); h != "" {
		return h
	}
	return DefaultCertHeader
}

// CertValidator is a Tyk custom Go plugin (Pre-auth hook) that validates a
// base64 encoded client certificate passed in an HTTP header. This is designed for
// deployments where TLS is terminated at a load balancer (e.g. AWS ALB) which forwards the
// client certificate in a header.
//
// Configuration is via environment variables:
//
//    TYK_CA_BUNDLE_PATH – path to a PEM file with trusted CA certificates (required)
//    TYK_CERT_HEADER    – header name containing the PEM-encoded client cert (default: X-Client-Cert)
func CertValidator(rw http.ResponseWriter, r *http.Request) {
	header := certHeader()

	rawCert := r.Header.Get(header)
	if rawCert == "" {
		logger.Errorf("request denied: certificate missing")
		http.Error(rw, "Forbidden: client certificate required", http.StatusForbidden)
		return
	}
	fmt.Println("Raw cert:", rawCert)

	// Base64 Decode the Certificate
	certData, err := base64.StdEncoding.DecodeString(rawCert)
	fmt.Println("Decoded CertData: ", string(certData))
	if err != nil {
		logger.Errorf("Request Denied: unabled to decode certificate")
		http.Error(rw, "Unable to decode certificate", http.StatusForbidden)
		return
	}

	// Try parsing the decoded header value as a PEM-encoded certificate
	clientCert, err := parsePEMCertificate(string(certData))
	if err != nil {
		logger.Errorf("Request Denied: invalid certificate in header")
		http.Error(rw, "Forbidden: invalid client certificate", http.StatusForbidden)
		return
	}

	pool, err := loadCAPool()
	if err != nil {
		logger.Errorf("Request Denied: CA pool unavailable: %s", err)
		http.Error(rw, "Forbidden: certificate validation unavailable", http.StatusForbidden)
		return
	}

	if err := verifyCertificate(clientCert, pool); err != nil {
		logger.Errorf("Request Denied: certificate verification failed for %s (subject=%s): %v",
			r.RemoteAddr, clientCert.Subject, err)
		http.Error(rw, "Forbidden: certificate validation failed", http.StatusForbidden)
		return
	}

	logger.Infof("request allowed: valid certificate from %s (subject=%s, serial=%s, expires=%s)",
		r.RemoteAddr, clientCert.Subject, clientCert.SerialNumber, clientCert.NotAfter.Format(time.RFC3339))
}

// parsePEMCertificate decodes a PEM-encoded certificate string and returns the
// parsed x509.Certificate.
func parsePEMCertificate(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in certificate data")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block type is %q, expected CERTIFICATE", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// verifyCertificate verifies the client certificate against the trusted CA pool,
// checking the signature chain and expiration.
func verifyCertificate(cert *x509.Certificate, caPool *x509.CertPool) error {
	opts := x509.VerifyOptions{
		Roots:       caPool,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("Certificate verification failed: %w", err)
	}

	return nil
}

func main() {}
