package tlssession

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// ekuNames maps OpenSSL symbolic names (long and short) and well-known OID
// strings to Go's x509.ExtKeyUsage constants.
var ekuNames = map[string]x509.ExtKeyUsage{
	// OpenSSL long names
	"TLS Web Server Authentication": x509.ExtKeyUsageServerAuth,
	"TLS Web Client Authentication": x509.ExtKeyUsageClientAuth,
	"Code Signing":                  x509.ExtKeyUsageCodeSigning,
	"E-mail Protection":             x509.ExtKeyUsageEmailProtection,
	"Time Stamping":                 x509.ExtKeyUsageTimeStamping,
	"OCSP Signing":                  x509.ExtKeyUsageOCSPSigning,
	// OpenSSL short names
	"serverAuth":      x509.ExtKeyUsageServerAuth,
	"clientAuth":      x509.ExtKeyUsageClientAuth,
	"codeSigning":     x509.ExtKeyUsageCodeSigning,
	"emailProtection": x509.ExtKeyUsageEmailProtection,
	"timeStamping":    x509.ExtKeyUsageTimeStamping,
	"OCSPSigning":     x509.ExtKeyUsageOCSPSigning,
	// OID strings for the same EKUs
	"1.3.6.1.5.5.7.3.1": x509.ExtKeyUsageServerAuth,
	"1.3.6.1.5.5.7.3.2": x509.ExtKeyUsageClientAuth,
	"1.3.6.1.5.5.7.3.3": x509.ExtKeyUsageCodeSigning,
	"1.3.6.1.5.5.7.3.4": x509.ExtKeyUsageEmailProtection,
	"1.3.6.1.5.5.7.3.8": x509.ExtKeyUsageTimeStamping,
	"1.3.6.1.5.5.7.3.9": x509.ExtKeyUsageOCSPSigning,
}

// checkEKU returns an error if the leaf certificate does not carry the required
// EKU. The required string may be an OpenSSL symbolic name (short or long) or a
// dotted OID string.
func checkEKU(leaf *x509.Certificate, required string) error {
	// ExtKeyUsageAny satisfies any requirement.
	for _, e := range leaf.ExtKeyUsage {
		if e == x509.ExtKeyUsageAny {
			return nil
		}
	}

	// Try the name/OID lookup table for known EKUs.
	if want, ok := ekuNames[required]; ok {
		for _, e := range leaf.ExtKeyUsage {
			if e == want {
				return nil
			}
		}
		return fmt.Errorf("%w: cert missing required EKU %q", ErrCannotVerifyCertChain, required)
	}

	// Fall back: parse as a dotted OID and check UnknownExtKeyUsage.
	oid, err := parseOIDString(required)
	if err != nil {
		return fmt.Errorf("%w: unrecognized EKU %q: %s", ErrCannotVerifyCertChain, required, err)
	}
	for _, u := range leaf.UnknownExtKeyUsage {
		if u.Equal(oid) {
			return nil
		}
	}
	return fmt.Errorf("%w: cert missing required EKU OID %s", ErrCannotVerifyCertChain, required)
}

// parseOIDString converts a dotted OID string (e.g. "1.3.6.1.5.5.7.3.1") into
// an asn1.ObjectIdentifier.
func parseOIDString(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a valid OID: %q", s)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("not a valid OID: %q", s)
		}
		oid[i] = n
	}
	return oid, nil
}
