package tlssession

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"
)

func TestParseOIDString(t *testing.T) {
	t.Run("valid OID", func(t *testing.T) {
		oid, err := parseOIDString("1.3.6.1.5.5.7.3.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
		if !oid.Equal(want) {
			t.Errorf("got %v want %v", oid, want)
		}
	})

	t.Run("single component returns error", func(t *testing.T) {
		_, err := parseOIDString("1")
		if err == nil {
			t.Error("expected error for single-component OID")
		}
	})

	t.Run("non-numeric component returns error", func(t *testing.T) {
		_, err := parseOIDString("1.3.foo.1")
		if err == nil {
			t.Error("expected error for non-numeric OID component")
		}
	})

	t.Run("negative component returns error", func(t *testing.T) {
		_, err := parseOIDString("1.3.-1.1")
		if err == nil {
			t.Error("expected error for negative OID component")
		}
	})
}

func TestCheckEKU(t *testing.T) {
	serverAuthOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	leafWithServerAuth := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafWithAny := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	leafWithUnknownOID := &x509.Certificate{
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{customOID},
	}
	leafNoEKU := &x509.Certificate{}

	_ = serverAuthOID

	t.Run("serverAuth symbolic name matches serverAuth cert", func(t *testing.T) {
		if err := checkEKU(leafWithServerAuth, "serverAuth"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("long name matches serverAuth cert", func(t *testing.T) {
		if err := checkEKU(leafWithServerAuth, "TLS Web Server Authentication"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("OID string matches serverAuth cert", func(t *testing.T) {
		if err := checkEKU(leafWithServerAuth, "1.3.6.1.5.5.7.3.1"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("ExtKeyUsageAny satisfies any requirement", func(t *testing.T) {
		if err := checkEKU(leafWithAny, "serverAuth"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("ExtKeyUsageAny satisfies OID requirement", func(t *testing.T) {
		if err := checkEKU(leafWithAny, "1.2.3.4.5"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("unknown OID in UnknownExtKeyUsage is accepted", func(t *testing.T) {
		if err := checkEKU(leafWithUnknownOID, "1.2.3.4.5"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("clientAuth requirement fails on serverAuth cert", func(t *testing.T) {
		err := checkEKU(leafWithServerAuth, "clientAuth")
		if err == nil {
			t.Error("expected error but got nil")
		}
		if !errors.Is(err, ErrCannotVerifyCertChain) {
			t.Errorf("expected ErrCannotVerifyCertChain, got: %v", err)
		}
	})

	t.Run("missing EKU on cert with no EKUs", func(t *testing.T) {
		err := checkEKU(leafNoEKU, "serverAuth")
		if err == nil {
			t.Error("expected error but got nil")
		}
		if !errors.Is(err, ErrCannotVerifyCertChain) {
			t.Errorf("expected ErrCannotVerifyCertChain, got: %v", err)
		}
	})

	t.Run("unrecognized non-OID string returns error", func(t *testing.T) {
		err := checkEKU(leafWithServerAuth, "not-an-eku-or-oid")
		if err == nil {
			t.Error("expected error but got nil")
		}
		if !errors.Is(err, ErrCannotVerifyCertChain) {
			t.Errorf("expected ErrCannotVerifyCertChain, got: %v", err)
		}
	})
}
