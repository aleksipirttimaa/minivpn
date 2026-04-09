package tlssession

import (
	"errors"
	"testing"

	tls "github.com/refraction-networking/utls"
)

func TestParseTLSCipherList(t *testing.T) {
	t.Run("empty string returns error", func(t *testing.T) {
		_, err := parseTLSCipherList("")
		if err == nil {
			t.Error("expected error for empty string")
		}
	})

	t.Run("unknown cipher name returns ErrBadTLSInit", func(t *testing.T) {
		_, err := parseTLSCipherList("TLS-NOT-A-REAL-CIPHER")
		if err == nil {
			t.Fatal("expected error but got nil")
		}
		if !errors.Is(err, ErrBadTLSInit) {
			t.Errorf("expected ErrBadTLSInit, got: %v", err)
		}
	})

	t.Run("single IANA name returns correct ID plus SCSV", func(t *testing.T) {
		ids, err := parseTLSCipherList("TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 2 {
			t.Fatalf("expected 2 IDs, got %d", len(ids))
		}
		if ids[0] != tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
			t.Errorf("ids[0] = %#x, want %#x", ids[0], tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
		}
		if ids[1] != tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV {
			t.Errorf("ids[1] = %#x, want SCSV %#x", ids[1], tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
		}
	})

	t.Run("colon-separated IANA names parsed in order with SCSV appended", func(t *testing.T) {
		ids, err := parseTLSCipherList("TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 3 {
			t.Fatalf("expected 3 IDs, got %d", len(ids))
		}
		if ids[0] != tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
			t.Errorf("ids[0] = %#x", ids[0])
		}
		if ids[1] != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {
			t.Errorf("ids[1] = %#x", ids[1])
		}
		if ids[2] != tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV {
			t.Errorf("ids[2] = %#x, want SCSV", ids[2])
		}
	})

	t.Run("OpenSSL short name accepted", func(t *testing.T) {
		ids, err := parseTLSCipherList("ECDHE-ECDSA-AES256-GCM-SHA384")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ids[0] != tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
			t.Errorf("ids[0] = %#x, want %#x", ids[0], tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
		}
	})

	t.Run("DHE-RSA-CHACHA20-POLY1305 maps to 0xccaa", func(t *testing.T) {
		ids, err := parseTLSCipherList("DHE-RSA-CHACHA20-POLY1305")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ids[0] != 0xccaa {
			t.Errorf("ids[0] = %#x, want 0xccaa", ids[0])
		}
	})

	t.Run("unknown cipher in colon list returns error", func(t *testing.T) {
		_, err := parseTLSCipherList("TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:BOGUS-CIPHER")
		if err == nil {
			t.Fatal("expected error but got nil")
		}
		if !errors.Is(err, ErrBadTLSInit) {
			t.Errorf("expected ErrBadTLSInit, got: %v", err)
		}
	})
}
