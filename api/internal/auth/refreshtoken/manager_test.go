package refreshtoken_test

import (
	"testing"
	"time"

	"restaurant-api/internal/auth/refreshtoken"
)

func TestIssueAndHash(t *testing.T) {
	mgr, err := refreshtoken.NewManager("refresh-secret", 168*time.Hour)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	raw1, hash1, exp, expiresIn, err := mgr.Issue()
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if raw1 == "" || hash1 == "" || expiresIn <= 0 || exp.Before(time.Now()) {
		t.Fatalf("invalid issued token")
	}
	if mgr.Hash(raw1) != hash1 {
		t.Fatal("hash mismatch")
	}
	raw2, hash2, _, _, err := mgr.Issue()
	if err != nil {
		t.Fatalf("issue2: %v", err)
	}
	if raw1 == raw2 || hash1 == hash2 {
		t.Fatal("tokens should be unique")
	}
}
