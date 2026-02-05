package postgres

import "testing"

func TestOpenEmptyDSN(t *testing.T) {
    if _, err := Open(""); err != ErrEmptyDSN {
        t.Fatalf("expected ErrEmptyDSN, got %v", err)
    }
}
