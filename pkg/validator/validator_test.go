package validator

import "testing"

func TestEmailValidation(t *testing.T) {
    if !IsEmailValid("User@Example.com") {
        t.Fatalf("expected valid email")
    }
    if IsEmailValid("bad-email") {
        t.Fatalf("expected invalid email")
    }
}

func TestPhoneValidation(t *testing.T) {
    if !IsPhoneValid("+79990000000") {
        t.Fatalf("expected valid phone")
    }
    if IsPhoneValid("89990000000") {
        t.Fatalf("expected invalid phone")
    }
}

func TestIPValidation(t *testing.T) {
    if !IsIPValid("10.0.0.1") {
        t.Fatalf("expected valid IPv4")
    }
    if !IsIPValid("2001:db8::1") {
        t.Fatalf("expected valid IPv6")
    }
    if IsIPValid("not-an-ip") {
        t.Fatalf("expected invalid ip")
    }
}
