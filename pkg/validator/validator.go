package validator

import (
    "net"
    "regexp"
    "strings"
)

var (
    emailRe = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
    phoneRe = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
)

func NormalizeEmail(v string) string {
    return strings.ToLower(strings.TrimSpace(v))
}

func NormalizePhone(v string) string {
    return strings.TrimSpace(v)
}

func NormalizeIP(v string) string {
    return strings.TrimSpace(v)
}

func IsEmailValid(v string) bool {
    v = NormalizeEmail(v)
    return v != "" && emailRe.MatchString(v)
}

func IsPhoneValid(v string) bool {
    v = NormalizePhone(v)
    return v != "" && phoneRe.MatchString(v)
}

func IsIPValid(v string) bool {
    v = NormalizeIP(v)
    if v == "" {
        return false
    }
    return net.ParseIP(v) != nil
}
