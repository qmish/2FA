package ldap

import (
	"context"
	"errors"
	"net"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

type Authenticator interface {
	Authenticate(ctx context.Context, userDN string, password string) error
}

type Client struct {
	url     string
	timeout time.Duration
}

func NewClient(url string, timeout time.Duration) *Client {
	return &Client{url: url, timeout: timeout}
}

func (c *Client) Authenticate(ctx context.Context, userDN string, password string) error {
	_ = ctx
	if c.url == "" {
		return errors.New("ldap url is empty")
	}
	dialer := &net.Dialer{Timeout: c.timeout}
	conn, err := ldapv3.DialURL(c.url, ldapv3.DialWithDialer(dialer))
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Bind(userDN, password); err != nil {
		return err
	}
	return nil
}
