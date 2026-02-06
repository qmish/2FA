package ratelimit

import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "net"
    "net/url"
    "strconv"
    "strings"
    "time"
)

var ErrInvalidRedisURL = errors.New("invalid redis url")
var ErrInvalidRedisResponse = errors.New("invalid redis response")

type RedisClient struct {
    addr    string
    pass    string
    db      int
    timeout time.Duration
}

func NewRedisClient(redisURL string) (*RedisClient, error) {
    if redisURL == "" {
        return nil, ErrInvalidRedisURL
    }
    u, err := url.Parse(redisURL)
    if err != nil {
        return nil, err
    }
    if u.Scheme != "redis" && u.Scheme != "rediss" {
        return nil, ErrInvalidRedisURL
    }
    host := u.Host
    if host == "" {
        return nil, ErrInvalidRedisURL
    }
    if !strings.Contains(host, ":") {
        host += ":6379"
    }
    pass, _ := u.User.Password()
    db := 0
    if strings.TrimPrefix(u.Path, "/") != "" {
        if v, err := strconv.Atoi(strings.TrimPrefix(u.Path, "/")); err == nil {
            db = v
        }
    }
    return &RedisClient{
        addr:    host,
        pass:    pass,
        db:      db,
        timeout: 2 * time.Second,
    }, nil
}

func (c *RedisClient) WithTimeout(timeout time.Duration) *RedisClient {
    copy := *c
    copy.timeout = timeout
    return &copy
}

func (c *RedisClient) IncrWithExpire(ctx context.Context, key string, ttl time.Duration) (int64, error) {
    conn, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "tcp", c.addr)
    if err != nil {
        return 0, err
    }
    defer conn.Close()

    reader := bufio.NewReader(conn)
    writer := bufio.NewWriter(conn)

    if err := c.authSelect(writer, reader); err != nil {
        return 0, err
    }

    if err := writeCommand(writer, "INCR", key); err != nil {
        return 0, err
    }
    if err := writer.Flush(); err != nil {
        return 0, err
    }
    count, err := readInt(reader)
    if err != nil {
        return 0, err
    }
    if count == 1 {
        if err := writeCommand(writer, "PEXPIRE", key, strconv.FormatInt(ttl.Milliseconds(), 10)); err != nil {
            return count, err
        }
        if err := writer.Flush(); err != nil {
            return count, err
        }
        if _, err := readInt(reader); err != nil {
            return count, err
        }
    }
    return count, nil
}

func (c *RedisClient) Ping(ctx context.Context) error {
    conn, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "tcp", c.addr)
    if err != nil {
        return err
    }
    defer conn.Close()

    reader := bufio.NewReader(conn)
    writer := bufio.NewWriter(conn)
    if err := c.authSelect(writer, reader); err != nil {
        return err
    }
    if err := writeCommand(writer, "PING"); err != nil {
        return err
    }
    if err := writer.Flush(); err != nil {
        return err
    }
    _, err = readSimple(reader)
    return err
}

func (c *RedisClient) authSelect(writer *bufio.Writer, reader *bufio.Reader) error {
    if c.pass != "" {
        if err := writeCommand(writer, "AUTH", c.pass); err != nil {
            return err
        }
        if err := writer.Flush(); err != nil {
            return err
        }
        if _, err := readSimple(reader); err != nil {
            return err
        }
    }
    if c.db > 0 {
        if err := writeCommand(writer, "SELECT", strconv.Itoa(c.db)); err != nil {
            return err
        }
        if err := writer.Flush(); err != nil {
            return err
        }
        if _, err := readSimple(reader); err != nil {
            return err
        }
    }
    return nil
}

func writeCommand(w *bufio.Writer, args ...string) error {
    if _, err := w.WriteString(fmt.Sprintf("*%d\r\n", len(args))); err != nil {
        return err
    }
    for _, arg := range args {
        if _, err := w.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg)); err != nil {
            return err
        }
    }
    return nil
}

func readInt(r *bufio.Reader) (int64, error) {
    b, err := r.ReadByte()
    if err != nil {
        return 0, err
    }
    if b == '-' {
        line, _ := r.ReadString('\n')
        return 0, errors.New(strings.TrimSpace(line))
    }
    if b != ':' {
        return 0, ErrInvalidRedisResponse
    }
    line, err := r.ReadString('\n')
    if err != nil {
        return 0, err
    }
    return strconv.ParseInt(strings.TrimSpace(line), 10, 64)
}

func readSimple(r *bufio.Reader) (string, error) {
    b, err := r.ReadByte()
    if err != nil {
        return "", err
    }
    if b == '-' {
        line, _ := r.ReadString('\n')
        return "", errors.New(strings.TrimSpace(line))
    }
    if b != '+' {
        return "", ErrInvalidRedisResponse
    }
    line, err := r.ReadString('\n')
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(line), nil
}
