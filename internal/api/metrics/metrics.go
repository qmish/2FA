package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Registry struct {
	mu                      sync.Mutex
	httpRequests            map[string]int64
	httpLatency             map[string]*latencyMetric
	authFailures            map[string]int64
	authChallenges          map[string]int64
	authRegistrations       map[string]int64
	passkeyEvents           map[string]int64
	authLogins              map[string]int64
	systemErrors            map[string]int64
	radiusRequests          map[string]int64
	redisPings              map[string]int64
	dbPings                 map[string]int64
	dbPoolStats             DBPoolStats
	lockoutCreated          int64
	lockoutActive           int64
	lockoutCleared          int64
	webauthnSessionsCleared int64
}

func NewRegistry() *Registry {
	return &Registry{
		httpRequests:      map[string]int64{},
		httpLatency:       map[string]*latencyMetric{},
		authFailures:      map[string]int64{},
		authChallenges:    map[string]int64{},
		authRegistrations: map[string]int64{},
		passkeyEvents:     map[string]int64{},
		authLogins:        map[string]int64{},
		systemErrors:      map[string]int64{},
		radiusRequests:    map[string]int64{},
		redisPings:        map[string]int64{},
		dbPings:           map[string]int64{},
	}
}

var Default = NewRegistry()

func (r *Registry) IncHTTPRequest(method, path string, status int) {
	key := fmt.Sprintf("method=%s,path=%s,status=%d", method, path, status)
	r.mu.Lock()
	r.httpRequests[key]++
	r.mu.Unlock()
}

func (r *Registry) ObserveHTTPDuration(method, path string, duration time.Duration) {
	key := fmt.Sprintf("method=%s,path=%s", method, path)
	r.mu.Lock()
	metric := r.httpLatency[key]
	if metric == nil {
		metric = newLatencyMetric()
		r.httpLatency[key] = metric
	}
	metric.observe(duration)
	r.mu.Unlock()
}

func (r *Registry) IncAuthFailure(operation, reason string) {
	key := fmt.Sprintf("operation=%s,reason=%s", operation, reason)
	r.mu.Lock()
	r.authFailures[key]++
	r.mu.Unlock()
}

func (r *Registry) IncAuthChallenge(method string) {
	key := fmt.Sprintf("method=%s", method)
	r.mu.Lock()
	r.authChallenges[key]++
	r.mu.Unlock()
}

func (r *Registry) IncAuthRegistration(result string) {
	key := fmt.Sprintf("result=%s", result)
	r.mu.Lock()
	r.authRegistrations[key]++
	r.mu.Unlock()
}

func (r *Registry) IncAuthLogin(result string) {
	key := fmt.Sprintf("result=%s", result)
	r.mu.Lock()
	r.authLogins[key]++
	r.mu.Unlock()
}

func (r *Registry) IncPasskeyEvent(operation, result string) {
	key := fmt.Sprintf("operation=%s,result=%s", operation, result)
	r.mu.Lock()
	r.passkeyEvents[key]++
	r.mu.Unlock()
}

func (r *Registry) IncSystemError(component string) {
	key := fmt.Sprintf("component=%s", component)
	r.mu.Lock()
	r.systemErrors[key]++
	r.mu.Unlock()
}

func (r *Registry) IncRadiusRequest(result string) {
	key := fmt.Sprintf("result=%s", result)
	r.mu.Lock()
	r.radiusRequests[key]++
	r.mu.Unlock()
}

func (r *Registry) IncRedisPing(result string) {
	key := fmt.Sprintf("result=%s", result)
	r.mu.Lock()
	r.redisPings[key]++
	r.mu.Unlock()
}

func (r *Registry) IncDBPing(result string) {
	key := fmt.Sprintf("result=%s", result)
	r.mu.Lock()
	r.dbPings[key]++
	r.mu.Unlock()
}

type DBPoolStats struct {
	OpenConns      int
	InUse          int
	Idle           int
	WaitCount      int64
	WaitDurationMs int64
	MaxOpenConns   int
}

func (r *Registry) SetDBPoolStats(stats DBPoolStats) {
	r.mu.Lock()
	r.dbPoolStats = stats
	r.mu.Unlock()
}

func (r *Registry) IncLockoutCreated() {
	r.mu.Lock()
	r.lockoutCreated++
	r.mu.Unlock()
}

func (r *Registry) IncLockoutActive() {
	r.mu.Lock()
	r.lockoutActive++
	r.mu.Unlock()
}

func (r *Registry) AddLockoutCleared(count int64) {
	if count <= 0 {
		return
	}
	r.mu.Lock()
	r.lockoutCleared += count
	r.mu.Unlock()
}

func (r *Registry) AddWebauthnSessionsCleared(count int64) {
	if count <= 0 {
		return
	}
	r.mu.Lock()
	r.webauthnSessionsCleared += count
	r.mu.Unlock()
}

func (r *Registry) Render() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var b strings.Builder
	b.WriteString("# HELP http_requests_total Total HTTP requests\n")
	b.WriteString("# TYPE http_requests_total counter\n")
	for _, k := range sortedKeys(r.httpRequests) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("http_requests_total{%s} %d\n", labels, r.httpRequests[k]))
	}
	b.WriteString("# HELP http_request_duration_ms HTTP request duration buckets\n")
	b.WriteString("# TYPE http_request_duration_ms histogram\n")
	for _, k := range sortedKeysLatency(r.httpLatency) {
		labels := formatLabels(k)
		metric := r.httpLatency[k]
		for _, bucket := range metric.buckets {
			bucketLabels := labels + fmt.Sprintf(",le=\"%d\"", bucket.le)
			b.WriteString(fmt.Sprintf("http_request_duration_ms_bucket{%s} %d\n", bucketLabels, bucket.count))
		}
		b.WriteString(fmt.Sprintf("http_request_duration_ms_sum{%s} %d\n", labels, metric.sumMs))
		b.WriteString(fmt.Sprintf("http_request_duration_ms_count{%s} %d\n", labels, metric.count))
	}
	b.WriteString("# HELP auth_failures_total Auth failures\n")
	b.WriteString("# TYPE auth_failures_total counter\n")
	for _, k := range sortedKeys(r.authFailures) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("auth_failures_total{%s} %d\n", labels, r.authFailures[k]))
	}
	b.WriteString("# HELP auth_challenges_total Auth challenges created\n")
	b.WriteString("# TYPE auth_challenges_total counter\n")
	for _, k := range sortedKeys(r.authChallenges) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("auth_challenges_total{%s} %d\n", labels, r.authChallenges[k]))
	}
	b.WriteString("# HELP auth_registrations_total Auth registrations\n")
	b.WriteString("# TYPE auth_registrations_total counter\n")
	for _, k := range sortedKeys(r.authRegistrations) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("auth_registrations_total{%s} %d\n", labels, r.authRegistrations[k]))
	}
	b.WriteString("# HELP auth_logins_total Auth logins\n")
	b.WriteString("# TYPE auth_logins_total counter\n")
	for _, k := range sortedKeys(r.authLogins) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("auth_logins_total{%s} %d\n", labels, r.authLogins[k]))
	}
	b.WriteString("# HELP passkey_events_total Passkey events\n")
	b.WriteString("# TYPE passkey_events_total counter\n")
	for _, k := range sortedKeys(r.passkeyEvents) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("passkey_events_total{%s} %d\n", labels, r.passkeyEvents[k]))
	}
	b.WriteString("# HELP system_errors_total System errors\n")
	b.WriteString("# TYPE system_errors_total counter\n")
	for _, k := range sortedKeys(r.systemErrors) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("system_errors_total{%s} %d\n", labels, r.systemErrors[k]))
	}
	b.WriteString("# HELP radius_requests_total RADIUS access results\n")
	b.WriteString("# TYPE radius_requests_total counter\n")
	for _, k := range sortedKeys(r.radiusRequests) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("radius_requests_total{%s} %d\n", labels, r.radiusRequests[k]))
	}
	b.WriteString("# HELP redis_ping_total Redis ping results\n")
	b.WriteString("# TYPE redis_ping_total counter\n")
	for _, k := range sortedKeys(r.redisPings) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("redis_ping_total{%s} %d\n", labels, r.redisPings[k]))
	}
	b.WriteString("# HELP db_ping_total DB ping results\n")
	b.WriteString("# TYPE db_ping_total counter\n")
	for _, k := range sortedKeys(r.dbPings) {
		labels := formatLabels(k)
		b.WriteString(fmt.Sprintf("db_ping_total{%s} %d\n", labels, r.dbPings[k]))
	}
	b.WriteString("# HELP db_pool_open_connections Open DB connections\n")
	b.WriteString("# TYPE db_pool_open_connections gauge\n")
	b.WriteString(fmt.Sprintf("db_pool_open_connections %d\n", r.dbPoolStats.OpenConns))
	b.WriteString("# HELP db_pool_in_use Connections in use\n")
	b.WriteString("# TYPE db_pool_in_use gauge\n")
	b.WriteString(fmt.Sprintf("db_pool_in_use %d\n", r.dbPoolStats.InUse))
	b.WriteString("# HELP db_pool_idle Idle connections\n")
	b.WriteString("# TYPE db_pool_idle gauge\n")
	b.WriteString(fmt.Sprintf("db_pool_idle %d\n", r.dbPoolStats.Idle))
	b.WriteString("# HELP db_pool_wait_count Waiting for connection count\n")
	b.WriteString("# TYPE db_pool_wait_count gauge\n")
	b.WriteString(fmt.Sprintf("db_pool_wait_count %d\n", r.dbPoolStats.WaitCount))
	b.WriteString("# HELP db_pool_wait_duration_ms Total wait duration ms\n")
	b.WriteString("# TYPE db_pool_wait_duration_ms gauge\n")
	b.WriteString(fmt.Sprintf("db_pool_wait_duration_ms %d\n", r.dbPoolStats.WaitDurationMs))
	b.WriteString("# HELP db_pool_max_open_connections Max open connections\n")
	b.WriteString("# TYPE db_pool_max_open_connections gauge\n")
	b.WriteString(fmt.Sprintf("db_pool_max_open_connections %d\n", r.dbPoolStats.MaxOpenConns))
	b.WriteString("# HELP lockout_created_total Lockouts created\n")
	b.WriteString("# TYPE lockout_created_total counter\n")
	b.WriteString(fmt.Sprintf("lockout_created_total %d\n", r.lockoutCreated))
	b.WriteString("# HELP lockout_active_total Active lockout hits\n")
	b.WriteString("# TYPE lockout_active_total counter\n")
	b.WriteString(fmt.Sprintf("lockout_active_total %d\n", r.lockoutActive))
	b.WriteString("# HELP lockout_cleared_total Lockouts cleared\n")
	b.WriteString("# TYPE lockout_cleared_total counter\n")
	b.WriteString(fmt.Sprintf("lockout_cleared_total %d\n", r.lockoutCleared))
	b.WriteString("# HELP webauthn_sessions_cleared_total WebAuthn sessions cleared\n")
	b.WriteString("# TYPE webauthn_sessions_cleared_total counter\n")
	b.WriteString(fmt.Sprintf("webauthn_sessions_cleared_total %d\n", r.webauthnSessionsCleared))
	b.WriteString(fmt.Sprintf("# generated_at %s\n", time.Now().UTC().Format(time.RFC3339)))
	return b.String()
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysLatency(m map[string]*latencyMetric) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatLabels(s string) string {
	parts := strings.Split(s, ",")
	for i, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		parts[i] = fmt.Sprintf(`%s="%s"`, kv[0], kv[1])
	}
	return strings.Join(parts, ",")
}

type latencyMetric struct {
	buckets []latencyBucket
	sumMs   int64
	count   int64
}

type latencyBucket struct {
	le    int64
	count int64
}

func newLatencyMetric() *latencyMetric {
	return &latencyMetric{
		buckets: []latencyBucket{
			{le: 50}, {le: 100}, {le: 250}, {le: 500}, {le: 1000}, {le: 2500}, {le: 5000},
		},
	}
}

func (l *latencyMetric) observe(duration time.Duration) {
	ms := duration.Milliseconds()
	l.sumMs += ms
	l.count++
	for i := range l.buckets {
		if ms <= l.buckets[i].le {
			l.buckets[i].count++
		}
	}
}
