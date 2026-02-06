## SLO/SLI

### SLI
- auth_success_rate = success / (success + failure)
- auth_latency_p95 (login/verify)
- refresh_success_rate
- otp_delivery_latency_p95
- db_errors_total, redis_errors_total
### Метрики
- http_request_duration_ms (histogram buckets)
- system_errors_total{component="db|redis"}

### SLO
- Auth availability: 99.9%
- Login p95: <= 300ms
- Verify p95: <= 500ms
- Refresh success: >= 99.5%
- OTP delivery p95: <= 10s
