---
id: monitoring
title: Monitoring & Metrics
sidebar_label: Monitoring
---

# Monitoring & Metrics

Shadow SSO exposes Prometheus metrics and supports OpenTelemetry tracing for comprehensive observability.

## Prometheus Metrics

### Metrics Endpoint

Metrics are available at the management server endpoint:

```
http://<host>:5000/metrics
```

### Available Metrics

#### HTTP Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | Total HTTP requests |
| `http_request_duration_seconds` | Histogram | Request duration |
| `http_request_size_bytes` | Histogram | Request size |
| `http_response_size_bytes` | Histogram | Response size |

#### Authentication Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sso_login_attempts_total` | Counter | Total login attempts |
| `sso_login_success_total` | Counter | Successful logins |
| `sso_login_failure_total` | Counter | Failed logins |
| `sso_token_issued_total` | Counter | Tokens issued |
| `sso_token_revoked_total` | Counter | Tokens revoked |
| `sso_session_active` | Gauge | Active sessions |

#### Database Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mongodb_queries_total` | Counter | MongoDB queries |
| `mongodb_query_duration_seconds` | Histogram | Query duration |
| `mongodb_connections_active` | Gauge | Active connections |

#### System Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `go_goroutines` | Gauge | Goroutine count |
| `go_memstats_alloc_bytes` | Gauge | Memory allocated |
| `process_cpu_seconds_total` | Counter | CPU time used |

### Prometheus Configuration

#### ServiceMonitor (Prometheus Operator)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ssso-backend
  namespace: shadow-sso
  labels:
    app.kubernetes.io/name: ssso-backend
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: ssso-backend
  endpoints:
    - port: mgmt
      path: /metrics
      interval: 30s
```

#### Static Scrape Config

```yaml
scrape_configs:
  - job_name: 'shadow-sso'
    metrics_path: '/metrics'
    static_configs:
      - targets: ['ssso:5000']
    scrape_interval: 30s
```

## OpenTelemetry Tracing

### Enable Tracing

```bash
SSSO_TRACING_ENABLED=true
SSSO_TRACING_OTLP_ENDPOINT=http://tempo.observability:4317
```

### Helm Configuration

```yaml
tracing:
  enabled: true
  otlpEndpoint: "http://tempo.observability:4317"
  serviceName: "shadow-sso"
  # otlpHeaders: "Authorization=Bearer ..."
  # otlpProtocol: "grpc"  # or "http/protobuf"
```

### Trace Attributes

Shadow SSO includes these attributes in traces:

| Attribute | Description |
|-----------|-------------|
| `sso.user.id` | User ID (if authenticated) |
| `sso.client.id` | OAuth client ID |
| `sso.grant_type` | OAuth grant type |
| `sso.scope` | Requested scopes |
| `http.method` | HTTP method |
| `http.url` | Request URL |
| `http.status_code` | Response status |

### Grafana Tempo Configuration

```yaml
# tempo.yaml
server:
  http_listen_port: 3200

distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317

storage:
  trace:
    backend: gcs
    gcs:
      bucket: my-tempo-bucket
```

## Health Checks

### Endpoints

| Endpoint | Port | Purpose |
|----------|------|---------|
| `/healthz` | 5000 | Liveness probe |
| `/readyz` | 5000 | Readiness probe |

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 5000
  initialDelaySeconds: 30
  periodSeconds: 15
  timeoutSeconds: 3
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readyz
    port: 5000
  initialDelaySeconds: 10
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
```

## Logging

### Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `debug` | Detailed debugging | Development |
| `info` | General information | Production |
| `warn` | Warning messages | Production |
| `error` | Error messages | Production |

### JSON Logging

Enable structured JSON logging for production:

```bash
SSSO_JSON_LOG=true
SSSO_LOG_LEVEL=info
```

**Example output:**

```json
{
  "level": "info",
  "time": "2024-01-15T10:30:00Z",
  "message": "User login successful",
  "user_id": "usr_abc123",
  "client_id": "client_xyz",
  "ip": "192.168.1.100"
}
```

### Log Aggregation

#### Fluentd Configuration

```xml
<source>
  @type tail
  path /var/log/containers/ssso-*.log
  pos_file /var/log/ssso.pos
  tag kubernetes.*
  format json
  time_key time
</source>

<match kubernetes.**>
  @type elasticsearch
  host elasticsearch
  port 9200
  logstash_format true
</match>
```

#### Loki Configuration

```yaml
# promtail.yaml
scrape_configs:
  - job_name: kubernetes-pods
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
        target_label: app
    pipeline_stages:
      - json:
          expressions:
            level: level
            message: message
      - labels:
          level:
```

## Alerting

### Prometheus Alert Rules

```yaml
groups:
  - name: shadow-sso
    rules:
      - alert: HighLoginFailureRate
        expr: rate(sso_login_failure_total[5m]) / rate(sso_login_attempts_total[5m]) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High login failure rate"
          description: "More than 50% of login attempts are failing"

      - alert: MongoDBConnectionError
        expr: mongodb_connections_active == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "MongoDB connection lost"

      - alert: HighMemoryUsage
        expr: go_memstats_alloc_bytes > 500000000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"

      - alert: PodNotReady
        expr: kube_pod_status_ready{namespace="shadow-sso"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Pod not ready"
```

## Grafana Dashboards

### Import Dashboard

1. Open Grafana
2. Go to Dashboards > Import
3. Upload the dashboard JSON or use the dashboard ID

### Key Panels

- **Request Rate**: `rate(http_requests_total[5m])`
- **Error Rate**: `rate(http_requests_total{status=~"5.."}[5m])`
- **Latency**: `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))`
- **Active Sessions**: `sso_session_active`
- **Login Success Rate**: `rate(sso_login_success_total[5m]) / rate(sso_login_attempts_total[5m])`

## Monitoring Checklist

### Daily

- [ ] Check health endpoints
- [ ] Review error logs
- [ ] Monitor login success rate

### Weekly

- [ ] Review slow queries
- [ ] Check memory usage trends
- [ ] Review token usage patterns

### Monthly

- [ ] Capacity planning
- [ ] Review alert thresholds
- [ ] Update dashboards

## Next Steps

- [Troubleshooting](/troubleshooting/common-issues) - Common issues
- [Security](/operations/security) - Security best practices
- [Maintenance](/operations/maintenance) - Backup and recovery
