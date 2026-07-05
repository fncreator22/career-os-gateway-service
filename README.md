# 🚪 Career OS: The Gate (os-gateway-service)

## Overview
This service is the dedicated API and AI Gateway for the platform. It intercepts all incoming dashboard commands and routes them to their respective internal services.

## Key Capabilities
1. **API / AI Proxying:** Routes requests to `vault-service` and `agent-python`.
2. **Token Governance:** Audits token consumption and performs credit validation against Supabase schemas before triggering expensive LLM runs.
3. **Failover Routing:** Utilizes LiteLLM logic to dynamically failover prompt runs when upstream providers are unhealthy.

---

## 🔒 Security & Observability Audit Findings

Following a system audit, the following remediation targets have been identified for this Gateway service:

### 1. Security Hardening
* **Decryption Routing:** The `/v1/decrypt` and `/v1/encrypt` proxies do not currently validate standard Supabase Bearer JWT tokens. Inter-service mTLS or signature verification must be enforced.
* **CORS Restrictions:** `Access-Control-Allow-Origin` is configured to `*`. In production, this must be locked to specific application origins (e.g. `https://app.career-os.com`).

### 2. Rate Limiting
* **Redis Integration:** Replace the in-memory JavaScript `Map` rate-limiter with a horizontal-scaling-safe Redis token bucket mechanism.

### 3. Observability
* **Metrics:** Replace static metrics with active Prometheus/OpenTelemetry counter/histogram metrics capturing time-to-first-byte (TTFB), downstream latency, and failure rates.
