# 🚪 Career OS: The Gate (os-gateway-service)

## Overview
This service is the dedicated API and AI Gateway for the platform. It intercepts all incoming dashboard commands and routes them to their respective internal services.

## Key Capabilities
1. **API / AI Proxying:** Routes requests to `vault-service` and `agent-python`.
2. **Token Governance:** Audits token consumption and performs credit validation against Supabase schemas before triggering expensive LLM runs.
3. **Failover Routing:** Utilizes LiteLLM logic to dynamically failover prompt runs when upstream providers are unhealthy.
4. **Preflight Quota Verification:** Integrates with Supabase `check_token_quota` RPC for pre-execution gating, and `consume_token_quota` RPC for post-execution actual usage consumption logging.
5. **CORS & Size Validation:** Configures global security headers and limits request payload sizes to 10MB.
