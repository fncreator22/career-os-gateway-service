# 🚪 Career OS: The Gate (os-gateway-service)

## Overview
This service is the dedicated API and AI Gateway for the platform. It intercepts all incoming dashboard commands and routes them to their respective internal services.

## Key Capabilities
1. **API / AI Proxying:** Routes requests to `vault-service` and `agent-python`.
2. **Token Governance:** Audits token consumption and performs credit validation against Supabase schemas before triggering expensive LLM runs.
3. **Failover Routing:** Utilizes LiteLLM logic to dynamically failover prompt runs when upstream providers are unhealthy.
