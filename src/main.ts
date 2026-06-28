// career-os-gateway-service/src/main.ts
// Enterprise Gateway Service enforcing security headers, unified API payloads, and health checks.

import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const PORT = 3002;
const VAULT_SERVICE_URL = Deno.env.get("VAULT_SERVICE_URL") || "http://localhost:3001";
const AGENT_SERVICE_URL = Deno.env.get("AGENT_SERVICE_URL") || "http://localhost:8000";
const WORKER_SERVICE_URL = Deno.env.get("WORKER_SERVICE_URL") || "http://localhost:3003";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "https://oxkgdogymvxfnklhvrvj.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

// Initialize Supabase admin
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Metrics counters
let totalRequests = 0;
let failedRequests = 0;

const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const LIMIT_WINDOW_MS = 60000;
const MAX_REQUESTS_PER_WINDOW = 120;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Correlation-ID, X-Request-ID",
};

const securityHeaders = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-XSS-Protection": "1; mode=block",
};

function logJson(level: string, message: string, meta: Record<string, any> = {}) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    service: "gateway-service",
    message,
    ...meta
  }));
}

// Enterprise Standard Error helper
function createErrorResponse(
  code: string,
  message: string,
  correlationId: string,
  status: number
): Response {
  return new Response(
    JSON.stringify({
      success: false,
      code,
      message,
      correlationId,
      timestamp: new Date().toISOString(),
      details: {},
    }),
    {
      status,
      headers: { ...corsHeaders, ...securityHeaders, "Content-Type": "application/json" },
    }
  );
}

// Enterprise Standard Success helper
function createSuccessResponse(
  data: any,
  requestId: string,
  correlationId: string,
  durationMs: number
): Response {
  return new Response(
    JSON.stringify({
      success: true,
      data,
      meta: {
        requestId,
        correlationId,
        timestamp: new Date().toISOString(),
        durationMs,
      },
    }),
    {
      headers: { ...corsHeaders, ...securityHeaders, "Content-Type": "application/json" },
    }
  );
}

const handler = async (req: Request): Promise<Response> => {
  totalRequests++;
  const url = new URL(req.url);
  const startTime = Date.now();
  const correlationId = req.headers.get("X-Correlation-ID") || crypto.randomUUID();
  const requestId = req.headers.get("X-Request-ID") || crypto.randomUUID();

  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  // Payload size check (10MB Limit)
  const contentLength = Number(req.headers.get("Content-Length") || "0");
  if (contentLength > 10 * 1024 * 1024) {
    failedRequests++;
    return createErrorResponse("PAYLOAD_TOO_LARGE", "Request payload exceeds the 10MB limit.", correlationId, 413);
  }

  // Rate Limiting
  const ip = req.headers.get("X-Forwarded-For") || "local-ip";
  const now = Date.now();
  const rateLimitInfo = rateLimitMap.get(ip) || { count: 0, resetTime: now + LIMIT_WINDOW_MS };

  if (now > rateLimitInfo.resetTime) {
    rateLimitInfo.count = 1;
    rateLimitInfo.resetTime = now + LIMIT_WINDOW_MS;
  } else {
    rateLimitInfo.count++;
  }
  rateLimitMap.set(ip, rateLimitInfo);

  if (rateLimitInfo.count > MAX_REQUESTS_PER_WINDOW) {
    failedRequests++;
    return createErrorResponse("RATE_LIMIT_EXCEEDED", "Too many requests. Please try again later.", correlationId, 429);
  }

  // Live Check
  if (url.pathname === "/health/live" && req.method === "GET") {
    return createSuccessResponse({ status: "ok" }, requestId, correlationId, Date.now() - startTime);
  }

  // Ready Check
  if (url.pathname === "/health/ready" && req.method === "GET") {
    let agentOk = false;
    let vaultOk = false;
    let workerOk = false;

    try {
      const agentRes = await fetch(`${AGENT_SERVICE_URL}/health/live`);
      agentOk = agentRes.ok;
    } catch (_) {}

    try {
      const vaultRes = await fetch(`${VAULT_SERVICE_URL}/health/live`);
      vaultOk = vaultRes.ok;
    } catch (_) {}

    try {
      const workerRes = await fetch(`${WORKER_SERVICE_URL}/health/live`);
      workerOk = workerRes.ok;
    } catch (_) {}

    const overallStatus = agentOk && vaultOk && workerOk ? "ok" : "degraded";

    return new Response(
      JSON.stringify({
        success: overallStatus === "ok",
        status: overallStatus,
        dependencies: {
          python_agent: agentOk ? "healthy" : "offline",
          vault_service: vaultOk ? "healthy" : "offline",
          worker_service: workerOk ? "healthy" : "offline",
        },
      }),
      {
        status: overallStatus === "ok" ? 200 : 503,
        headers: { ...corsHeaders, ...securityHeaders, "Content-Type": "application/json" },
      }
    );
  }

  // Metrics
  if (url.pathname === "/metrics" && req.method === "GET") {
    return createSuccessResponse(
      {
        total_requests: totalRequests,
        failed_requests: failedRequests,
        gateway_version: "1.3.0",
      },
      requestId,
      correlationId,
      Date.now() - startTime
    );
  }

  // AI execution routing
  if (url.pathname.startsWith("/v1/skills") || url.pathname.startsWith("/v1/workflows")) {
    let userId: string | null = null;

    try {
      const authHeader = req.headers.get("Authorization");
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        failedRequests++;
        return createErrorResponse("MISSING_BEARER_TOKEN", "Bearer authorization header is required.", correlationId, 401);
      }

      const token = authHeader.split(" ")[1];

      const { data: { user }, error: authError } = await supabase.auth.getUser(token);
      if (authError || !user) {
        failedRequests++;
        return createErrorResponse("INVALID_SESSION", "Active user session is invalid or has expired.", correlationId, 401);
      }

      userId = user.id;

      let bodyText = "";
      if (req.method === "POST") {
        bodyText = await req.clone().text();
        const payload = bodyText ? JSON.parse(bodyText) : {};
        const skillSlug = payload.skill_slug || payload.workflow_slug || "brainstorm";

        // CREDIT GATING
        const { data: debitResult, error: debitError } = await supabase.rpc("debit_credits", {
          p_user_id: userId,
          p_skill_name: skillSlug,
          p_model: payload.model_override || "career-os-gpt",
          p_tokens_used: 100,
          p_metadata: { source: "gateway-proxy", correlationId }
        });

        if (debitError || !debitResult || !debitResult.success) {
          failedRequests++;
          return createErrorResponse("INSUFFICIENT_CREDITS", debitError?.message || debitResult?.error || "Insufficient balance.", correlationId, 402);
        }
      }

      const agentUrl = `${AGENT_SERVICE_URL}${url.pathname}${url.search}`;
      
      const response = await fetch(agentUrl, {
        method: req.method,
        headers: {
          "Content-Type": "application/json",
          "X-Correlation-ID": correlationId,
          "X-Request-ID": requestId,
        },
        body: req.method === "GET" ? undefined : (bodyText || undefined),
      });

      if (response.headers.get("Content-Type")?.includes("text/event-stream")) {
        return new Response(response.body, {
          status: 200,
          headers: {
            ...corsHeaders,
            ...securityHeaders,
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Correlation-ID": correlationId,
            "X-Request-ID": requestId,
          },
        });
      }

      const responseText = await response.text();

      // Return the standardized payload from backend directly
      return new Response(responseText, {
        status: response.status,
        headers: { ...corsHeaders, ...securityHeaders, "Content-Type": "application/json" }
      });
    } catch (err) {
      failedRequests++;
      return createErrorResponse("GATEWAY_PROXY_ERROR", err.message, correlationId, 502);
    }
  }

  // Encrypt / Decrypt Vault Proxying
  if (url.pathname.startsWith("/v1/encrypt") || url.pathname.startsWith("/v1/decrypt")) {
    try {
      const vaultUrl = `${VAULT_SERVICE_URL}${url.pathname}`;
      const payload = await req.text();

      const response = await fetch(vaultUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      });

      const responseText = await response.text();

      // Return the standardized payload from vault directly
      return new Response(responseText, {
        status: response.status,
        headers: { ...corsHeaders, ...securityHeaders, "Content-Type": "application/json" }
      });
    } catch (err) {
      failedRequests++;
      return createErrorResponse("VAULT_PROXY_ERROR", err.message, correlationId, 502);
    }
  }

  failedRequests++;
  return createErrorResponse("NOT_FOUND", "The requested path could not be found.", correlationId, 404);
};

logJson("INFO", `Edge Gateway active on http://localhost:${PORT}`);
await serve(handler, { port: PORT });
