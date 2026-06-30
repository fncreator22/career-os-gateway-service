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

      let user = null;
      let authError = null;

      // All tokens must be validated against Supabase — no mock bypass.
      const authRes = await supabase.auth.getUser(token);
      user = authRes.data.user;
      authError = authRes.error;

      if (authError || !user) {
        failedRequests++;
        return createErrorResponse("INVALID_SESSION", "Active user session is invalid or has expired.", correlationId, 401);
      }

      userId = user.id;

      let bodyText = "";
      let userTier = "free";
      let skillSlug = "brainstorm";
      let modelName = "claude-sonnet-4-6";
      let estInput = 2000;
      let estOutput = 1000;

      if (req.method === "POST") {
        bodyText = await req.clone().text();
        const payload = bodyText ? JSON.parse(bodyText) : {};
        skillSlug = payload.skill_slug || payload.workflow_slug || "brainstorm";
        modelName = payload.model_override || "claude-sonnet-4-6";
        if (modelName === "career-os-gpt" || modelName === "gpt-4o") modelName = "gpt-4o";
        else if (modelName === "career-os-claude" || modelName === "claude-sonnet-4-6") modelName = "claude-sonnet-4-6";
        else if (modelName === "gpt-4o-mini") modelName = "gpt-4o-mini";
        else if (modelName === "claude-haiku-4-5") modelName = "claude-haiku-4-5";

        // 1. Fetch user subscription tier
        const { data: subData } = await supabase
          .from("user_subscription")
          .select("tier_slug")
          .eq("user_id", userId)
          .single();
        if (subData?.tier_slug) {
          userTier = subData.tier_slug;
        }

        // 2. Fetch expected tokens estimates
        const { data: estData } = await supabase
          .from("skill_token_estimates")
          .select("avg_input_tokens, avg_output_tokens")
          .eq("skill_slug", skillSlug)
          .single();
        if (estData) {
          estInput = estData.avg_input_tokens || 2000;
          estOutput = estData.avg_output_tokens || 1000;
        }

        // 3. Pre-flight quota check
        const { data: checkResult, error: checkError } = await supabase.rpc("check_token_quota", {
          p_user_id: userId,
          p_user_tier: userTier,
          p_skill_slug: skillSlug,
          p_model: modelName,
          p_input_tokens: estInput,
          p_output_tokens: estOutput
        });

        if (checkError || !checkResult || !checkResult.success) {
          failedRequests++;
          const reason = checkResult?.reason || "insufficient_quota";
          return createErrorResponse("INSUFFICIENT_QUOTA", `Quota check failed: ${reason}`, correlationId, 402);
        }
      }

      let modifiedBodyText = bodyText;
      if (req.method === "POST" && userId) {
        try {
          const payload = JSON.parse(bodyText);
          payload.user_id = userId;
          if (payload.prompt && !payload.prompt_payload) {
            payload.prompt_payload = payload.prompt;
          }
          if (payload.inputs?.query && !payload.prompt_payload) {
            payload.prompt_payload = payload.inputs.query;
          }
          modifiedBodyText = JSON.stringify(payload);
        } catch (_) {}
      }

      const agentUrl = `${AGENT_SERVICE_URL}${url.pathname}${url.search}`;
      
      const response = await fetch(agentUrl, {
        method: req.method,
        headers: {
          "Content-Type": "application/json",
          "X-Correlation-ID": correlationId,
          "X-Request-ID": requestId,
        },
        body: req.method === "GET" ? undefined : (modifiedBodyText || undefined),
      });

      if (response.headers.get("Content-Type")?.includes("text/event-stream")) {
        // Run actual consume_token_quota with estimate for streams on successful initiation
        if (req.method === "POST" && userId && response.ok) {
          await supabase.rpc("consume_token_quota", {
            p_user_id: userId,
            p_user_tier: userTier,
            p_skill_slug: skillSlug,
            p_model: modelName,
            p_input_tokens: estInput,
            p_output_tokens: estOutput
          });
        }
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

      // Post-flight actual usage debit for non-streaming
      if (req.method === "POST" && userId && response.ok) {
        let actualInput = estInput;
        let actualOutput = estOutput;
        try {
          const responseJson = JSON.parse(responseText);
          if (responseJson.usage) {
            actualInput = responseJson.usage.prompt_tokens || estInput;
            actualOutput = responseJson.usage.completion_tokens || estOutput;
          }
        } catch (_) {}

        await supabase.rpc("consume_token_quota", {
          p_user_id: userId,
          p_user_tier: userTier,
          p_skill_slug: skillSlug,
          p_model: modelName,
          p_input_tokens: actualInput,
          p_output_tokens: actualOutput
        });
      }

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
