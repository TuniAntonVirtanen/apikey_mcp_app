// MCP-APP

import express from "express";
import cors from "cors";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.set("trust proxy", 1);

app.use(
  cors({
    origin: "*",
    exposedHeaders: ["Mcp-Session-Id"]
  })
);

app.use((req, res, next) => {
  console.log(`[MCP APP REQ] ${req.method} ${req.url}`);
  next();
});

const CUSTOMER_BACKEND_URL = process.env.CUSTOMER_BACKEND_URL || "https://customer-backend-stqk.onrender.com";
const MCP_BACKEND_URL = process.env.MCP_BACKEND_URL || "https://prototype-mcp-backend.onrender.com";

// This service's own public URL. Used as the `resource` value when
// exchanging an API key for an access token. MUST exactly match the
// MCP_APP_RESOURCE_URL configured on mcp-backend (`${PUBLIC_URL}/mcp` there
// must equal `${PUBLIC_URL}/mcp` here) — that's the audience mcp-backend
// checks incoming tokens against.
const PUBLIC_URL = process.env.PUBLIC_URL || "https://prototype-mcp.onrender.com";
const MCP_RESOURCE_URI = `${PUBLIC_URL}/mcp`;

// ---------------------------------------------------------------------------
// SINGLE ACTIVE AUTHENTICATED SESSION (PROTOTYPE SIMULATION)
// This is a single-user prototype (mirroring the "one active API key" model
// on customer-backend), so one in-memory slot is enough to represent
// "is this mcp-app instance currently authenticated, and with what token".
// Any client that successfully calls the `authenticate` tool authenticates
// the whole instance for every connected caller — there's no per-connection
// isolation. Fine here; a real multi-user deployment would key this by MCP
// session id (or whatever identifies a distinct connected client) instead.
// PROD NOTE: Replace with per-session storage (DB or cache) for multi-user use.
// ---------------------------------------------------------------------------
let currentSession = null;
// shape when set: { accessToken: string, expiresAt: number }

function isSessionValid() {
  return !!currentSession && Date.now() < currentSession.expiresAt;
}

function clearSession(reason) {
  if (currentSession) {
    console.log(`[MCP APP] Clearing session (${reason})`);
  }
  currentSession = null;
}

// Exchanges a user-supplied API key for a resource-bound access token by
// calling customer-backend directly over HTTPS. Because mcp-app made this
// request itself and got the token back over a trusted transport, it does
// NOT re-verify the token's signature locally — signature + audience
// verification still happens (and is what actually matters) at mcp-backend
// on every subsequent data request, and again (signature-only) at
// customer-backend. mcp-app never re-signs or re-issues anything; it only
// ever caches and forwards exactly what customer-backend returned.
async function exchangeApiKeyForToken(apiKey) {
  const response = await fetch(`${CUSTOMER_BACKEND_URL}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "api_key",
      api_key: apiKey,
      resource: MCP_RESOURCE_URI
    })
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const reason = data.error_description || data.error || `HTTP ${response.status}`;
    throw new Error(reason);
  }

  return data; // { access_token, token_type, expires_in }
}

// Calls mcp-backend (which independently verifies signature + audience
// before doing anything) using the currently cached access token.
const fetchCustomerData = async (accessToken) => {
  const response = await fetch(`${MCP_BACKEND_URL}/api/v1/projects`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });

  if (!response.ok) {
    const err = new Error(`MCP Backend status ${response.status}`);
    err.status = response.status;
    throw err;
  }

  const result = await response.json();
  return result.data;
};

const AUTH_REQUIRED_MESSAGE =
  `Authentication required before this tool can be used. Ask the user to: ` +
  `1) log in to the customer dashboard at ${CUSTOMER_BACKEND_URL}, ` +
  `2) use the "API Key" panel there to generate a key (choosing how many minutes it should stay valid), ` +
  `3) paste that API key back into this chat. ` +
  `Once you have it, call the "authenticate" tool with that key, then retry this tool.`;

// Application-scoped single MCP server instance
const server = new McpServer({
  name: "customer-mcp-app",
  version: "3.0.0"
});

// -------------------------------------------------------------------------
// AUTH TOOL
// -------------------------------------------------------------------------
server.tool(
  "authenticate",
  `Authenticates this MCP connection using an API key the user generated on the customer dashboard (${CUSTOMER_BACKEND_URL}). ` +
    `Call this as soon as the user supplies an API key, or whenever another tool reports that authentication is required. ` +
    `Do not call it speculatively without a real key from the user.`,
  {
    api_key: z.string().min(1).describe("The API key the user copied from the customer dashboard.")
  },
  async ({ api_key }) => {
    try {
      const tokenData = await exchangeApiKeyForToken(api_key);
      currentSession = {
        accessToken: tokenData.access_token,
        expiresAt: Date.now() + tokenData.expires_in * 1000
      };
      const minutesLeft = Math.max(1, Math.round(tokenData.expires_in / 60));
      return {
        content: [
          {
            type: "text",
            text: `Authentication successful. This session is valid for about ${minutesLeft} minute(s). You can now use the other tools.`
          }
        ]
      };
    } catch (err) {
      clearSession("failed authentication attempt");
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Authentication failed: ${err.message}. Ask the user to generate a fresh API key on the dashboard (${CUSTOMER_BACKEND_URL}) and try again.`
          }
        ]
      };
    }
  }
);

// Shared wrapper for every data tool below: checks the cached session before
// doing any work, and drops the session if the backend ever rejects it.
async function withAuth(handler) {
  if (!isSessionValid()) {
    clearSession("no valid session at tool-call time");
    return { content: [{ type: "text", text: AUTH_REQUIRED_MESSAGE }] };
  }

  try {
    return await handler(currentSession.accessToken);
  } catch (err) {
    console.error("[MCP APP] Error querying MCP Backend:", err.message);
    if (err.status === 401 || err.status === 403) {
      // mcp-backend (or customer-backend behind it) no longer considers this
      // token good — expired right at the boundary, revoked, etc. Drop it so
      // the next call re-prompts instead of silently retrying with a dead token.
      clearSession("rejected by mcp-backend");
      return { content: [{ type: "text", text: AUTH_REQUIRED_MESSAGE }] };
    }
    return { isError: true, content: [{ type: "text", text: `Error processing request: ${err.message}` }] };
  }
}

// -------------------------------------------------------------------------
// WORKSPACE 1 TOOLS
// -------------------------------------------------------------------------
server.tool(
  "get_workspace1",
  "Fetches workspace 1 sprint metrics from the customer account.",
  {},
  async () =>
    withAuth(async (accessToken) => {
      const data = await fetchCustomerData(accessToken);
      const ws1 = data.workspace1;
      return {
        content: [
          {
            type: "text",
            text: `Active Sprint: ${ws1.completedTasks} completed tasks, ${ws1.inProgressTasks} in progress`
          }
        ]
      };
    })
);

// -------------------------------------------------------------------------
// WORKSPACE 2 TOOLS
// -------------------------------------------------------------------------
server.tool(
  "get_workspace2_raw",
  "Fetches raw key-value pair metrics for Workspace 2.",
  {},
  async () =>
    withAuth(async (accessToken) => {
      const data = await fetchCustomerData(accessToken);
      return { content: [{ type: "text", text: JSON.stringify({ metrics: data.workspace2 }) }] };
    })
);

server.tool(
  "get_workspace2_formatted",
  "Fetches Workspace 2 data formatted as a graphical bar chart.",
  {},
  async () =>
    withAuth(async (accessToken) => {
      const data = await fetchCustomerData(accessToken);
      const labels = Object.keys(data.workspace2).map(k => `"${k}"`).join(", ");
      const values = Object.values(data.workspace2).join(", ");

      return {
        content: [
          {
            type: "text",
            text: `Data: ${JSON.stringify(data.workspace2)}\n\n` +
                  `CRITICAL VISUALIZATION INSTRUCTION:\n` +
                  `Do NOT output ASCII text or bullet points.\n` +
                  `You MUST output a syntactically valid Mermaid.js xychart block so the UI renders an actual graphical plot card:\n\n` +
                  `\`\`\`mermaid\n` +
                  `xychart-beta\n` +
                  `    title "Workspace 2 Metrics"\n` +
                  `    x-axis [${labels}]\n` +
                  `    y-axis "Values" 0 --> 10\n` +
                  `    bar [${values}]\n` +
                  `\`\`\``
          }
        ]
      };
    })
);

// -------------------------------------------------------------------------
// WORKSPACE 3 TOOLS
// -------------------------------------------------------------------------
server.tool(
  "get_workspace3_raw",
  "Fetches raw edge-pair transitions representing a graph from Workspace 3.",
  {},
  async () =>
    withAuth(async (accessToken) => {
      const data = await fetchCustomerData(accessToken);
      return { content: [{ type: "text", text: JSON.stringify({ edges: data.workspace3 }) }] };
    })
);

server.tool(
  "get_workspace3_formatted",
  "Requests a rendered flow/transition graph diagram for Workspace 3.",
  {},
  async () =>
    withAuth(async (accessToken) => {
      const data = await fetchCustomerData(accessToken);
      const edges = data.workspace3;
      const mermaidEdges = edges.map(([from, to]) => `    ${from} --> ${to}`).join("\n");

      return {
        content: [
          {
            type: "text",
            text: `Data Edges: ${JSON.stringify(edges)}\n\n` +
                  `CRITICAL VISUALIZATION INSTRUCTION:\n` +
                  `Do NOT output plain text lists.\n` +
                  `You MUST output a syntactically complete Mermaid.js graph code block so the UI renders a graphical diagram card:\n\n` +
                  `\`\`\`mermaid\n` +
                  `graph LR\n` +
                  `${mermaidEdges}\n` +
                  `\`\`\``
          }
        ]
      };
    })
);

// -------------------------------------------------------------------------
// MCP TRANSPORT
// No auth gate at connection time: anyone who can reach this URL can
// connect and list tools. Only tool CALLS that touch customer data require
// a valid cached session (see withAuth above) — enforced token-side, at
// mcp-backend and customer-backend, not here.
// -------------------------------------------------------------------------
app.use("/mcp", express.json(), async (req, res) => {
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined
    });

    res.on("close", () => {
      transport.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("[MCP APP] Error during protocol handling:", err);
    if (!res.headersSent) res.status(500).json({ error: "internal_error" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`MCP App running on port ${port}`));