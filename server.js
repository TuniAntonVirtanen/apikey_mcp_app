// MCP app
//
// New flow:
//   1. Client connects to /mcp with NO auth at all — no oauth-protected-resource
//      metadata is published anymore, so ChatGPT won't try to run an OAuth
//      handshake before it can even list tools.
//   2. The model can call `authenticate` at any point. It returns a widget
//      (an iframe) with an input box for the API key generated on the
//      customer dashboard.
//   3. The widget calls the `submit_api_key` tool via window.openai.callTool.
//      That tool exchanges the key for a short-lived RS256 JWT at the
//      customer backend's /api/exchange-api-key, and stores that JWT
//      against THIS MCP session (keyed by the streamable-HTTP session id).
//   4. Once authenticated, get_workspace* tools use the session's stored
//      token to call mcp-backend exactly like before.
//
// IMPORTANT PROTOTYPE CAVEAT: session state lives in an in-memory Map. That
// is fine for a single-process prototype, but it means (a) a server restart
// forces re-authentication, and (b) this will NOT work if you scale to
// multiple instances behind a load balancer without sticky sessions / a
// shared session store (e.g. Redis). Fine to defer, as agreed, but worth
// flagging since it's a real constraint of this design, not just a "do more
// work later" detail.
import express from "express";
import cors from "cors";
import crypto from "crypto";
import { AsyncLocalStorage } from "async_hooks";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

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

const CUSTOMER_BACKEND_URL = process.env.CUSTOMER_BACKEND_URL || "https://apikey-customer-backend.onrender.com";
const MCP_BACKEND_URL = process.env.MCP_BACKEND_URL || "https://apikey-mcp-backend.onrender.com";

const getHostUrl = (req) => `${req.protocol}://${req.get("host")}`;

// resource identifier this app requests tokens against when exchanging an
// API key. Must match what mcp-backend checks as its expected audience.
const MCP_APP_RESOURCE_URL = process.env.MCP_APP_RESOURCE_URL || "https://apikey-mcp-app.onrender.com/mcp";

// ---------------------------------------------------------------------------
// SESSION STORE (protocol routing only)
// sessionId -> { transport }
// One transport per active streamable-HTTP session, purely so MCP protocol
// messages get routed to the right server/transport pair.
// ---------------------------------------------------------------------------
const sessions = new Map();

// ---------------------------------------------------------------------------
// AUTH STATE (deliberately NOT per-session)
// In testing, the connecting client re-initializes a fresh MCP session on
// most turns rather than reusing one Mcp-Session-Id for the whole
// conversation — so auth state tied to a session id gets thrown away the
// moment the session churns. Since this prototype already assumes a single
// mock user (see the single-slot activeApiKey on the customer backend),
// auth state here is likewise a single global slot rather than per-session.
// PROD NOTE: a real multi-user version would need a stable identity to key
// this by (e.g. a cookie set on the widget's iframe, or a longer-lived
// per-user session token), not the transport session id.
// ---------------------------------------------------------------------------
let authState = { token: null, authenticated: false };

// Propagates the current session id into tool handlers, which run inside
// async callbacks where we don't otherwise have access to `req`. Still
// useful for logging / future per-session needs even though auth no longer
// depends on it.
const requestContext = new AsyncLocalStorage();

const AUTH_WIDGET_HTML = `
<div id="app" style="font-family: -apple-system, sans-serif; padding: 16px; max-width: 380px; box-sizing: border-box;">
  <h3 style="margin: 0 0 8px 0;">Connect your account</h3>
  <p style="font-size: 13px; color: #555; margin: 0 0 12px 0;">
    Log into your dashboard in a browser tab, generate an API key there, then paste it below.
  </p>
  <input
    id="apiKeyInput"
    type="text"
    placeholder="Paste API key (sk_...)"
    style="width: 100%; padding: 8px; box-sizing: border-box; margin-bottom: 8px; font-family: monospace;"
  />
  <button id="submitBtn" style="width: 100%; padding: 8px 16px; cursor: pointer;">Authenticate</button>
  <div id="status" style="margin-top: 10px; font-size: 13px;"></div>
</div>
<script>
  (function () {
    var btn = document.getElementById('submitBtn');
    var input = document.getElementById('apiKeyInput');
    var status = document.getElementById('status');

    async function submit() {
      var apiKey = input.value.trim();
      if (!apiKey) {
        status.textContent = 'Please paste your API key.';
        status.style.color = '#c00';
        return;
      }
      if (!window.openai || !window.openai.callTool) {
        status.textContent = 'This widget must be opened inside the chat app.';
        status.style.color = '#c00';
        return;
      }

      btn.disabled = true;
      status.textContent = 'Authenticating...';
      status.style.color = '#555';

      try {
        var result = await window.openai.callTool('submit_api_key', { apiKey: apiKey });
        if (result && result.isError) {
          var msg = (result.content && result.content[0] && result.content[0].text) || 'Authentication failed.';
          status.textContent = msg;
          status.style.color = '#c00';
          btn.disabled = false;
          return;
        }
        status.textContent = 'Authenticated! You can close this and continue chatting.';
        status.style.color = '#0a0';
        if (window.openai.sendFollowUpMessage) {
          window.openai.sendFollowUpMessage({ prompt: 'I have authenticated, please continue with my original request.' });
        }
      } catch (err) {
        status.textContent = 'Error: ' + (err && err.message ? err.message : 'unknown error');
        status.style.color = '#c00';
        btn.disabled = false;
      }
    }

    btn.addEventListener('click', submit);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') submit();
    });
  })();
</script>
`;

async function fetchCustomerData() {
  if (!authState.authenticated || !authState.token) {
    const err = new Error(
      "Not authenticated yet. Call the 'authenticate' tool, generate an API key on the dashboard, and paste it into the widget."
    );
    err.code = "NOT_AUTHENTICATED";
    throw err;
  }

  const response = await fetch(`${MCP_BACKEND_URL}/api/v1/projects`, {
    headers: { Authorization: `Bearer ${authState.token}` }
  });

  if (response.status === 401 || response.status === 403) {
    // Token expired or was rejected downstream — drop auth state so the
    // next call prompts re-authentication instead of looping on stale data.
    authState = { token: null, authenticated: false };
    const err = new Error("Your session expired. Please authenticate again.");
    err.code = "NOT_AUTHENTICATED";
    throw err;
  }

  if (!response.ok) throw new Error(`MCP Backend status ${response.status}`);
  const result = await response.json();
  return result.data;
}

function buildServer() {
  const server = new McpServer({
    name: "customer-mcp-app",
    version: "3.0.0"
  });

  // -------------------------------------------------------------------
  // WIDGET RESOURCE
  // -------------------------------------------------------------------
  server.registerResource(
    "auth-widget",
    "ui://widget/auth.html",
    {},
    async () => ({
      contents: [
        {
          uri: "ui://widget/auth.html",
          mimeType: "text/html+skybridge",
          text: AUTH_WIDGET_HTML
        }
      ]
    })
  );

  // -------------------------------------------------------------------
  // AUTH TOOLS
  // -------------------------------------------------------------------
  server.registerTool(
    "authenticate",
    {
      title: "Connect your account",
      description:
        "Opens a widget to connect this chat to your account. Generate an API key from your dashboard and paste it into the widget to authenticate. Call this whenever data tools report that authentication is required.",
      _meta: {
        "openai/outputTemplate": "ui://widget/auth.html",
        "openai/widgetAccessible": true,
        "openai/toolInvocation/invoking": "Opening the sign-in widget",
        "openai/toolInvocation/invoked": "Sign-in widget ready"
      },
      inputSchema: {}
    },
    async () => {
      return {
        content: [
          {
            type: "text",
            text: "Paste the API key from your dashboard into the widget to authenticate."
          }
        ],
        structuredContent: {}
      };
    }
  );

  server.registerTool(
    "submit_api_key",
    {
      title: "Submit API key",
      description:
        "Internal tool used by the authenticate widget to submit the pasted API key. Not normally called directly.",
      _meta: {
        "openai/widgetAccessible": true
      },
      inputSchema: { apiKey: z.string().min(1) }
    },
    async ({ apiKey }) => {
      const exchangeUrl = `${CUSTOMER_BACKEND_URL}/api/exchange-api-key`;
      try {
        const resp = await fetch(exchangeUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ apiKey, resource: MCP_APP_RESOURCE_URL })
        });

        if (!resp.ok) {
          const rawBody = await resp.text();
          let errBody = {};
          try {
            errBody = JSON.parse(rawBody);
          } catch {
            // Non-JSON body (e.g. an HTML 404 page) usually means
            // exchangeUrl is wrong, not that the key itself was rejected.
          }
          console.error(
            `[MCP APP] Key exchange failed. url=${exchangeUrl} status=${resp.status} body=${rawBody.slice(0, 300)}`
          );
          return {
            isError: true,
            content: [
              {
                type: "text",
                text:
                  errBody.error_description ||
                  `That API key was rejected (HTTP ${resp.status} from ${exchangeUrl}). Check CUSTOMER_BACKEND_URL and try again.`
              }
            ]
          };
        }

        const { access_token } = await resp.json();
        authState = { token: access_token, authenticated: true };

        return {
          content: [{ type: "text", text: "Authenticated successfully." }]
        };
      } catch (err) {
        console.error("[MCP APP] Error exchanging API key:", err.message);
        return {
          isError: true,
          content: [{ type: "text", text: `Error contacting authentication service: ${err.message}` }]
        };
      }
    }
  );

  // -------------------------------------------------------------------
  // DATA TOOLS — same behavior as before, now gated on session auth
  // instead of a bearer token supplied at connection time.
  // -------------------------------------------------------------------
  server.tool(
    "get_workspace1",
    "Fetches workspace 1 sprint metrics from the customer account.",
    {},
    async () => {
      try {
        const data = await fetchCustomerData();
        const ws1 = data.workspace1;
        return {
          content: [
            {
              type: "text",
              text: `Active Sprint: ${ws1.completedTasks} completed tasks, ${ws1.inProgressTasks} in progress`
            }
          ]
        };
      } catch (err) {
        console.error("[MCP APP] Error querying MCP Backend:", err.message);
        return { isError: true, content: [{ type: "text", text: err.message }] };
      }
    }
  );

  server.tool(
    "get_workspace2_raw",
    "Fetches raw key-value pair metrics for Workspace 2.",
    {},
    async () => {
      try {
        const data = await fetchCustomerData();
        return { content: [{ type: "text", text: JSON.stringify({ metrics: data.workspace2 }) }] };
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: err.message }] };
      }
    }
  );

  server.tool(
    "get_workspace2_formatted",
    "Fetches Workspace 2 data formatted as a graphical bar chart.",
    {},
    async () => {
      try {
        const data = await fetchCustomerData();
        const labels = Object.keys(data.workspace2).map((k) => `"${k}"`).join(", ");
        const values = Object.values(data.workspace2).join(", ");

        return {
          content: [
            {
              type: "text",
              text:
                `Data: ${JSON.stringify(data.workspace2)}\n\n` +
                `CRITICAL VISUALIZATION INSTRUCTION:\n` +
                `Do NOT output ASCII text or bullet points.\n` +
                `You MUST output a syntactically valid Mermaid.js xychart block so the UI renders an actual graphical plot card:\n\n` +
                "```mermaid\n" +
                `xychart-beta\n` +
                `    title "Workspace 2 Metrics"\n` +
                `    x-axis [${labels}]\n` +
                `    y-axis "Values" 0 --> 10\n` +
                `    bar [${values}]\n` +
                "```"
            }
          ]
        };
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: err.message }] };
      }
    }
  );

  server.tool(
    "get_workspace3_raw",
    "Fetches raw edge-pair transitions representing a graph from Workspace 3.",
    {},
    async () => {
      try {
        const data = await fetchCustomerData();
        return { content: [{ type: "text", text: JSON.stringify({ edges: data.workspace3 }) }] };
      } catch (err) {
        console.error("[MCP APP] Error fetching raw edges:", err.message);
        return { isError: true, content: [{ type: "text", text: err.message }] };
      }
    }
  );

  server.tool(
    "get_workspace3_formatted",
    "Requests a rendered flow/transition graph diagram for Workspace 3.",
    {},
    async () => {
      try {
        const data = await fetchCustomerData();
        const edges = data.workspace3;
        const mermaidEdges = edges.map(([from, to]) => `    ${from} --> ${to}`).join("\n");

        return {
          content: [
            {
              type: "text",
              text:
                `Data Edges: ${JSON.stringify(edges)}\n\n` +
                `CRITICAL VISUALIZATION INSTRUCTION:\n` +
                `Do NOT output plain text lists.\n` +
                `You MUST output a syntactically complete Mermaid.js graph code block so the UI renders a graphical diagram card:\n\n` +
                "```mermaid\n" +
                `graph LR\n` +
                `${mermaidEdges}\n` +
                "```"
            }
          ]
        };
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: err.message }] };
      }
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// NO oauth-protected-resource metadata is published anymore — publishing it
// is what tells an Apps SDK / MCP client "this connector requires OAuth
// before you can even list tools". We want zero friction at connect time.
// ---------------------------------------------------------------------------

app.use("/mcp", express.json(), async (req, res) => {
  try {
    const incomingSessionId = req.headers["mcp-session-id"];
    let entry;

    if (incomingSessionId && sessions.has(incomingSessionId)) {
      entry = sessions.get(incomingSessionId);
    } else if (!incomingSessionId && isInitializeRequest(req.body)) {
      const server = buildServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
        onsessioninitialized: (sessionId) => {
          sessions.set(sessionId, { transport });
          console.log(`[MCP APP] Session initialized: ${sessionId}`);
        }
      });

      transport.onclose = () => {
        if (transport.sessionId) {
          sessions.delete(transport.sessionId);
          console.log(`[MCP APP] Session closed: ${transport.sessionId}`);
        }
      };

      await server.connect(transport);
      entry = { transport };
    } else {
      return res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: No valid session. Reconnect to start a new one." },
        id: null
      });
    }

    await requestContext.run({ sessionId: entry.transport.sessionId }, async () => {
      await entry.transport.handleRequest(req, res, req.body);
    });
  } catch (err) {
    console.error("[MCP APP] Error during protocol handling:", err);
    if (!res.headersSent) res.status(500).json({ error: "internal_error" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`MCP App running on port ${port}`);
  console.log(`[CONFIG] CUSTOMER_BACKEND_URL = ${CUSTOMER_BACKEND_URL}`);
  console.log(`[CONFIG] MCP_BACKEND_URL      = ${MCP_BACKEND_URL}`);
  console.log(`[CONFIG] MCP_APP_RESOURCE_URL = ${MCP_APP_RESOURCE_URL}`);
});