// MCP app
import express from "express";
import cors from "cors";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { AsyncLocalStorage } from "async_hooks";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.set("trust proxy", 1);

app.use(
  cors({
    origin: "*",
    exposedHeaders: ["WWW-Authenticate", "Mcp-Session-Id"]
  })
);

app.use((req, res, next) => {
  console.log(`[MCP APP REQ] ${req.method} ${req.url}`);
  next();
});

const CUSTOMER_BACKEND_URL = process.env.CUSTOMER_BACKEND_URL || "https://customer-backend-stqk.onrender.com";
const MCP_BACKEND_URL = process.env.MCP_BACKEND_URL || "https://prototype-mcp-backend.onrender.com";

const getHostUrl = (req) => `${req.protocol}://${req.get("host")}`;

// AsyncLocalStorage propagates request context (Auth Header) into tool handler calls asynchronously
const requestContext = new AsyncLocalStorage();

// ---------------------------------------------------------------------------
// Token verification (JWKS-backed RS256). Previously this middleware only
// checked that an Authorization: Bearer header was present, and fully
// deferred trust to mcp-backend. As the service that actually publishes
// /.well-known/oauth-protected-resource, mcp-app is the OAuth resource
// server for this MCP endpoint, so it now verifies the signature, expiry,
// and audience itself instead of passing an unverified token onward.
// ---------------------------------------------------------------------------
let cachedPemPublicKey = null;

async function getPublicKeyFromJWKS() {
  if (cachedPemPublicKey) return cachedPemPublicKey;

  const resKey = await fetch(`${CUSTOMER_BACKEND_URL}/.well-known/jwks.json`);
  if (!resKey.ok) throw new Error(`Failed to fetch JWKS: ${resKey.status}`);

  const jwks = await resKey.json();
  const jwk = jwks.keys && jwks.keys[0];
  if (!jwk) throw new Error("No public key found in JWKS");

  const keyObject = crypto.createPublicKey({ key: jwk, format: "jwk" });
  cachedPemPublicKey = keyObject.export({ type: "spki", format: "pem" });
  return cachedPemPublicKey;
}

const validateAuthHeader = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const host = getHostUrl(req);

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.set(
      "WWW-Authenticate",
      `Bearer realm="mcp", resource_metadata="${host}/.well-known/oauth-protected-resource"`
    );
    return res.status(401).json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "Authentication required." },
      id: null
    });
  }

  const token = authHeader.slice("Bearer ".length);

  // This is the same resource identifier advertised in
  // /.well-known/oauth-protected-resource below, and the value a
  // well-behaved client passes as `resource` when it requests
  // authorization. A token not issued for this exact resource is rejected,
  // even if it is validly signed by the trusted authorization server.
  const resourceUri = `${host}/mcp`;

  try {
    const publicKey = await getPublicKeyFromJWKS();
    const verifiedPayload = jwt.verify(token, publicKey, {
      algorithms: ["RS256"],
      audience: resourceUri
    });
    req.authTokenPayload = verifiedPayload;
    next();
  } catch (err) {
    console.error("[MCP APP AUTH ERROR]", err.message);
    // Invalidate cached key if verification fails to allow key rotation recovery
    cachedPemPublicKey = null;
    res.set(
      "WWW-Authenticate",
      `Bearer realm="mcp", resource_metadata="${host}/.well-known/oauth-protected-resource", error="invalid_token"`
    );
    return res.status(401).json({
      jsonrpc: "2.0",
      error: { code: -32001, message: `Token verification failed: ${err.message}` },
      id: null
    });
  }
};

// Helper for tool execution to fetch data using active context token
const fetchCustomerData = async () => {
  const store = requestContext.getStore();
  const authToken = store?.authToken;

  if (!authToken) {
    throw new Error("Missing authentication context for tool execution.");
  }

  const response = await fetch(`${MCP_BACKEND_URL}/api/v1/projects`, {
    headers: { Authorization: authToken }
  });

  if (!response.ok) throw new Error(`MCP Backend status ${response.status}`);
  const result = await response.json();
  return result.data;
};

// Application-scoped single MCP server instance
const server = new McpServer({
  name: "customer-mcp-app",
  version: "2.0.0"
});

// -------------------------------------------------------------------------
// WORKSPACE 1 TOOLS
// -------------------------------------------------------------------------
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
      return {
        isError: true,
        content: [{ type: "text", text: `Error processing request: ${err.message}` }]
      };
    }
  }
);

// -------------------------------------------------------------------------
// WORKSPACE 2 TOOLS
// -------------------------------------------------------------------------
server.tool(
  "get_workspace2_raw",
  "Fetches raw key-value pair metrics for Workspace 2.",
  {},
  async () => {
    try {
      const data = await fetchCustomerData();
      return {
        content: [{ type: "text", text: JSON.stringify({ metrics: data.workspace2 }) }]
      };
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
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: err.message }] };
    }
  }
);

// -------------------------------------------------------------------------
// WORKSPACE 3 TOOLS
// -------------------------------------------------------------------------
server.tool(
  "get_workspace3_raw",
  "Fetches raw edge-pair transitions representing a graph from Workspace 3.",
  {},
  async () => {
    try {
      const data = await fetchCustomerData();
      const rawEdges = data.workspace3;

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ edges: rawEdges })
          }
        ]
      };
    } catch (err) {
      console.error("[MCP APP] Error fetching raw edges:", err.message);
      return {
        isError: true,
        content: [{ type: "text", text: `Error processing request: ${err.message}` }]
      };
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

      const mermaidEdges = edges
        .map(([from, to]) => `    ${from} --> ${to}`)
        .join("\n");

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
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: err.message }] };
    }
  }
);

const sendProtectedResourceMetadata = (req, res) => {
  const host = getHostUrl(req);
  res.json({
    resource: `${host}/mcp`,
    authorization_servers: [CUSTOMER_BACKEND_URL],
    scopes_supported: ["read", "write"],
    bearer_methods_supported: ["header"]
  });
};

app.get("/.well-known/oauth-protected-resource", sendProtectedResourceMetadata);
app.get("/.well-known/oauth-protected-resource/mcp", sendProtectedResourceMetadata);

app.use("/mcp", express.json(), validateAuthHeader, async (req, res) => {
  try {
    const authToken = req.headers.authorization;

    // Create a new transport instance for this HTTP request lifecycle
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined
    });

    res.on("close", () => {
      transport.close();
    });

    // Connect the single server instance to the new per-request transport
    await server.connect(transport);

    // Execute request inside AsyncLocalStorage to pass bearer token to tools
    await requestContext.run({ authToken }, async () => {
      await transport.handleRequest(req, res, req.body);
    });
  } catch (err) {
    console.error("[MCP APP] Error during protocol handling:", err);
    if (!res.headersSent) res.status(500).json({ error: "internal_error" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`MCP App running on port ${port}`));