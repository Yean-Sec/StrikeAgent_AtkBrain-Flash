/**
 * DeepSeek Harness 本地工具插件：把图工具桥到 FastAPI。
 * 打包进 dsh-jsonrpc-agent 的运行时没有 @deepseek-ai/dsh-mcp-client，
 * 因此用绝对路径加载本文件，经 HTTP 调用 /api/projects/{pid}/agent-tools。
 */
export const name = "atkbrain-tools";
export const inject = ["tools"];

function toParams(schema) {
  const props = (schema && schema.properties) || {};
  const required = new Set((schema && schema.required) || []);
  const out = {};
  for (const [key, raw] of Object.entries(props)) {
    const spec = raw && typeof raw === "object" ? raw : {};
    const p = {
      type: spec.type || "string",
      description: spec.description || "",
    };
    if (required.has(key)) p.required = true;
    if (Array.isArray(spec.enum)) p.enum = spec.enum;
    if (spec.type === "array") p.items = spec.items || { type: "string" };
    if (spec.type === "object") p.additionalProperties = true;
    out[key] = p;
  }
  return out;
}

async function listTools(base, pid) {
  const res = await fetch(`${base}/api/projects/${pid}/agent-tools`);
  if (!res.ok) {
    throw new Error(`atkbrain tools list HTTP ${res.status}`);
  }
  const body = await res.json();
  return body.tools || [];
}

function loadEmbedded() {
  try {
    const raw = process.env.ATKBRAIN_TOOLS_JSON;
    if (raw) return JSON.parse(raw);
  } catch (_) {}
  return [];
}

export async function apply(ctx) {
  const base = (process.env.ATKBRAIN_TOOLS_BASE || "http://127.0.0.1:5003").replace(/\/$/, "");
  const pid = process.env.ATKBRAIN_PROJECT_ID;
  if (!pid) {
    throw new Error("ATKBRAIN_PROJECT_ID is required");
  }
  let tools = loadEmbedded();
  if (!Array.isArray(tools) || tools.length === 0) {
    tools = await listTools(base, pid);
  }
  for (const t of tools) {
    const rawName = t.name;
    const publicName = `mcp__atkbrain__${rawName}`;
    ctx.tools.register({
      name: publicName,
      description: t.description || rawName,
      parameters: toParams(t.inputSchema || {}),
      output: {
        schema: { type: "string" },
        render: (_args, value) => [{ type: "text", text: String(value ?? "") }],
      },
      async execute(args, exec) {
        const res = await fetch(`${base}/api/projects/${pid}/agent-tools/${encodeURIComponent(rawName)}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(args || {}),
          signal: exec && exec.signal,
        });
        const body = await res.json().catch(() => ({ text: `HTTP ${res.status}`, is_error: true }));
        const text = body.text || "";
        if (body.is_error) {
          throw new Error(text || `${rawName} failed`);
        }
        return text;
      },
    });
  }
}
