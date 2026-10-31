// Runs the reference TAP verifier (cdn-proxy/server.js, visa/trusted-agent-protocol@16d59bd)
// against KYA Bench TAP vectors, fully offline.
//
// stdin:  {"server_js": path, "now": unix, "registry": {...}, "vectors": [{"id", "requests": [...]}]}
// stdout: {"<id>": [{"passed": bool, "status": int|null, "title": str|null, "message": str|null}, ...]}
//
// The script is loaded into a vm context with stubbed modules: express (no-op app), axios
// (answers GET /keys/{keyId} from the registry fixture exactly like agent-registry/main.py
// get_key_by_id: unknown or inactive key -> 404; agent status is not consulted there),
// dotenv, http-proxy-middleware. Date.now is frozen to the vector time; setInterval is a no-op.
// The real `verifySignature` middleware is then called directly for each request. One fresh
// context per vector, so the nonce cache spans only that vector's requests.
"use strict";
const fs = require("fs");
const vm = require("vm");
const nodeCrypto = require("crypto");

function noopProxy() {
  const fn = function () { return proxy; };
  const proxy = new Proxy(fn, { get: (t, p) => (p === "then" ? undefined : proxy), apply: () => proxy });
  return proxy;
}

function makeAxios(registry) {
  return {
    get: async (url) => {
      const keyId = decodeURIComponent(url.split("/keys/")[1] || "");
      for (const agent of registry.agents || []) {
        for (const k of agent.keys || []) {
          if (k.key_id === keyId) {
            if (k.is_active !== "true") { const e = new Error("404 inactive"); e.response = { status: 404 }; throw e; }
            return { status: 200, data: { key_id: keyId, is_active: k.is_active, public_key: k.public_key,
                                          algorithm: k.algorithm, agent_id: agent.id, agent_domain: agent.domain } };
          }
        }
      }
      const e = new Error("404 not found"); e.response = { status: 404 }; throw e;
    },
  };
}

function loadVerifier(source, now, registry) {
  const stubs = {
    express: Object.assign(() => noopProxy(), { json: () => noopProxy(), static: () => noopProxy() }),
    "http-proxy-middleware": { createProxyMiddleware: () => noopProxy() },
    dotenv: { config: () => ({}) },
    axios: makeAxios(registry),
    crypto: nodeCrypto,
  };
  const quiet = { log() {}, error() {}, warn() {}, info() {} };
  const ctx = vm.createContext({
    require: (m) => { if (m in stubs) return stubs[m]; throw new Error("unexpected require " + m); },
    console: quiet, process: { env: {} }, Buffer, setInterval: () => 0, setTimeout, module: { exports: {} },
  });
  vm.runInContext(`Date.now = () => ${now * 1000};`, ctx);
  const tail = `
;sendErrorResponse = function (res, code, title, message) {
  res.__kya = { code, title, message }; res.status(code); res.send("");
};
globalThis.__kya = { verifySignature };`;
  vm.runInContext(source + tail, ctx, { filename: "server.js" });
  return ctx.__kya.verifySignature;
}

async function runRequest(verify, r) {
  const headers = Object.assign({}, r.headers, { host: r.authority });
  const req = {
    method: r.method, url: r.path + (r.query ? "?" + r.query : ""), headers,
    get: (n) => headers[String(n).toLowerCase()],
  };
  const res = { statusCode: null, status(c) { this.statusCode = c; return this; }, send() { return this; },
                setHeader() {} };
  let passed = false;
  try {
    await verify(req, res, () => { passed = true; });
  } catch (e) {
    return { passed: false, status: null, title: "exception", message: String(e && e.message) };
  }
  const k = res.__kya || {};
  return { passed, status: res.statusCode, title: k.title || null, message: k.message || null };
}

(async () => {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  const source = fs.readFileSync(input.server_js, "utf8");
  const out = {};
  for (const v of input.vectors) {
    const verify = loadVerifier(source, v.now ?? input.now, input.registry);
    out[v.id] = [];
    for (const r of v.requests) out[v.id].push(await runRequest(verify, r));
  }
  process.stdout.write(JSON.stringify(out));
})();
