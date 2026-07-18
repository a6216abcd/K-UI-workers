import { DurableObject } from "cloudflare:workers";

// Admins need the fastest updates. Public monitoring remains responsive at
// ten seconds, while no viewers reduces routine status work to thirty seconds.
const ADMIN_STATUS_INTERVAL = 5_000;
const PUBLIC_STATUS_INTERVAL = 10_000;
const IDLE_STATUS_INTERVAL = 30_000;
const STATUS_STALE_AFTER = 20_000;
const VIEWER_LEASE_MS = 90_000;
const RESYNC_COOLDOWN_MS = 30_000;
const SNAPSHOT_CACHE_MS = 10_000;
const MAX_PUBLIC_SOCKETS = 5;
const MAX_PUBLIC_SOCKETS_PER_IP = 1;
const MAX_DASHBOARD_SOCKETS = 5;
const DEFAULT_FREQUENCY_POLICY = { admin: ADMIN_STATUS_INTERVAL, public: PUBLIC_STATUS_INTERVAL, idle: IDLE_STATUS_INTERVAL };

function validFrequencyPolicy(value) {
  const admin = Number(value?.admin);
  const publicInterval = Number(value?.public);
  const idle = Number(value?.idle);
  if (!Number.isInteger(admin) || !Number.isInteger(publicInterval) || !Number.isInteger(idle) || admin < 5 || admin > 60 || publicInterval < 10 || publicInterval > 120 || idle < 30 || idle > 600 || publicInterval < admin || idle < publicInterval) return null;
  return { admin: admin * 1000, public: publicInterval * 1000, idle: idle * 1000 };
}

function viewerActive(attachment, now = Date.now()) { return Number(attachment?.lastActivity || 0) + VIEWER_LEASE_MS > now; }

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extraHeaders },
  });
}

function pagesOrigins(env) {
  return String(env.PAGES_ORIGIN || "").split(",").map(origin => origin.trim().replace(/\/$/, "")).filter(origin => /^https:\/\//.test(origin));
}

function isPagesDevOrigin(origin) {
  try { return new URL(origin).protocol === "https:" && /^[a-z0-9-]+\.pages\.dev$/i.test(new URL(origin).hostname); } catch { return false; }
}

function isWorkersDevOrigin(origin) {
  try { return new URL(origin).protocol === "https:" && /^[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev$/i.test(new URL(origin).hostname); } catch { return false; }
}

function isAllowedPagesOrigin(origin, env) {
  const configured = pagesOrigins(env);
  return configured.length ? configured.includes(origin) : (isPagesDevOrigin(origin) || isWorkersDevOrigin(origin));
}

function requestPagesOrigin(request, env) {
  const candidates = [request.headers.get("X-KUI-Pages-Origin"), request.headers.get("Origin")].filter(Boolean);
  return candidates.find(origin => isAllowedPagesOrigin(origin, env)) || "";
}

function cors(request, env) {
  const requested = request.headers.get("Origin") || "";
  const origin = isAllowedPagesOrigin(requested, env) ? requested : "null";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Vary": "Origin",
  };
}

function sanitizeSnapshot(snapshot) {
  if (!snapshot?.ip || !snapshot.core) return null;
  const core = snapshot.core;
  return {
    ip: snapshot.ip,
    core: {
      cpu: core.cpu, mem: core.mem, disk: core.disk, load: core.load, uptime: core.uptime,
      net_in_speed: core.net_in_speed, net_out_speed: core.net_out_speed,
      tcp_conn: core.tcp_conn, udp_conn: core.udp_conn,
    },
    core_last_seen: snapshot.core_last_seen || 0,
    core_state: snapshot.core_state || "offline",
    updated_at: snapshot.updated_at || 0,
  };
}

function compactRoleState(role, data) {
  if (role === "core") {
    const keys = ["cpu", "mem", "disk", "load", "uptime", "net_in_speed", "net_out_speed", "tcp_conn", "udp_conn", "os", "arch"];
    return Object.fromEntries(keys.filter(key => data?.[key] !== undefined).map(key => [key, data[key]]));
  }
  return {
    details: Array.isArray(data?.details) ? data.details.slice(0, 4).map(item => ({ tunnel: String(item?.tunnel || "").slice(0, 32), active: item?.active === true, node_ip: String(item?.node_ip || "").slice(0, 64), exit_ip: String(item?.exit_ip || "").slice(0, 64), country: String(item?.country || "").slice(0, 2), port: Number(item?.port) || 0, ready: item?.ready === true, connected_time: Math.max(0, Math.min(Number(item?.connected_time) || 0, 31536000)) })) : [],
    logs: String(data?.logs || "").slice(0, 16 * 1024),
  };
}

async function verifyAdmin(header, request, env) {
  try {
    if (!header?.startsWith("Bearer ")) return false;
    const token = header.slice(7);
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) return false;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    const tokenHash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
    const session = await env.DB.prepare("SELECT username FROM auth_sessions WHERE token_hash = ? AND expires_at > ?").bind(tokenHash, Date.now()).first();
    if (session?.username === (env.ADMIN_USERNAME || "admin")) return true;

    // Signed browser requests are validated by the Pages API. Keep this
    // fallback for clients that have not yet migrated to session tokens.
    const configured = pagesOrigins(env);
    const origins = configured.length ? configured : [requestPagesOrigin(request, env)].filter(Boolean);
    for (const origin of origins) {
      const response = await fetch(`${origin}/api/realtime_auth`, {
        method: "POST",
        headers: { Authorization: header, "Content-Type": "application/json" },
        body: "{}",
      });
      if (response.ok && (await response.json()).admin === true) return true;
    }
    return false;
  } catch {
    return false;
  }
}

async function verifyAgent(header, ip, env) {
  if (!header || !ip) return false;
  const server = await env.DB.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
  return !!server?.agent_token && header === server.agent_token;
}

async function presenceName(ip, env) {
  const server = await env.DB.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
  if (!server?.agent_token) return "";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(server.agent_token));
  const tokenHash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
  return `v2:${ip}:${tokenHash}`;
}

function doRequest(path, request, headers = {}) {
  const outgoing = new Request(`https://durable.internal${path}`, request);
  for (const [name, value] of Object.entries(headers)) outgoing.headers.set(name, value);
  return outgoing;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(request, env) });
    if (url.pathname === "/health") return json({ ok: true, service: "kui-realtime", version: 1 }, 200, cors(request, env));

    if (url.pathname === "/agent/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "WebSocket required" }, 426);
      const ip = url.searchParams.get("ip") || "";
      const role = url.searchParams.get("role") || "";
      if (!['core', 'proxy'].includes(role)) return json({ error: "Invalid role" }, 400);
      if (!(await verifyAgent(request.headers.get("Authorization"), ip, env))) return json({ error: "Unauthorized" }, 401);
      const name = await presenceName(ip, env);
      if (!name) return json({ error: "VPS not found" }, 404);
      const stub = env.VPS_PRESENCE.get(env.VPS_PRESENCE.idFromName(name));
      return stub.fetch(doRequest("/ws", request, { "X-KUI-IP": ip, "X-KUI-ROLE": role }));
    }

    if (url.pathname === "/dashboard/ticket" && request.method === "POST") {
      if (!(await verifyAdmin(request.headers.get("Authorization"), request, env))) return json({ error: "Forbidden" }, 403, cors(request, env));
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      const response = await hub.fetch(new Request("https://hub.internal/ticket", { method: "POST", headers: { "X-KUI-USER": "admin" } }));
      return new Response(response.body, { status: response.status, headers: { ...Object.fromEntries(response.headers), ...cors(request, env) } });
    }

    if (url.pathname === "/dashboard/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "WebSocket required" }, 426);
      if (!isAllowedPagesOrigin(request.headers.get("Origin") || "", env)) return json({ error: "Forbidden origin" }, 403);
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      return hub.fetch(doRequest(`/ws?ticket=${encodeURIComponent(url.searchParams.get("ticket") || "")}`, request));
    }

    if (url.pathname === "/public/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "WebSocket required" }, 426);
      if (!isAllowedPagesOrigin(request.headers.get("Origin") || "", env)) return json({ error: "Forbidden origin" }, 403);
      const setting = await env.DB.prepare("SELECT value FROM probe_settings WHERE key = 'is_public'").first();
      if (setting && setting.value !== "true") return json({ error: "Private dashboard" }, 403);
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      return hub.fetch(doRequest("/public-ws", request, { "X-KUI-CLIENT-IP": request.headers.get("CF-Connecting-IP") || "unknown" }));
    }

    if (url.pathname === "/dashboard/snapshot") {
      if (!(await verifyAdmin(request.headers.get("Authorization"), request, env))) return json({ error: "Forbidden" }, 403, cors(request, env));
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      const response = await hub.fetch(new Request("https://hub.internal/snapshot"));
      return new Response(response.body, { status: response.status, headers: { ...Object.fromEntries(response.headers), ...cors(request, env) } });
    }

    if (url.pathname === "/notify" && request.method === "POST") {
      if (!(await verifyAdmin(request.headers.get("Authorization"), request, env))) return json({ error: "Forbidden" }, 403, cors(request, env));
      const body = await request.json().catch(() => ({}));
      const ips = body.ip ? [body.ip] : (await env.DB.prepare("SELECT ip FROM servers").all()).results.map(row => row.ip);
      await Promise.all(ips.slice(0, 100).map(async ip => {
        const name = await presenceName(ip, env);
        if (!name) return;
        const stub = env.VPS_PRESENCE.get(env.VPS_PRESENCE.idFromName(name));
        return stub.fetch(new Request("https://presence.internal/notify", { method: "POST" }));
      }));
      return json({ success: true, notified: ips.length }, 200, cors(request, env));
    }

    if (url.pathname === "/public-policy" && request.method === "POST") {
      if (!(await verifyAdmin(request.headers.get("Authorization"), request, env))) return json({ error: "Forbidden" }, 403, cors(request, env));
      const body = await request.json().catch(() => ({}));
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      const response = await hub.fetch(new Request("https://hub.internal/public-policy", { method: "POST", headers: { "X-KUI-Public": body.public === true ? "1" : "0" } }));
      return new Response(response.body, { status: response.status, headers: { ...Object.fromEntries(response.headers), ...cors(request, env) } });
    }

    if (url.pathname === "/frequency-policy" && request.method === "POST") {
      if (!(await verifyAdmin(request.headers.get("Authorization"), request, env))) return json({ error: "Forbidden" }, 403, cors(request, env));
      const policy = validFrequencyPolicy(await request.json().catch(() => null));
      if (!policy) return json({ error: "Invalid frequency policy" }, 400, cors(request, env));
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      const response = await hub.fetch(new Request("https://hub.internal/frequency-policy", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ admin: policy.admin / 1000, public: policy.public / 1000, idle: policy.idle / 1000 }) }));
      return new Response(response.body, { status: response.status, headers: { ...Object.fromEntries(response.headers), ...cors(request, env) } });
    }

    return json({ error: "Not found" }, 404, cors(request, env));
  },
};

export class VpsPresence extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.snapshot = { ip: "", core: null, proxy: null, updated_at: 0 };
    this.dashboardActive = false;
    this.dashboardInterval = IDLE_STATUS_INTERVAL;
    this.dashboardActiveUntil = 0;
    this.lastPersisted = 0;
    this.lastStatusBroadcast = 0;
    try { ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong")); } catch {}
    this.lastSeq = { core: -1, proxy: -1 };
    this.bootId = { core: "", proxy: "" };
    ctx.blockConcurrencyWhile(async () => {
      const state = await ctx.storage.get("state");
      this.snapshot = state?.snapshot || (await ctx.storage.get("snapshot")) || this.snapshot;
      this.lastSeq = state?.lastSeq || (await ctx.storage.get("lastSeq")) || this.lastSeq;
      this.bootId = state?.bootId || (await ctx.storage.get("bootId")) || this.bootId;
      this.lastPersisted = Number(state?.persistedAt) || 0;
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/ws") {
      const ip = request.headers.get("X-KUI-IP") || "";
      const role = request.headers.get("X-KUI-ROLE") || "";
      for (const existing of this.ctx.getWebSockets(role)) {
        try { existing.close(1000, "replaced"); } catch {}
      }
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.serializeAttachment({ ip, role, connected_at: Date.now(), bootId: "", lastSeq: -1, lastSeen: 0, state: null });
      this.ctx.acceptWebSocket(server, [role]);
      const hub = this.env.DASHBOARD_HUB.get(this.env.DASHBOARD_HUB.idFromName("main"));
      try {
        const activeResponse = await hub.fetch(new Request("https://hub.internal/active"));
        const active = activeResponse.ok ? await activeResponse.json() : null;
        this.setDashboardActivity(active?.active === true, Number(active?.interval_seconds) * 1000 || IDLE_STATUS_INTERVAL, Number(active?.until) || Date.now() + 300000);
      } catch {}
      this.snapshot.ip = ip;
      this.snapshot[`${role}_connected`] = true;
      this.snapshot[`${role}_connected_at`] = Date.now();
      await this.broadcast();
      server.send(JSON.stringify({ type: "hello.ok", ts: Date.now(), role }));
      server.send(JSON.stringify({ type: "status.interval", seconds: this.dashboardInterval / 1000 }));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/notify") {
      for (const ws of this.ctx.getWebSockets()) {
        try { ws.send(JSON.stringify({ type: "config.refresh", ts: Date.now() })); } catch {}
      }
      return json({ success: true });
    }
    if (url.pathname === "/dashboard-active" && request.method === "POST") {
      this.setDashboardActivity(request.headers.get("X-KUI-Active") === "1", Number(request.headers.get("X-KUI-Interval")) || IDLE_STATUS_INTERVAL, Number(request.headers.get("X-KUI-Until")) || Date.now() + 300000);
      return json({ success: true });
    }
    if (url.pathname === "/snapshot") return json(this.publicSnapshot());
    return json({ error: "Not found" }, 404);
  }

  async webSocketMessage(ws, message) {
    if (typeof message !== "string" || message.length > 64 * 1024) return;
    let envelope;
    try { envelope = JSON.parse(message); } catch { return; }
    const attachment = ws.deserializeAttachment() || {};
    const role = attachment?.role;
    if (!['core', 'proxy'].includes(role) || envelope.role !== role || envelope.ip !== attachment.ip) return;
    const sequence = Number(envelope.seq);
    const bootId = String(envelope.boot_id || "");
    const messageType = String(envelope.type || "status");
    if (!Number.isSafeInteger(sequence) || sequence < 0 || !bootId) return;
    if (attachment.bootId !== bootId) {
      attachment.bootId = bootId;
      attachment.lastSeq = -1;
    }
    if (this.bootId[role] === bootId && sequence <= Number(this.lastSeq[role] ?? -1)) return;
    if (sequence <= Number(attachment.lastSeq ?? -1)) return;
    attachment.lastSeq = sequence;
    this.bootId[role] = bootId;
    this.lastSeq[role] = sequence;
    if (messageType === "hello") {
      attachment.capabilities = Array.isArray(envelope.data?.capabilities) ? envelope.data.capabilities.slice(0, 20).map(value => String(value).slice(0, 64)) : [];
      ws.serializeAttachment(attachment);
      return;
    }
    if (messageType === "config.result") {
      const result = { success: envelope.data?.success === true, component: String(envelope.data?.component || "").slice(0, 32), revision: Number(envelope.data?.revision) || 0, desired_mode: String(envelope.data?.desired_mode || "").slice(0, 32), applied_mode: String(envelope.data?.applied_mode || "").slice(0, 32), egress_ip: String(envelope.data?.egress_ip || "").slice(0, 64), error: String(envelope.data?.error || "").slice(0, 500), applied_at: Number(envelope.data?.applied_at) || Date.now() };
      this.snapshot[`${role}_config_result`] = result;
      if (result.component === "egress") this.snapshot[`${role}_egress_result`] = result;
      this.snapshot[`${role}_config_result_at`] = Date.now();
      ws.serializeAttachment(attachment);
      await this.persistAndBroadcast();
      return;
    }
    if (messageType !== "status") return;
    const previousRoleState = this.snapshot[role];
    const nextRoleState = compactRoleState(role, envelope.data || {});
    const criticalChange = !previousRoleState || (role === "proxy" && JSON.stringify((previousRoleState.details || []).map(item => [item.tunnel, item.active, item.node_ip])) !== JSON.stringify((nextRoleState.details || []).map(item => [item.tunnel, item.active, item.node_ip])));
    attachment.lastSeen = Date.now();
    attachment.state = compactRoleState(role, nextRoleState);
    ws.serializeAttachment(attachment);
    this.snapshot.ip = attachment.ip;
    this.snapshot[role] = nextRoleState;
    this.snapshot[`${role}_connected`] = true;
    this.snapshot[`${role}_last_seen`] = attachment.lastSeen;
    this.snapshot.updated_at = attachment.lastSeen;
    if (role === "core" && Date.now() - this.lastPersisted >= 60000) {
      this.lastPersisted = Date.now();
      await this.ctx.storage.put("state", { snapshot: this.snapshot, lastSeq: this.lastSeq, bootId: this.bootId, persistedAt: this.lastPersisted });
    }
    if (Date.now() >= this.dashboardActiveUntil) await this.refreshDashboardActivity();
    const statusBroadcastDue = this.dashboardActive && Date.now() - this.lastStatusBroadcast >= this.dashboardInterval;
    if (statusBroadcastDue) this.lastStatusBroadcast = Date.now();
    if (statusBroadcastDue || criticalChange) await this.broadcast();
  }

  async webSocketClose(ws) {
    await this.markDisconnected(ws);
  }

  async webSocketError(ws) {
    await this.markDisconnected(ws);
  }

  async markDisconnected(ws) {
    const role = ws.deserializeAttachment()?.role;
    if (['core', 'proxy'].includes(role) && this.ctx.getWebSockets(role).length === 0) {
      this.snapshot[`${role}_connected`] = false;
      this.snapshot[`${role}_disconnected_at`] = Date.now();
      await this.persistAndBroadcast();
    }
  }

  setDashboardActivity(active, interval, until) {
    const changed = this.dashboardActive !== active || this.dashboardInterval !== interval;
    this.dashboardActive = active;
    this.dashboardInterval = interval;
    this.dashboardActiveUntil = until;
    if (!changed) return;
    this.lastStatusBroadcast = 0;
    for (const ws of this.ctx.getWebSockets()) {
      try { ws.send(JSON.stringify({ type: "status.interval", seconds: interval / 1000 })); } catch {}
    }
  }

  async refreshDashboardActivity() {
    const hub = this.env.DASHBOARD_HUB.get(this.env.DASHBOARD_HUB.idFromName("main"));
    try {
      const response = await hub.fetch(new Request("https://hub.internal/active"));
      const active = response.ok ? await response.json() : null;
      this.setDashboardActivity(active?.active === true, Number(active?.interval_seconds) * 1000 || IDLE_STATUS_INTERVAL, Number(active?.until) || Date.now() + IDLE_STATUS_INTERVAL);
    } catch {
      this.setDashboardActivity(false, IDLE_STATUS_INTERVAL, Date.now() + IDLE_STATUS_INTERVAL);
    }
  }

  publicSnapshot() {
    this.syncFromSockets();
    const now = Date.now();
    const coreAge = this.snapshot.core_last_seen ? now - this.snapshot.core_last_seen : null;
    const proxyAge = this.snapshot.proxy_last_seen ? now - this.snapshot.proxy_last_seen : null;
    return {
      ...this.snapshot,
      core_state: !this.snapshot.core_connected ? "offline" : coreAge === null || coreAge > STATUS_STALE_AFTER ? "stale" : "online",
      proxy_state: !this.snapshot.proxy_connected ? "offline" : proxyAge === null || proxyAge > STATUS_STALE_AFTER ? "stale" : "online",
      core_age: coreAge,
      proxy_age: proxyAge,
      boot_id: this.bootId,
      sequence: this.lastSeq,
    };
  }

  syncFromSockets() {
    for (const role of ["core", "proxy"]) {
      const socket = this.ctx.getWebSockets(role)[0];
      const attachment = socket?.deserializeAttachment();
      this.snapshot[`${role}_connected`] = !!socket;
      if (!attachment) continue;
      this.snapshot.ip = attachment.ip || this.snapshot.ip;
      if (attachment.state) this.snapshot[role] = { ...(this.snapshot[role] || {}), ...attachment.state };
      if (attachment.lastSeen) this.snapshot[`${role}_last_seen`] = attachment.lastSeen;
      this.bootId[role] = attachment.bootId || this.bootId[role];
      this.lastSeq[role] = Number(attachment.lastSeq ?? this.lastSeq[role]);
    }
    this.snapshot.updated_at = Math.max(this.snapshot.core_last_seen || 0, this.snapshot.proxy_last_seen || 0, this.snapshot.updated_at || 0);
  }

  async persistAndBroadcast() {
    this.snapshot.updated_at = Date.now();
    this.lastPersisted = Date.now();
    await this.ctx.storage.put("state", { snapshot: this.snapshot, lastSeq: this.lastSeq, bootId: this.bootId, persistedAt: this.lastPersisted });
    await this.broadcast();
  }

  async broadcast() {
    const hub = this.env.DASHBOARD_HUB.get(this.env.DASHBOARD_HUB.idFromName("main"));
    if (Date.now() >= this.dashboardActiveUntil) await this.refreshDashboardActivity();
    if (!this.dashboardActive) return;
    await hub.fetch(new Request("https://hub.internal/update", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-KUI-Presence": "1" },
      body: JSON.stringify(this.publicSnapshot()),
    }));
  }
}

export class DashboardHub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    try { ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong")); } catch {}
    this.activityUntil = 0;
    this.activityInterval = IDLE_STATUS_INTERVAL;
    this.frequencyPolicy = DEFAULT_FREQUENCY_POLICY;
    this.publicPolicyAllowed = false;
    this.publicPolicyCheckedAt = 0;
    this.snapshotCache = null;
    this.snapshotCachedAt = 0;
    ctx.blockConcurrencyWhile(async () => {
      this.frequencyPolicy = validFrequencyPolicy(await ctx.storage.get("frequencyPolicy")) || DEFAULT_FREQUENCY_POLICY;
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/ticket" && request.method === "POST") {
      const ticket = crypto.randomUUID();
      await this.ctx.storage.put(`ticket:${ticket}`, { user: request.headers.get("X-KUI-USER") || "", expires: Date.now() + 60000 });
      await this.ctx.storage.setAlarm(Date.now() + 65000);
      return json({ ticket, expires_in: 60 });
    }
    if (url.pathname === "/active") {
      const interval = this.viewerInterval();
      const active = this.ctx.getWebSockets("dashboard").length + this.ctx.getWebSockets("public").length > 0;
      return json({ active, interval_seconds: interval / 1000, until: active ? Date.now() + VIEWER_LEASE_MS : 0 });
    }
    if (url.pathname === "/ws") {
      const ticket = url.searchParams.get("ticket") || "";
      const record = await this.ctx.storage.get(`ticket:${ticket}`);
      if (!record || record.expires < Date.now()) {
        if (record) await this.ctx.storage.delete(`ticket:${ticket}`);
        return json({ error: "Invalid ticket" }, 401);
      }
      await this.ctx.storage.delete(`ticket:${ticket}`);
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      if (this.ctx.getWebSockets("dashboard").length >= MAX_DASHBOARD_SOCKETS) return json({ error: "Too many dashboard connections" }, 429);
      server.serializeAttachment({ user: record.user, connected_at: Date.now(), lastActivity: Date.now(), lastResync: 0 });
      this.ctx.acceptWebSocket(server, ["dashboard"]);
      await this.setDashboardActivity();
      await this.ctx.storage.setAlarm(Date.now() + 30000);
      server.send(JSON.stringify({ type: "snapshot", data: await this.snapshot(), ts: Date.now() }));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/public-ws") {
      const clientIp = request.headers.get("X-KUI-CLIENT-IP") || "unknown";
      const publicSockets = this.ctx.getWebSockets("public");
      if (publicSockets.length >= MAX_PUBLIC_SOCKETS || publicSockets.filter(ws => ws.deserializeAttachment()?.clientIp === clientIp).length >= MAX_PUBLIC_SOCKETS_PER_IP) return json({ error: "Too many public connections" }, 429);
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.serializeAttachment({ public: true, clientIp, connected_at: Date.now(), lastActivity: Date.now(), lastResync: 0 });
      this.ctx.acceptWebSocket(server, ["public"]);
      await this.setDashboardActivity();
      await this.ctx.storage.setAlarm(Date.now() + 60000);
      server.send(JSON.stringify({ type: "snapshot", data: (await this.snapshot()).map(sanitizeSnapshot).filter(Boolean), ts: Date.now() }));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/public-policy" && request.method === "POST") {
      const enabled = request.headers.get("X-KUI-Public") === "1";
      if (!enabled) {
        for (const ws of this.ctx.getWebSockets("public")) {
          try { ws.close(1008, "private dashboard"); } catch {}
        }
      }
      return json({ success: true });
    }
    if (url.pathname === "/frequency-policy" && request.method === "POST") {
      const policy = validFrequencyPolicy(await request.json().catch(() => null));
      if (!policy) return json({ error: "Invalid frequency policy" }, 400);
      this.frequencyPolicy = policy;
      await this.ctx.storage.put("frequencyPolicy", { admin: policy.admin / 1000, public: policy.public / 1000, idle: policy.idle / 1000 });
      await this.setDashboardActivity();
      return json({ success: true, policy: { admin: policy.admin / 1000, public: policy.public / 1000, idle: policy.idle / 1000 } });
    }
    if (url.pathname === "/update" && request.method === "POST") {
      if (request.headers.get("X-KUI-Presence") !== "1") return json({ error: "Forbidden" }, 403);
      const snapshot = await request.json();
      if (!snapshot.ip) return json({ error: "Invalid snapshot" }, 400);
      const payload = JSON.stringify({ type: "patch", data: snapshot, ts: Date.now() });
      for (const ws of this.ctx.getWebSockets("dashboard")) {
        try { ws.send(payload); } catch {}
      }
      const publicSnapshot = sanitizeSnapshot(snapshot);
      const publicSockets = this.ctx.getWebSockets("public");
      if (publicSnapshot && publicSockets.length && await this.publicPolicyEnabled()) {
        const publicPayload = JSON.stringify({ type: "patch", data: publicSnapshot, ts: Date.now() });
        for (const ws of this.ctx.getWebSockets("public")) {
          try { ws.send(publicPayload); } catch {}
        }
      }
      return json({ success: true });
    }
    if (url.pathname === "/snapshot") return json(await this.snapshot());
    return json({ error: "Not found" }, 404);
  }

  async snapshot() {
    if (this.snapshotCache && Date.now() - this.snapshotCachedAt < SNAPSHOT_CACHE_MS) return this.snapshotCache;
    const servers = (await this.env.DB.prepare("SELECT ip, cpu, mem, disk, load, uptime, net_in_speed, net_out_speed, tcp_conn, udp_conn, last_report FROM servers").all()).results || [];
    const proxies = (await this.env.DB.prepare("SELECT ip, details, last_seen FROM proxy_ctrl_servers").all()).results || [];
    const proxyMap = new Map(proxies.map(row => [row.ip, row]));
    const snapshots = await Promise.all(servers.slice(0, 100).map(async row => {
      const { ip } = row;
      const name = await presenceName(ip, this.env);
      if (!name) return null;
      const presence = this.env.VPS_PRESENCE.get(this.env.VPS_PRESENCE.idFromName(name));
      const response = await presence.fetch(new Request("https://presence.internal/snapshot"));
      const live = response.ok ? await response.json() : null;
      if (live?.ip && (live.core || live.proxy)) return live;
      const proxy = proxyMap.get(ip);
      let details = [];
      try { details = JSON.parse(proxy?.details || "[]"); } catch {}
      return {
        ip,
        transport: "http",
        core: { cpu: row.cpu, mem: row.mem, disk: row.disk, load: row.load, uptime: row.uptime, net_in_speed: row.net_in_speed, net_out_speed: row.net_out_speed, tcp_conn: row.tcp_conn, udp_conn: row.udp_conn },
        core_last_seen: row.last_report || 0,
        core_state: Date.now() - (row.last_report || 0) < 360000 ? "online" : Date.now() - (row.last_report || 0) < 1200000 ? "stale" : "offline",
        proxy: proxy ? { details } : null,
        proxy_last_seen: proxy?.last_seen || 0,
        proxy_state: proxy && Date.now() - proxy.last_seen < 360000 ? "online" : proxy && Date.now() - proxy.last_seen < 1200000 ? "stale" : "offline",
        updated_at: Math.max(row.last_report || 0, proxy?.last_seen || 0),
      };
    }));
    this.snapshotCache = snapshots.filter(Boolean);
    this.snapshotCachedAt = Date.now();
    return this.snapshotCache;
  }

  async webSocketMessage(ws, message) {
    if (message === "ping") {
      const attachment = ws.deserializeAttachment() || {}; attachment.lastActivity = Date.now(); ws.serializeAttachment(attachment);
      ws.send("pong");
      return;
    }
    try {
      const parsed = JSON.parse(message);
      if (parsed?.type === "resync") {
        const attachment = ws.deserializeAttachment() || {};
        if (Date.now() - Number(attachment.lastResync || 0) < RESYNC_COOLDOWN_MS) return;
        attachment.lastResync = Date.now(); attachment.lastActivity = Date.now(); ws.serializeAttachment(attachment);
        const snapshots = await this.snapshot();
        const isPublic = ws.deserializeAttachment()?.public === true;
        ws.send(JSON.stringify({ type: "snapshot", data: isPublic ? snapshots.map(sanitizeSnapshot).filter(Boolean) : snapshots, ts: Date.now() }));
      }
      if (parsed?.type === "activity") {
        const attachment = ws.deserializeAttachment() || {}; attachment.lastActivity = Date.now(); ws.serializeAttachment(attachment);
        if (ws.deserializeAttachment()?.public === true) {
          const setting = await this.env.DB.prepare("SELECT value FROM probe_settings WHERE key = 'is_public'").first();
          if (setting && setting.value !== "true") {
            ws.close(1008, "private dashboard");
            return;
          }
        }
        await this.setDashboardActivity();
      }
    } catch {}
  }

  async webSocketClose() {
    await this.setDashboardActivity();
  }
  async webSocketError() {
    await this.setDashboardActivity();
  }

  viewerInterval() {
    if (this.ctx.getWebSockets("dashboard").length) return this.frequencyPolicy.admin;
    if (this.ctx.getWebSockets("public").length) return this.frequencyPolicy.public;
    return this.frequencyPolicy.idle;
  }

  async setDashboardActivity() {
    const interval = this.viewerInterval();
    const active = this.ctx.getWebSockets("dashboard").length + this.ctx.getWebSockets("public").length > 0;
    const until = active ? Date.now() + VIEWER_LEASE_MS : 0;
    if (this.activityInterval === interval && (!active || this.activityUntil - Date.now() > 60000)) return;
    this.activityUntil = until;
    this.activityInterval = interval;
    const servers = (await this.env.DB.prepare("SELECT ip FROM servers").all()).results || [];
    await Promise.all(servers.slice(0, 100).map(async ({ ip }) => {
      const name = await presenceName(ip, this.env);
      if (!name) return;
      const presence = this.env.VPS_PRESENCE.get(this.env.VPS_PRESENCE.idFromName(name));
      return presence.fetch(new Request("https://presence.internal/dashboard-active", { method: "POST", headers: { "X-KUI-Active": active ? "1" : "0", "X-KUI-Interval": String(interval), "X-KUI-Until": String(until) } }));
    }));
  }

  async publicPolicyEnabled() {
    if (Date.now() - this.publicPolicyCheckedAt < 5000) return this.publicPolicyAllowed;
    const setting = await this.env.DB.prepare("SELECT value FROM probe_settings WHERE key = 'is_public'").first();
    this.publicPolicyAllowed = !setting || setting.value === "true";
    this.publicPolicyCheckedAt = Date.now();
    if (!this.publicPolicyAllowed) {
      for (const ws of this.ctx.getWebSockets("public")) { try { ws.close(1008, "private dashboard"); } catch {} }
    }
    return this.publicPolicyAllowed;
  }

  async alarm() {
    const tickets = await this.ctx.storage.list({ prefix: "ticket:" });
    const now = Date.now();
    const expired = [];
    let next = 0;
    for (const [key, value] of tickets) {
      if (!value?.expires || value.expires <= now) expired.push(key);
      else if (!next || value.expires < next) next = value.expires;
    }
    if (expired.length) await this.ctx.storage.delete(expired);
    const hasActiveViewers = this.ctx.getWebSockets("dashboard").length + this.ctx.getWebSockets("public").length > 0;
    if (!hasActiveViewers) await this.setDashboardActivity();
    const publicSockets = this.ctx.getWebSockets("public");
    if (publicSockets.length) {
      const setting = await this.env.DB.prepare("SELECT value FROM probe_settings WHERE key = 'is_public'").first();
      if (setting && setting.value !== "true") {
        for (const ws of publicSockets) {
          try { ws.close(1008, "private dashboard"); } catch {}
        }
      } else {
        const publicCheck = Date.now() + 30000;
        if (!next || publicCheck < next) next = publicCheck;
      }
    }
    if (hasActiveViewers) { const viewerCheck = Date.now() + 30000; if (!next || viewerCheck < next) next = viewerCheck; }
    if (next) await this.ctx.storage.setAlarm(next + 5000);
  }
}
