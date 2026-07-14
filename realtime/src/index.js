import { DurableObject } from "cloudflare:workers";

// Viewers receive five-second updates. Connected agents slow routine status
// snapshots only while no dashboard or public probe WebSocket is open.
const ACTIVE_STATUS_INTERVAL = 5_000;
const IDLE_STATUS_INTERVAL = 30_000;
const STATUS_STALE_AFTER = 20_000;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extraHeaders },
  });
}

function cors(request, env) {
  const requested = request.headers.get("Origin") || "";
  const allowed = env.PAGES_ORIGIN || "https://k-ui2.pages.dev";
  const origin = requested === allowed ? allowed : "null";
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
  return { details: Array.isArray(data?.details) ? data.details.slice(0, 4).map(item => ({ tunnel: item.tunnel, active: item.active, node_ip: item.node_ip, exit_ip: item.exit_ip, country: item.country, ready: item.ready })) : [] };
}

async function verifyAdmin(header, env) {
  try {
    if (!header || !env.PAGES_ORIGIN) return false;
    const response = await fetch(`${env.PAGES_ORIGIN.replace(/\/$/, "")}/api/realtime_auth`, {
      method: "POST",
      headers: { Authorization: header, "Content-Type": "application/json" },
      body: "{}",
    });
    if (!response.ok) return false;
    return (await response.json()).admin === true;
  } catch {
    return false;
  }
}

async function verifyAgent(header, ip, env) {
  if (!header || !ip) return false;
  const server = await env.DB.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
  return !!server?.agent_token && header === server.agent_token;
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
      const stub = env.VPS_PRESENCE.get(env.VPS_PRESENCE.idFromName(ip));
      return stub.fetch(doRequest("/ws", request, { "X-KUI-IP": ip, "X-KUI-ROLE": role }));
    }

    if (url.pathname === "/dashboard/ticket" && request.method === "POST") {
      if (!(await verifyAdmin(request.headers.get("Authorization"), env))) return json({ error: "Forbidden" }, 403, cors(request, env));
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      const response = await hub.fetch(new Request("https://hub.internal/ticket", { method: "POST", headers: { "X-KUI-USER": "admin" } }));
      return new Response(response.body, { status: response.status, headers: { ...Object.fromEntries(response.headers), ...cors(request, env) } });
    }

    if (url.pathname === "/dashboard/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "WebSocket required" }, 426);
      if (request.headers.get("Origin") !== (env.PAGES_ORIGIN || "https://k-ui2.pages.dev")) return json({ error: "Forbidden origin" }, 403);
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      return hub.fetch(doRequest(`/ws?ticket=${encodeURIComponent(url.searchParams.get("ticket") || "")}`, request));
    }

    if (url.pathname === "/public/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "WebSocket required" }, 426);
      if (request.headers.get("Origin") !== (env.PAGES_ORIGIN || "https://k-ui2.pages.dev")) return json({ error: "Forbidden origin" }, 403);
      const setting = await env.DB.prepare("SELECT value FROM probe_settings WHERE key = 'is_public'").first();
      if (setting && setting.value !== "true") return json({ error: "Private dashboard" }, 403);
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      return hub.fetch(doRequest("/public-ws", request));
    }

    if (url.pathname === "/dashboard/snapshot") {
      if (!(await verifyAdmin(request.headers.get("Authorization"), env))) return json({ error: "Forbidden" }, 403, cors(request, env));
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      const response = await hub.fetch(new Request("https://hub.internal/snapshot"));
      return new Response(response.body, { status: response.status, headers: { ...Object.fromEntries(response.headers), ...cors(request, env) } });
    }

    if (url.pathname === "/notify" && request.method === "POST") {
      if (!(await verifyAdmin(request.headers.get("Authorization"), env))) return json({ error: "Forbidden" }, 403, cors(request, env));
      const body = await request.json().catch(() => ({}));
      const ips = body.ip ? [body.ip] : (await env.DB.prepare("SELECT ip FROM servers").all()).results.map(row => row.ip);
      await Promise.all(ips.slice(0, 100).map(ip => {
        const stub = env.VPS_PRESENCE.get(env.VPS_PRESENCE.idFromName(ip));
        return stub.fetch(new Request("https://presence.internal/notify", { method: "POST" }));
      }));
      return json({ success: true, notified: ips.length }, 200, cors(request, env));
    }

    if (url.pathname === "/public-policy" && request.method === "POST") {
      if (!(await verifyAdmin(request.headers.get("Authorization"), env))) return json({ error: "Forbidden" }, 403, cors(request, env));
      const body = await request.json().catch(() => ({}));
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      const response = await hub.fetch(new Request("https://hub.internal/public-policy", { method: "POST", headers: { "X-KUI-Public": body.public === true ? "1" : "0" } }));
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
        this.setDashboardActivity(active?.active === true, Number(active?.until) || Date.now() + 300000);
      } catch {}
      this.snapshot.ip = ip;
      this.snapshot[`${role}_connected`] = true;
      this.snapshot[`${role}_connected_at`] = Date.now();
      await this.broadcast();
      server.send(JSON.stringify({ type: "hello.ok", ts: Date.now(), role }));
      server.send(JSON.stringify({ type: "status.interval", seconds: this.dashboardActive ? 5 : 30 }));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/notify") {
      for (const ws of this.ctx.getWebSockets()) {
        try { ws.send(JSON.stringify({ type: "config.refresh", ts: Date.now() })); } catch {}
      }
      return json({ success: true });
    }
    if (url.pathname === "/dashboard-active" && request.method === "POST") {
      this.setDashboardActivity(request.headers.get("X-KUI-Active") === "1", Number(request.headers.get("X-KUI-Until")) || Date.now() + 300000);
      return json({ success: true });
    }
    if (url.pathname === "/snapshot") return json(this.publicSnapshot());
    return json({ error: "Not found" }, 404);
  }

  async webSocketMessage(ws, message) {
    if (typeof message !== "string" || message.length > 1024 * 1024) return;
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
      this.snapshot[`${role}_config_result`] = envelope.data || {};
      this.snapshot[`${role}_config_result_at`] = Date.now();
      ws.serializeAttachment(attachment);
      await this.persistAndBroadcast();
      return;
    }
    if (messageType !== "status") return;
    const previousRoleState = this.snapshot[role];
    const nextRoleState = envelope.data || {};
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
    const statusBroadcastDue = this.dashboardActive && role === "core" && Date.now() - this.lastStatusBroadcast >= ACTIVE_STATUS_INTERVAL;
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

  setDashboardActivity(active, until) {
    const changed = this.dashboardActive !== active;
    this.dashboardActive = active;
    this.dashboardActiveUntil = until;
    if (!changed) return;
    this.lastStatusBroadcast = 0;
    const interval = active ? ACTIVE_STATUS_INTERVAL : IDLE_STATUS_INTERVAL;
    for (const ws of this.ctx.getWebSockets()) {
      try { ws.send(JSON.stringify({ type: "status.interval", seconds: interval / 1000 })); } catch {}
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
    if (Date.now() >= this.dashboardActiveUntil) {
      try {
        const response = await hub.fetch(new Request("https://hub.internal/active"));
        const active = response.ok ? await response.json() : null;
        this.setDashboardActivity(active?.active === true, Number(active?.until) || Date.now() + 300000);
      } catch {
        this.dashboardActive = false;
        this.dashboardActiveUntil = Date.now() + 300000;
        return;
      }
    }
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
    this.publicPolicyAllowed = false;
    this.publicPolicyCheckedAt = 0;
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
      const active = this.ctx.getWebSockets("dashboard").length + this.ctx.getWebSockets("public").length > 0;
      return json({ active, until: active ? Date.now() + 300000 : 0 });
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
      server.serializeAttachment({ user: record.user, connected_at: Date.now() });
      this.ctx.acceptWebSocket(server, ["dashboard"]);
      await this.setDashboardActivity(true);
      server.send(JSON.stringify({ type: "snapshot", data: await this.snapshot(), ts: Date.now() }));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/public-ws") {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.serializeAttachment({ public: true, connected_at: Date.now() });
      this.ctx.acceptWebSocket(server, ["public"]);
      await this.setDashboardActivity(true);
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
    const servers = (await this.env.DB.prepare("SELECT ip, cpu, mem, disk, load, uptime, net_in_speed, net_out_speed, tcp_conn, udp_conn, last_report FROM servers").all()).results || [];
    const proxies = (await this.env.DB.prepare("SELECT ip, details, last_seen FROM proxy_ctrl_servers").all()).results || [];
    const proxyMap = new Map(proxies.map(row => [row.ip, row]));
    const snapshots = await Promise.all(servers.slice(0, 100).map(async row => {
      const { ip } = row;
      const presence = this.env.VPS_PRESENCE.get(this.env.VPS_PRESENCE.idFromName(ip));
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
    return snapshots.filter(Boolean);
  }

  async webSocketMessage(ws, message) {
    if (message === "ping") {
      ws.send("pong");
      return;
    }
    try {
      const parsed = JSON.parse(message);
      if (parsed?.type === "resync") {
        const snapshots = await this.snapshot();
        const isPublic = ws.deserializeAttachment()?.public === true;
        ws.send(JSON.stringify({ type: "snapshot", data: isPublic ? snapshots.map(sanitizeSnapshot).filter(Boolean) : snapshots, ts: Date.now() }));
      }
      if (parsed?.type === "activity") {
        if (ws.deserializeAttachment()?.public === true) {
          const setting = await this.env.DB.prepare("SELECT value FROM probe_settings WHERE key = 'is_public'").first();
          if (setting && setting.value !== "true") {
            ws.close(1008, "private dashboard");
            return;
          }
        }
        await this.setDashboardActivity(true);
      }
    } catch {}
  }

  async webSocketClose() {
    if (this.ctx.getWebSockets("dashboard").length + this.ctx.getWebSockets("public").length === 0) await this.setDashboardActivity(false);
  }
  async webSocketError() {
    if (this.ctx.getWebSockets("dashboard").length + this.ctx.getWebSockets("public").length === 0) await this.setDashboardActivity(false);
  }

  async setDashboardActivity(active) {
    const until = active ? Date.now() + 300000 : 0;
    if (active && this.activityUntil - Date.now() > 60000) return;
    this.activityUntil = until;
    const servers = (await this.env.DB.prepare("SELECT ip FROM servers").all()).results || [];
    await Promise.all(servers.slice(0, 100).map(({ ip }) => {
      const presence = this.env.VPS_PRESENCE.get(this.env.VPS_PRESENCE.idFromName(ip));
      return presence.fetch(new Request("https://presence.internal/dashboard-active", { method: "POST", headers: { "X-KUI-Active": active ? "1" : "0", "X-KUI-Until": String(until) } }));
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
    const publicSockets = this.ctx.getWebSockets("public");
    if (publicSockets.length) {
      const setting = await this.env.DB.prepare("SELECT value FROM probe_settings WHERE key = 'is_public'").first();
      if (setting && setting.value !== "true") {
        for (const ws of publicSockets) {
          try { ws.close(1008, "private dashboard"); } catch {}
        }
      } else {
        const publicCheck = Date.now() + 60000;
        if (!next || publicCheck < next) next = publicCheck;
      }
    }
    if (next) await this.ctx.storage.setAlarm(next + 5000);
  }
}
