import { onRequest, onRequestScheduled } from '../functions/api/[[path]].js';
import realtime, { DashboardHub, VpsPresence } from '../realtime/src/index.js';

export { DashboardHub, VpsPresence };

function apiParams(pathname) {
    const segments = pathname.slice('/api/'.length).split('/').filter(Boolean);
    return { path: segments };
}

function withWorkerOrigin(env, origin) {
    return Object.assign(Object.create(env), { PAGES_ORIGIN: origin, REALTIME_URL: origin });
}

function isRealtimeRoute(pathname) {
    return pathname === '/health'
        || pathname === '/agent/ws'
        || pathname === '/dashboard/ticket'
        || pathname === '/dashboard/ws'
        || pathname === '/dashboard/snapshot'
        || pathname === '/public/ws'
        || pathname === '/notify'
        || pathname === '/public-policy'
        || pathname === '/frequency-policy';
}

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const runtimeEnv = withWorkerOrigin(env, url.origin);

        if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
            return onRequest({ request, env: runtimeEnv, params: apiParams(url.pathname), waitUntil: ctx.waitUntil.bind(ctx) });
        }

        if (isRealtimeRoute(url.pathname)) {
            return realtime.fetch(request, runtimeEnv, ctx);
        }

        // Workers + Assets: 优先通过 Worker 处理，兜底检查 ASSETS 绑定
        if (!env.ASSETS || typeof env.ASSETS.fetch !== 'function') {
            return new Response(
                `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>KUI - 部署问题</title><style>body{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f8fafc;color:#1e293b;line-height:1.6}div{max-width:600px;padding:40px;text-align:center}h1{font-size:24px;color:#0f172a;margin-bottom:8px}p{color:#64748b;font-size:15px;margin:8px 0}code{background:#e2e8f0;padding:2px 6px;border-radius:4px;font-size:13px}ol{text-align:left;color:#475569;font-size:14px}li{margin:6px 0}.btn{display:inline-block;margin-top:20px;background:#3b82f6;color:#fff;padding:12px 28px;border-radius:12px;text-decoration:none;font-weight:600;font-size:14px}</style></head><body><div>
                <h1>⚙️ KUI 需要配置才能运行</h1>
                <p>一键部署后, Cloudflare 需要正确绑定以下资源：</p>
                <ol>
                    <li><strong>D1 数据库</strong> — Variable name: <code>DB</code></li>
                    <li><strong>Durable Objects</strong> — <code>VPS_PRESENCE</code> → VpsPresence, <code>DASHBOARD_HUB</code> → DashboardHub</li>
                    <li><strong>Assets 绑定</strong> — Workers + Assets 模式</li>
                </ol>
                <p>请进入 Cloudflare Dashboard → Worker → Settings → Variables, 添加缺失的绑定后重新部署。</p>
                <a class="btn" href="https://dash.cloudflare.com/?to=/:account/workers-and-pages" target="_blank">前往 Cloudflare Dashboard</a>
                <p style="margin-top:24px;font-size:12px;color:#94a3b8">详细步骤请查看项目 README → 一键部署故障排除</p>
            </div></body></html>`,
                { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
            );
        }

        try {
            return await env.ASSETS.fetch(request);
        } catch (e) {
            return new Response(
                `<html><body style="font-family:sans-serif;text-align:center;padding:40px"><h1>⛔ 服务未就绪</h1><p>${e.message}</p><p>请检查 Cloudflare Dashboard 中的绑定配置。</p></body></html>`,
                { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
            );
        }
    },

    async scheduled(controller, env, ctx) {
        return onRequestScheduled({ scheduledTime: controller.scheduledTime, cron: controller.cron, env: withWorkerOrigin(env, ''), waitUntil: ctx.waitUntil.bind(ctx) });
    },
};
