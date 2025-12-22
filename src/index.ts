import { escapeHtml, renderLayout, type LayoutUser } from "./renderHtml";

// 缓存日历图标 SVG，避免重复生成
const CALENDAR_ICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>';

function renderDateInput(name: string, value?: string | null, required = false): string {
  const escapedName = escapeHtml(name);
  const valueAttr = value ? ` value="${escapeHtml(value)}"` : "";
  const requiredAttr = required ? " required" : "";
  // 日期輸入框：點擊輸入框本身就會開啟日期選擇器（由 renderHtml.ts 中的 JavaScript 處理）
  return `<div class="date-input-wrapper"><input name="${escapedName}" type="date"${valueAttr}${requiredAttr} /><button type="button" class="date-icon-btn" aria-label="選擇日期" tabindex="-1">${CALENDAR_ICON_SVG}</button></div>`;
}

const SESSION_COOKIE_NAME = "__Host-teamadmin_session";
const SESSION_TTL_DAYS = 30;
const PBKDF2_ITERATIONS = 100_000; // Cloudflare Workers Web Crypto API limit is 100,000

type AuthedSession = {
  sessionId: string;
  csrfToken: string;
  user: LayoutUser;
};

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function nowMs() {
  return Date.now();
}

function redirect(location: string, status = 302): Response {
  return new Response(null, { status, headers: { location } });
}

function htmlResponse(html: string, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("content-type", "text/html; charset=utf-8");
  if (!headers.has("cache-control")) headers.set("cache-control", "no-store");
  return new Response(html, { ...init, headers });
}

function setCookieHeader(name: string, value: string, options: { maxAgeSeconds: number } | { expireNow: true }) {
  if ("expireNow" in options) {
    return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
  }
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${options.maxAgeSeconds}`;
}

function parseCookies(cookieHeader: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const [rawName, ...rest] = part.trim().split("=");
    if (!rawName) continue;
    out[rawName] = rest.join("=");
  }
  return out;
}

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function isEmail(email: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function base64UrlFromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll(/=+$/g, "");
}

function bytesFromBase64Url(input: string): Uint8Array {
  const padded = input.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((input.length + 3) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}

async function pbkdf2Hash(password: string, saltB64Url: string): Promise<string> {
  const enc = new TextEncoder();
  const salt = bytesFromBase64Url(saltB64Url);
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return base64UrlFromBytes(new Uint8Array(bits));
}

function generateRandomPassword(length: number = 16): string {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset[randomValues[i] % charset.length];
  }
  return password;
}

async function hashPasswordNewSalt(password: string): Promise<{ salt: string; hash: string }> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = base64UrlFromBytes(saltBytes);
  const hash = await pbkdf2Hash(password, salt);
  return { salt, hash };
}

async function verifyPassword(password: string, salt: string, expectedHash: string): Promise<boolean> {
  const actual = await pbkdf2Hash(password, salt);
  return timingSafeEqual(actual, expectedHash);
}

async function countUsers(env: Env): Promise<number> {
  try {
    const row = (await env.DB.prepare("SELECT COUNT(*) as c FROM users").first()) as { c?: number } | null;
    return Number(row?.c ?? 0);
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    if (errMsg.includes('no such table') || errMsg.includes('does not exist') || errMsg.includes('no table named')) {
      throw new HttpError(
        500,
        "資料庫尚未初始化（缺少 tables）。請先執行 `wrangler d1 migrations apply DB --local/--remote` 再重試。"
      );
    }
    throw new HttpError(500, `資料庫查詢錯誤：${errMsg}`);
  }
}

async function getSession(env: Env, request: Request): Promise<AuthedSession | null> {
  const cookies = parseCookies(request.headers.get("cookie"));
  const sid = cookies[SESSION_COOKIE_NAME];
  if (!sid) return null;

  const row = (await env.DB.prepare(
    `SELECT
      s.id as session_id,
      s.csrf_token as csrf_token,
      s.expires_at as expires_at,
      u.id as user_id,
      u.email as email,
      u.display_name as display_name,
      u.role as role,
      u.is_active as is_active,
      u.must_change_password as must_change_password
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = ?
     LIMIT 1`
  )
    .bind(sid)
    .first()) as
    | {
        session_id: string;
        csrf_token: string;
        expires_at: number;
        user_id: string;
        email: string;
        display_name: string;
        role: "admin" | "member";
        is_active: number;
        must_change_password: number;
      }
    | null;

  if (!row) return null;
  if (!row.is_active) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sid).run();
    return null;
  }
  if (Number(row.expires_at) <= nowMs()) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sid).run();
    return null;
  }

  const ts = nowMs();
  await env.DB.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").bind(ts, sid).run();

  return {
    sessionId: row.session_id,
    csrfToken: row.csrf_token,
    user: {
      id: row.user_id,
      email: row.email,
      displayName: row.display_name,
      role: row.role,
    },
  };
}

async function createSession(env: Env, userId: string): Promise<{ sessionId: string; csrfToken: string }> {
  const sessionId = crypto.randomUUID();
  const csrfToken = base64UrlFromBytes(crypto.getRandomValues(new Uint8Array(32)));
  const ts = nowMs();
  const expiresAt = ts + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;
  try {
    await env.DB.prepare(
      "INSERT INTO sessions (id, user_id, csrf_token, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
      .bind(sessionId, userId, csrfToken, ts, ts, expiresAt)
      .run();
  } catch (dbErr) {
    throw new HttpError(500, `建立 session 失敗：${dbErr instanceof Error ? dbErr.message : String(dbErr)}`);
  }
  return { sessionId, csrfToken };
}

async function deleteSession(env: Env, sessionId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
}

function requireAuth(session: AuthedSession | null): asserts session is AuthedSession {
  if (!session) throw new HttpError(401, "請先登入");
}

function requireAdmin(session: AuthedSession): void {
  if (session.user.role !== "admin") throw new HttpError(403, "需要管理員權限");
}

async function readForm(request: Request): Promise<FormData> {
  const ct = request.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    const data = (await request.json()) as Record<string, unknown>;
    const fd = new FormData();
    for (const [k, v] of Object.entries(data)) fd.set(k, typeof v === "string" ? v : JSON.stringify(v));
    return fd;
  }
  return await request.formData();
}

function getString(form: FormData, key: string): string {
  const v = form.get(key);
  if (typeof v === "string") return v.trim();
  return "";
}

function assertCsrf(form: FormData, session: AuthedSession) {
  const token = getString(form, "csrf");
  if (!token || token !== session.csrfToken) throw new HttpError(403, "CSRF token 無效，請重新整理再試一次");
}

async function postDiscord(env: Env, content: string): Promise<void> {
  const anyEnv = env as unknown as { DISCORD_WEBHOOK_URL?: string };
  const webhook = anyEnv.DISCORD_WEBHOOK_URL?.trim();
  if (!webhook) return;
  try {
    await fetch(webhook, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ content }),
    });
  } catch {
    // Ignore webhook errors
  }
}

// 狀態和身份的中文映射
function translateRole(role: string): string {
  const roleMap: Record<string, string> = {
    admin: "管理員",
    member: "成員",
  };
  return roleMap[role.toLowerCase()] || role;
}

function translateUserStatus(isActive: number | boolean): string {
  return isActive ? "啟用" : "停用";
}

function translateEventStatus(status: string): string {
  const statusMap: Record<string, string> = {
    planned: "計劃中",
    active: "進行中",
    completed: "已完成",
    cancelled: "已取消",
  };
  return statusMap[status.toLowerCase()] || status;
}

function translateTaskStatus(status: string): string {
  const statusMap: Record<string, string> = {
    todo: "待辦",
    in_progress: "進行中",
    done: "已完成",
    blocked: "受阻",
  };
  return statusMap[status.toLowerCase()] || status;
}

function translateGoalStatus(status: string): string {
  const statusMap: Record<string, string> = {
    open: "開啟",
    on_track: "正常",
    at_risk: "有風險",
    achieved: "已達成",
    dropped: "已放棄",
  };
  return statusMap[status.toLowerCase()] || status;
}

function translateParticipantRole(role: string): string {
  const roleMap: Record<string, string> = {
    participant: "參與者",
    owner: "擁有者",
  };
  return roleMap[role.toLowerCase()] || role;
}

function translateEntityType(type: string): string {
  const typeMap: Record<string, string> = {
    event: "活動",
    task: "任務",
    goal: "目標",
  };
  return typeMap[type.toLowerCase()] || type;
}

function translateStatus(status: string, type?: "event" | "task" | "goal"): string {
  if (type === "event") return translateEventStatus(status);
  if (type === "task") return translateTaskStatus(status);
  if (type === "goal") return translateGoalStatus(status);
  // 自動判斷類型
  if (["planned", "active", "completed", "cancelled"].includes(status.toLowerCase())) {
    return translateEventStatus(status);
  }
  if (["todo", "in_progress", "done", "blocked"].includes(status.toLowerCase())) {
    return translateTaskStatus(status);
  }
  if (["open", "on_track", "at_risk", "achieved", "dropped"].includes(status.toLowerCase())) {
    return translateGoalStatus(status);
  }
  return status;
}

function pillForStatus(status: string) {
  const s = status.toLowerCase();
  if (["done", "completed", "achieved"].includes(s)) return "pill pill--green";
  if (["in_progress", "active", "on_track"].includes(s)) return "pill pill--purple";
  if (["blocked", "at_risk", "planned"].includes(s)) return "pill pill--yellow";
  if (["cancelled", "dropped"].includes(s)) return "pill pill--red";
  return "pill";
}

function formatDate(input?: string | null) {
  if (!input) return "";
  try {
    const d = new Date(input);
    if (Number.isNaN(d.getTime())) return input;
    return d.toLocaleString("zh-TW", { hour12: false });
  } catch {
    return input;
  }
}

function safeFileName(name: string) {
  const trimmed = name.trim().replaceAll("\u0000", "");
  return trimmed.replaceAll(/[^\p{L}\p{N}\-_. ()[\]]/gu, "_").slice(0, 180) || "upload";
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    try {
      // Bootstrap: allow /setup only if no users exist
      if (pathname === "/setup" && request.method === "GET") {
        const existing = await countUsers(env);
        if (existing > 0) return redirect("/login");
        return htmlResponse(
          renderLayout({
            title: "初始化管理員",
            body: renderSetupForm(),
          })
        );
      }

      if (pathname === "/setup" && request.method === "POST") {
        const existing = await countUsers(env);
        if (existing > 0) return redirect("/login");

        const form = await readForm(request);
        const email = normalizeEmail(getString(form, "email"));
        const displayName = getString(form, "display_name") || "Admin";
        const password = getString(form, "password");
        const password2 = getString(form, "password_confirm");

        if (!isEmail(email)) throw new HttpError(400, "Email 格式不正確");
        if (password.length < 8) throw new HttpError(400, "密碼至少 8 碼");
        if (password !== password2) throw new HttpError(400, "兩次輸入的密碼不一致");

        const { salt, hash } = await hashPasswordNewSalt(password);
        const userId = crypto.randomUUID();
        const ts = nowMs();
        try {
          await env.DB.prepare(
            `INSERT INTO users (id, email, password_hash, password_salt, role, display_name, created_at)
             VALUES (?, ?, ?, ?, 'admin', ?, ?)`
          )
            .bind(userId, email, hash, salt, displayName, ts)
            .run();
        } catch (dbErr) {
          const errMsg = dbErr instanceof Error ? dbErr.message : String(dbErr);
          if (errMsg.includes('no such table') || errMsg.includes('does not exist')) {
            throw new HttpError(500, "資料庫尚未初始化（缺少 tables）。請先執行 `wrangler d1 migrations apply DB --remote` 再重試。");
          }
          throw new HttpError(500, `資料庫錯誤：${errMsg}`);
        }

        const { sessionId, csrfToken } = await createSession(env, userId);
        const headers = new Headers();
        headers.append("set-cookie", setCookieHeader(SESSION_COOKIE_NAME, sessionId, { maxAgeSeconds: 60 * 60 * 24 * SESSION_TTL_DAYS }));
        headers.set("location", "/app");
        return new Response(null, { status: 302, headers });
      }

      // Login
      if (pathname === "/login" && request.method === "GET") {
        const session = await getSession(env, request);
        if (session) return redirect("/app");
        return htmlResponse(
          renderLayout({
            title: "登入",
            body: renderLoginForm(),
          })
        );
      }

      if (pathname === "/login" && request.method === "POST") {
        const form = await readForm(request);
        const email = normalizeEmail(getString(form, "email"));
        const password = getString(form, "password");
        if (!isEmail(email) || !password) {
          return htmlResponse(
            renderLayout({
              title: "登入",
              body: renderLoginForm({ email, error: "請輸入正確的 Email 和密碼" }),
              flash: { type: "error", message: "登入失敗" },
            }),
            { status: 400 }
          );
        }

        const row = (await env.DB.prepare(
          `SELECT id, email, password_hash, password_salt, role, display_name, is_active, must_change_password
           FROM users
           WHERE email = ?
           LIMIT 1`
        )
          .bind(email)
          .first()) as
          | {
              id: string;
              email: string;
              password_hash: string;
              password_salt: string;
              role: "admin" | "member";
              display_name: string;
              is_active: number;
              must_change_password: number;
            }
          | null;

        if (!row || !row.is_active) {
          return htmlResponse(
            renderLayout({
              title: "登入",
              body: renderLoginForm({ email, error: "帳號或密碼不正確" }),
              flash: { type: "error", message: "帳號或密碼不正確" },
            }),
            { status: 401 }
          );
        }

        const ok = await verifyPassword(password, row.password_salt, row.password_hash);
        if (!ok) {
          return htmlResponse(
            renderLayout({
              title: "登入",
              body: renderLoginForm({ email, error: "帳號或密碼不正確" }),
              flash: { type: "error", message: "帳號或密碼不正確" },
            }),
            { status: 401 }
          );
        }

        const { sessionId, csrfToken } = await createSession(env, row.id);
        const headers = new Headers();
        headers.append("set-cookie", setCookieHeader(SESSION_COOKIE_NAME, sessionId, { maxAgeSeconds: 60 * 60 * 24 * SESSION_TTL_DAYS }));
        
        // 如果用户需要更改密码，重定向到强制更改密码页面
        if (row.must_change_password) {
          headers.set("location", "/change-password-required");
        } else {
          headers.set("location", "/app");
        }
        return new Response(null, { status: 302, headers });
      }

      // Root
      if (pathname === "/" && request.method === "GET") {
        const existing = await countUsers(env);
        if (existing === 0) return redirect("/setup");
        const session = await getSession(env, request);
        return redirect(session ? "/app" : "/login");
      }

      const session = await getSession(env, request);

      // Logout
      if (pathname === "/logout" && request.method === "POST") {
        if (session) {
          const form = await readForm(request);
          assertCsrf(form, session);
          await deleteSession(env, session.sessionId);
        }
        const headers = new Headers();
        headers.append("set-cookie", setCookieHeader(SESSION_COOKIE_NAME, "", { expireNow: true }));
        headers.set("location", "/login");
        return new Response(null, { status: 302, headers });
      }

      // Protected routes below
      requireAuth(session);

      // 强制更改密码页面（如果用户需要更改密码，必须访问此页面）
      if (pathname === "/change-password-required" && request.method === "GET") {
        // 检查用户是否需要更改密码
        const userRow = (await env.DB.prepare(
          "SELECT must_change_password FROM users WHERE id = ? LIMIT 1"
        )
          .bind(session.user.id)
          .first()) as { must_change_password: number } | null;
        
        if (!userRow || !userRow.must_change_password) {
          return redirect("/app");
        }

        return htmlResponse(
          renderLayout({
            title: "必須更改密碼",
            user: session.user,
            csrfToken: session.csrfToken,
            body: renderChangePasswordRequiredForm({ csrfToken: session.csrfToken }),
          })
        );
      }

      if (pathname === "/change-password-required" && request.method === "POST") {
        const form = await readForm(request);
        assertCsrf(form, session);
        const password = getString(form, "password");
        const password2 = getString(form, "password_confirm");
        
        if (password.length < 8) throw new HttpError(400, "密碼至少 8 碼");
        if (password !== password2) throw new HttpError(400, "兩次輸入的密碼不一致");

        const { salt, hash } = await hashPasswordNewSalt(password);
        // 更新密码并清除 must_change_password 标记
        await env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ?, must_change_password = 0 WHERE id = ?")
          .bind(hash, salt, session.user.id)
          .run();

        return redirect("/app");
      }

      // 如果用户需要更改密码，除了更改密码页面外，重定向到更改密码页面
      const userRow = (await env.DB.prepare(
        "SELECT must_change_password FROM users WHERE id = ? LIMIT 1"
      )
        .bind(session.user.id)
        .first()) as { must_change_password: number } | null;
      
      if (userRow && userRow.must_change_password && pathname !== "/change-password-required" && pathname !== "/logout") {
        return redirect("/change-password-required");
      }

      if (pathname === "/app" && request.method === "GET") {
        const events = (await env.DB.prepare(
          "SELECT id, title, status, start_date, end_date, updated_at FROM events ORDER BY updated_at DESC LIMIT 10"
        ).all()) as { results: Array<{ id: string; title: string; status: string; start_date: string | null; end_date: string | null; updated_at: number }> };

        const membersRow = (await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE is_active = 1").first()) as { c?: number } | null;
        const membersCount = Number(membersRow?.c ?? 0);

        // 查询所有任务用于看板视图
        const allTasks = (await env.DB.prepare(
          `SELECT t.id, t.title, t.description, t.status, t.due_date, t.assignee_user_id, t.event_id,
                  u.display_name as assignee_name, u.id as assignee_id,
                  e.title as event_title, e.id as event_id
           FROM tasks t
           LEFT JOIN users u ON u.id = t.assignee_user_id
           LEFT JOIN events e ON e.id = t.event_id
           ORDER BY t.updated_at DESC`
        ).all()) as {
          results: Array<{
            id: string;
            title: string;
            description: string | null;
            status: string;
            due_date: string | null;
            assignee_user_id: string | null;
            assignee_name: string | null;
            assignee_id: string | null;
            event_id: string;
            event_title: string;
          }>;
        };

        // 查询所有成员用于看板
        const allMembers = (await env.DB.prepare(
          "SELECT id, display_name, email FROM users WHERE is_active = 1 ORDER BY display_name ASC"
        ).all()) as {
          results: Array<{ id: string; display_name: string; email: string }>;
        };

        return htmlResponse(
          renderLayout({
            title: "儀表板",
            user: session.user,
            csrfToken: session.csrfToken,
            body: renderDashboard({ 
              user: session.user, 
              membersCount, 
              events: events.results,
              tasks: allTasks.results,
              members: allMembers.results,
              csrfToken: session.csrfToken
            }),
          })
        );
      }

      if (pathname === "/profile" && request.method === "GET") {
        return redirect(`/members/${session.user.id}`);
      }

      // Members (admin)
      if (pathname === "/members" && request.method === "GET") {
        requireAdmin(session);
        const res = (await env.DB.prepare(
          "SELECT id, email, role, display_name, is_active, created_at FROM users ORDER BY created_at DESC"
        ).all()) as {
          results: Array<{ id: string; email: string; role: "admin" | "member"; display_name: string; is_active: number; created_at: number }>;
        };
        return htmlResponse(
          renderLayout({
            title: "成員",
            user: session.user,
            csrfToken: session.csrfToken,
            body: renderMembersList({ users: res.results, csrfToken: session.csrfToken, currentUserId: session.user.id }),
          })
        );
      }

      if (pathname === "/members/new" && request.method === "GET") {
        requireAdmin(session);
        return htmlResponse(
          renderLayout({
            title: "新增成員",
            user: session.user,
            csrfToken: session.csrfToken,
            body: renderMemberCreateForm({ csrfToken: session.csrfToken }),
          })
        );
      }

      if (pathname === "/members" && request.method === "POST") {
        requireAdmin(session);
        const form = await readForm(request);
        assertCsrf(form, session);
        const email = normalizeEmail(getString(form, "email"));
        const displayName = getString(form, "display_name") || email;
        const role = (getString(form, "role") === "admin" ? "admin" : "member") as "admin" | "member";
        let password = getString(form, "password");
        
        // 如果密码为空或未提供，自动生成随机密码
        const useRandomPassword = !password || password.length === 0;
        if (useRandomPassword) {
          password = generateRandomPassword(16);
        }
        
        if (!isEmail(email)) throw new HttpError(400, "Email 格式不正確");
        if (password.length < 8) throw new HttpError(400, "密碼至少 8 碼");

        const existing = (await env.DB.prepare("SELECT id FROM users WHERE email = ? LIMIT 1").bind(email).first()) as
          | { id: string }
          | null;
        if (existing) throw new HttpError(409, "此 Email 已存在");

        const { salt, hash } = await hashPasswordNewSalt(password);
        const userId = crypto.randomUUID();
        const ts = nowMs();
        // 如果使用随机密码，设置 must_change_password = 1
        const mustChangePassword = useRandomPassword ? 1 : 0;
        await env.DB.prepare(
          `INSERT INTO users (id, email, password_hash, password_salt, role, display_name, created_at, must_change_password)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(userId, email, hash, salt, role, displayName, ts, mustChangePassword)
          .run();

        // 如果使用随机密码，显示生成的密码给管理员
        if (useRandomPassword) {
          return htmlResponse(
            renderLayout({
              title: "成員已建立",
              user: session.user,
              csrfToken: session.csrfToken,
              body: renderMemberCreatedSuccess({ email, displayName, generatedPassword: password }),
            })
          );
        }

        return redirect("/members");
      }

      // Member profile view/edit (self or admin)
      {
        const match = new URLPattern({ pathname: "/members/:id" }).exec(url);
        if (match && request.method === "GET") {
          const memberId = match.pathname.groups.id;
          if (session.user.role !== "admin" && session.user.id !== memberId) throw new HttpError(403, "沒有權限");

          const row = (await env.DB.prepare(
            "SELECT id, email, role, display_name, bio, discord_handle, is_active, created_at FROM users WHERE id = ? LIMIT 1"
          )
            .bind(memberId)
            .first()) as
            | {
                id: string;
                email: string;
                role: "admin" | "member";
                display_name: string;
                bio: string | null;
                discord_handle: string | null;
                is_active: number;
                created_at: number;
              }
            | null;
          if (!row) throw new HttpError(404, "找不到成員");

          return htmlResponse(
            renderLayout({
              title: "成員資料",
              user: session.user,
              csrfToken: session.csrfToken,
              body: renderMemberDetail({
                viewer: session.user,
                member: row,
                csrfToken: session.csrfToken,
              }),
            })
          );
        }

        if (match && request.method === "POST") {
          const memberId = match.pathname.groups.id;
          if (session.user.role !== "admin" && session.user.id !== memberId) throw new HttpError(403, "沒有權限");
          const form = await readForm(request);
          assertCsrf(form, session);
          const action = getString(form, "action");

          if (action === "profile") {
            const displayName = getString(form, "display_name");
            const bio = getString(form, "bio");
            const discord = getString(form, "discord_handle");
            if (!displayName) throw new HttpError(400, "顯示名稱不可為空");
            await env.DB.prepare("UPDATE users SET display_name = ?, bio = ?, discord_handle = ? WHERE id = ?")
              .bind(displayName, bio || null, discord || null, memberId)
              .run();
            return redirect(`/members/${memberId}`);
          }

          if (action === "password") {
            if (session.user.role !== "admin" && session.user.id !== memberId) throw new HttpError(403, "沒有權限");
            const password = getString(form, "password");
            const password2 = getString(form, "password_confirm");
            if (password.length < 8) throw new HttpError(400, "密碼至少 8 碼");
            if (password !== password2) throw new HttpError(400, "兩次輸入的密碼不一致");
            const { salt, hash } = await hashPasswordNewSalt(password);
            // 更改密码后，清除 must_change_password 标记
            await env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ?, must_change_password = 0 WHERE id = ?")
              .bind(hash, salt, memberId)
              .run();
            
            // 如果用户更改了自己的密码，重定向到首页
            if (session.user.id === memberId) {
              return redirect("/app");
            }
            return redirect(`/members/${memberId}`);
          }

          if (action === "admin_update") {
            requireAdmin(session);
            const role = (getString(form, "role") === "admin" ? "admin" : "member") as "admin" | "member";
            const isActive = getString(form, "is_active") === "1" ? 1 : 0;
            await env.DB.prepare("UPDATE users SET role = ?, is_active = ? WHERE id = ?")
              .bind(role, isActive, memberId)
              .run();
            return redirect(`/members/${memberId}`);
          }

          if (action === "delete") {
            const isSelf = session.user.id === memberId;
            const isAdmin = session.user.role === "admin";

            // 权限检查：管理员不能删除自己，成员只能删除自己
            if (isAdmin && isSelf) {
              throw new HttpError(400, "管理員不能移除自己");
            }
            if (!isAdmin && !isSelf) {
              throw new HttpError(403, "沒有權限刪除此成員");
            }

            // 获取要删除的成员信息
            const memberRow = (await env.DB.prepare("SELECT role FROM users WHERE id = ? LIMIT 1")
              .bind(memberId)
              .first()) as { role: "admin" | "member" } | null;
            if (!memberRow) throw new HttpError(404, "找不到成員");

            // 如果要删除的是管理员，检查是否是最后一个管理员
            if (memberRow.role === "admin") {
              const adminCount = (await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin' AND is_active = 1")
                .first()) as { c?: number } | null;
              const count = Number(adminCount?.c ?? 0);
              if (count <= 1) {
                throw new HttpError(400, "無法刪除最後一個管理員");
              }
            }

            // 删除该用户的所有 sessions
            await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(memberId).run();

            // 将用户标记为 inactive（软删除）
            await env.DB.prepare("UPDATE users SET is_active = 0 WHERE id = ?").bind(memberId).run();

            // 如果用户自己删除，登出并重定向到登录页面
            if (isSelf) {
              await deleteSession(env, session.sessionId);
              const headers = new Headers();
              headers.append("set-cookie", setCookieHeader(SESSION_COOKIE_NAME, "", { expireNow: true }));
              headers.set("location", "/login");
              return new Response(null, { status: 302, headers });
            }

            // 管理员删除其他成员，重定向到成员列表
            return redirect("/members");
          }

          throw new HttpError(400, "未知操作");
        }
      }

      // Events
      if (pathname === "/events" && request.method === "GET") {
        const res = (await env.DB.prepare(
          "SELECT id, title, status, start_date, end_date, updated_at FROM events ORDER BY updated_at DESC LIMIT 100"
        ).all()) as {
          results: Array<{ id: string; title: string; status: string; start_date: string | null; end_date: string | null; updated_at: number }>;
        };
        return htmlResponse(
          renderLayout({
            title: "活動",
            user: session.user,
            csrfToken: session.csrfToken,
            body: renderEventsList({ events: res.results, csrfToken: session.csrfToken }),
          })
        );
      }

      if (pathname === "/events/new" && request.method === "GET") {
        return htmlResponse(
          renderLayout({
            title: "建立活動",
            user: session.user,
            csrfToken: session.csrfToken,
            body: renderEventCreateForm({ csrfToken: session.csrfToken }),
          })
        );
      }

      if (pathname === "/events" && request.method === "POST") {
        const form = await readForm(request);
        assertCsrf(form, session);
        const title = getString(form, "title");
        const description = getString(form, "description");
        const startDate = getString(form, "start_date");
        const endDate = getString(form, "end_date");
        if (!title) throw new HttpError(400, "活動名稱不可為空");

        const eventId = crypto.randomUUID();
        const ts = nowMs();
        await env.DB.prepare(
          `INSERT INTO events (id, title, description, start_date, end_date, status, created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 'planned', ?, ?, ?)`
        )
          .bind(eventId, title, description || null, startDate || null, endDate || null, session.user.id, ts, ts)
          .run();

        // Creator becomes owner participant
        await env.DB.prepare(
          "INSERT OR IGNORE INTO event_participants (event_id, user_id, participant_role, created_at) VALUES (?, ?, 'owner', ?)"
        )
          .bind(eventId, session.user.id, ts)
          .run();

        ctx.waitUntil(postDiscord(env, `📅 新活動建立：**${title}**（建立者：${session.user.displayName}）`));
        return redirect(`/events/${eventId}`);
      }

      // Event detail & nested actions
      {
        const match = new URLPattern({ pathname: "/events/:id" }).exec(url);
        if (match && request.method === "GET") {
          const eventId = match.pathname.groups.id;
          const event = (await env.DB.prepare(
            "SELECT id, title, description, start_date, end_date, status, created_by, created_at, updated_at FROM events WHERE id = ? LIMIT 1"
          )
            .bind(eventId)
            .first()) as
            | {
                id: string;
                title: string;
                description: string | null;
                start_date: string | null;
                end_date: string | null;
                status: string;
                created_by: string;
                created_at: number;
                updated_at: number;
              }
            | null;
          if (!event) throw new HttpError(404, "找不到活動");

          const participants = (await env.DB.prepare(
            `SELECT u.id, u.display_name, u.email, u.role, ep.participant_role
             FROM event_participants ep
             JOIN users u ON u.id = ep.user_id
             WHERE ep.event_id = ?
             ORDER BY ep.created_at ASC`
          )
            .bind(eventId)
            .all()) as {
            results: Array<{
              id: string;
              display_name: string;
              email: string;
              role: "admin" | "member";
              participant_role: string;
            }>;
          };

          const tasks = (await env.DB.prepare(
            `SELECT t.id, t.title, t.description, t.status, t.due_date, t.assignee_user_id,
                    u.display_name as assignee_name
             FROM tasks t
             LEFT JOIN users u ON u.id = t.assignee_user_id
             WHERE t.event_id = ?
             ORDER BY t.updated_at DESC`
          )
            .bind(eventId)
            .all()) as {
            results: Array<{
              id: string;
              title: string;
              description: string | null;
              status: string;
              due_date: string | null;
              assignee_user_id: string | null;
              assignee_name: string | null;
            }>;
          };

          const goals = (await env.DB.prepare(
            `SELECT id, title, description, status, due_date
             FROM goals
             WHERE event_id = ?
             ORDER BY updated_at DESC`
          )
            .bind(eventId)
            .all()) as {
            results: Array<{ id: string; title: string; description: string | null; status: string; due_date: string | null }>;
          };

          const progress = (await env.DB.prepare(
            `SELECT pu.id, pu.entity_type, pu.entity_id, pu.progress_percent, pu.note, pu.created_at,
                    u.display_name as author_name
             FROM progress_updates pu
             JOIN users u ON u.id = pu.created_by
             WHERE pu.event_id = ?
             ORDER BY pu.created_at DESC
             LIMIT 50`
          )
            .bind(eventId)
            .all()) as {
            results: Array<{
              id: string;
              entity_type: string;
              entity_id: string;
              progress_percent: number | null;
              note: string;
              created_at: number;
              author_name: string;
            }>;
          };

          const docs = (await env.DB.prepare(
            `SELECT d.id, d.file_name, d.content_type, d.size_bytes, d.created_at, u.display_name as uploader_name
             FROM documents d
             JOIN users u ON u.id = d.uploaded_by
             WHERE d.event_id = ?
             ORDER BY d.created_at DESC`
          )
            .bind(eventId)
            .all()) as {
            results: Array<{
              id: string;
              file_name: string;
              content_type: string;
              size_bytes: number;
              created_at: number;
              uploader_name: string;
            }>;
          };

          const usersRes = session.user.role === "admin"
            ? ((await env.DB.prepare("SELECT id, display_name, email FROM users WHERE is_active = 1 ORDER BY display_name ASC").all()) as {
                results: Array<{ id: string; display_name: string; email: string }>;
              })
            : { results: [] as Array<{ id: string; display_name: string; email: string }> };

          return htmlResponse(
            renderLayout({
              title: event.title,
              user: session.user,
              csrfToken: session.csrfToken,
              body: renderEventDetail({
                viewer: session.user,
                csrfToken: session.csrfToken,
                event,
                participants: participants.results,
                tasks: tasks.results,
                goals: goals.results,
                progress: progress.results,
                docs: docs.results,
                allUsers: usersRes.results,
              }),
            })
          );
        }
      }

      // Event updates
      {
        const match = new URLPattern({ pathname: "/events/:id/update" }).exec(url);
        if (match && request.method === "POST") {
          const eventId = match.pathname.groups.id;
          const form = await readForm(request);
          assertCsrf(form, session);
          const title = getString(form, "title");
          const description = getString(form, "description");
          const startDate = getString(form, "start_date");
          const endDate = getString(form, "end_date");
          const status = getString(form, "status") || "planned";
          if (!title) throw new HttpError(400, "活動名稱不可為空");
          const ts = nowMs();
          await env.DB.prepare(
            "UPDATE events SET title = ?, description = ?, start_date = ?, end_date = ?, status = ?, updated_at = ? WHERE id = ?"
          )
            .bind(title, description || null, startDate || null, endDate || null, status, ts, eventId)
            .run();
          return redirect(`/events/${eventId}`);
        }
      }

      // Event participants add/remove (admin)
      {
        const addMatch = new URLPattern({ pathname: "/events/:id/participants/add" }).exec(url);
        if (addMatch && request.method === "POST") {
          requireAdmin(session);
          const eventId = addMatch.pathname.groups.id;
          const form = await readForm(request);
          assertCsrf(form, session);
          const userId = getString(form, "user_id");
          if (!userId) throw new HttpError(400, "請選擇成員");
          const ts = nowMs();
          await env.DB.prepare(
            "INSERT OR IGNORE INTO event_participants (event_id, user_id, participant_role, created_at) VALUES (?, ?, 'participant', ?)"
          )
            .bind(eventId, userId, ts)
            .run();
          return redirect(`/events/${eventId}`);
        }

        const rmMatch = new URLPattern({ pathname: "/events/:id/participants/remove" }).exec(url);
        if (rmMatch && request.method === "POST") {
          requireAdmin(session);
          const eventId = rmMatch.pathname.groups.id;
          const form = await readForm(request);
          assertCsrf(form, session);
          const userId = getString(form, "user_id");
          if (!userId) throw new HttpError(400, "缺少 user_id");
          await env.DB.prepare("DELETE FROM event_participants WHERE event_id = ? AND user_id = ?").bind(eventId, userId).run();
          return redirect(`/events/${eventId}`);
        }
      }

      // Tasks
      if (pathname === "/tasks/create" && request.method === "POST") {
        const form = await readForm(request);
        assertCsrf(form, session);
        const eventId = getString(form, "event_id");
        const title = getString(form, "title");
        const description = getString(form, "description");
        const dueDate = getString(form, "due_date");
        const assignee = getString(form, "assignee_user_id");
        if (!eventId) throw new HttpError(400, "缺少 event_id");
        if (!title) throw new HttpError(400, "任務名稱不可為空");
        const taskId = crypto.randomUUID();
        const ts = nowMs();
        await env.DB.prepare(
          `INSERT INTO tasks (id, event_id, title, description, status, due_date, assignee_user_id, created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'todo', ?, ?, ?, ?, ?)`
        )
          .bind(taskId, eventId, title, description || null, dueDate || null, assignee || null, session.user.id, ts, ts)
          .run();

        if (assignee) {
          const who = (await env.DB.prepare("SELECT display_name FROM users WHERE id = ? LIMIT 1").bind(assignee).first()) as
            | { display_name: string }
            | null;
          ctx.waitUntil(
            postDiscord(env, `✅ 任務指派：**${title}** → **${who?.display_name ?? "（未知）"}**（指派者：${session.user.displayName}）`)
          );
        }
        return redirect(`/events/${eventId}`);
      }

      {
        const match = new URLPattern({ pathname: "/tasks/:id/update" }).exec(url);
        if (match && request.method === "POST") {
          const taskId = match.pathname.groups.id;
          const form = await readForm(request);
          assertCsrf(form, session);
          const eventId = getString(form, "event_id");
          const status = getString(form, "status");
          const assignee = getString(form, "assignee_user_id");
          const title = getString(form, "title");
          const description = getString(form, "description");
          const dueDate = getString(form, "due_date");
          if (!eventId) throw new HttpError(400, "缺少 event_id");
          const ts = nowMs();
          await env.DB.prepare(
            "UPDATE tasks SET title = ?, description = ?, status = ?, due_date = ?, assignee_user_id = ?, updated_at = ? WHERE id = ?"
          )
            .bind(title, description || null, status || "todo", dueDate || null, assignee || null, ts, taskId)
            .run();
          return redirect(`/events/${eventId}`);
        }
      }

      // Goals
      if (pathname === "/goals/create" && request.method === "POST") {
        const form = await readForm(request);
        assertCsrf(form, session);
        const eventId = getString(form, "event_id");
        const title = getString(form, "title");
        const description = getString(form, "description");
        const dueDate = getString(form, "due_date");
        if (!eventId) throw new HttpError(400, "缺少 event_id");
        if (!title) throw new HttpError(400, "目標名稱不可為空");
        const goalId = crypto.randomUUID();
        const ts = nowMs();
        await env.DB.prepare(
          `INSERT INTO goals (id, event_id, title, description, status, due_date, created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)`
        )
          .bind(goalId, eventId, title, description || null, dueDate || null, session.user.id, ts, ts)
          .run();
        return redirect(`/events/${eventId}`);
      }

      {
        const match = new URLPattern({ pathname: "/goals/:id/update" }).exec(url);
        if (match && request.method === "POST") {
          const goalId = match.pathname.groups.id;
          const form = await readForm(request);
          assertCsrf(form, session);
          const eventId = getString(form, "event_id");
          const title = getString(form, "title");
          const description = getString(form, "description");
          const status = getString(form, "status");
          const dueDate = getString(form, "due_date");
          if (!eventId) throw new HttpError(400, "缺少 event_id");
          if (!title) throw new HttpError(400, "目標名稱不可為空");
          const ts = nowMs();
          await env.DB.prepare("UPDATE goals SET title = ?, description = ?, status = ?, due_date = ?, updated_at = ? WHERE id = ?")
            .bind(title, description || null, status || "open", dueDate || null, ts, goalId)
            .run();
          return redirect(`/events/${eventId}`);
        }
      }

      // Progress update
      if (pathname === "/progress/create" && request.method === "POST") {
        const form = await readForm(request);
        assertCsrf(form, session);
        const eventId = getString(form, "event_id");
        const entityType = getString(form, "entity_type") || "event";
        const entityId = getString(form, "entity_id") || eventId;
        const percentRaw = getString(form, "progress_percent");
        const note = getString(form, "note");
        if (!eventId) throw new HttpError(400, "缺少 event_id");
        if (!note) throw new HttpError(400, "請輸入進度說明");
        const pct = percentRaw ? Math.max(0, Math.min(100, Number(percentRaw))) : null;
        const id = crypto.randomUUID();
        const ts = nowMs();
        await env.DB.prepare(
          `INSERT INTO progress_updates (id, event_id, entity_type, entity_id, progress_percent, note, created_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(id, eventId, entityType, entityId, pct, note, session.user.id, ts)
          .run();

        ctx.waitUntil(
          postDiscord(env, `📝 進度更新（${entityType}）：${note}${pct === null ? "" : `（${pct}%）`} — ${session.user.displayName}`)
        );
        return redirect(`/events/${eventId}`);
      }

      // Document upload (R2)
      if (pathname === "/docs/upload" && request.method === "POST") {
        const form = await readForm(request);
        assertCsrf(form, session);
        const eventId = getString(form, "event_id");
        const file = form.get("file");
        if (!eventId) throw new HttpError(400, "缺少 event_id");
        if (!(file instanceof File)) throw new HttpError(400, "請選擇檔案");

        const anyEnv = env as unknown as { DOCS_BUCKET?: R2Bucket };
        if (!anyEnv.DOCS_BUCKET) throw new HttpError(500, "尚未設定 R2（DOCS_BUCKET），無法上傳文件");

        const fileName = safeFileName(file.name);
        const key = `${eventId}/${crypto.randomUUID()}-${fileName}`;
        const buf = await file.arrayBuffer();
        await anyEnv.DOCS_BUCKET.put(key, buf, { httpMetadata: { contentType: file.type || "application/octet-stream" } });

        const docId = crypto.randomUUID();
        const ts = nowMs();
        await env.DB.prepare(
          `INSERT INTO documents (id, event_id, uploaded_by, file_name, content_type, size_bytes, r2_key, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(docId, eventId, session.user.id, fileName, file.type || "application/octet-stream", file.size, key, ts)
          .run();
        return redirect(`/events/${eventId}`);
      }

      {
        const match = new URLPattern({ pathname: "/docs/:id" }).exec(url);
        if (match && request.method === "GET") {
          const docId = match.pathname.groups.id;
          const row = (await env.DB.prepare(
            "SELECT id, event_id, file_name, content_type, r2_key FROM documents WHERE id = ? LIMIT 1"
          )
            .bind(docId)
            .first()) as { id: string; event_id: string | null; file_name: string; content_type: string; r2_key: string } | null;
          if (!row) throw new HttpError(404, "找不到文件");
          const anyEnv = env as unknown as { DOCS_BUCKET?: R2Bucket };
          if (!anyEnv.DOCS_BUCKET) throw new HttpError(500, "尚未設定 R2（DOCS_BUCKET），無法下載文件");
          const obj = await anyEnv.DOCS_BUCKET.get(row.r2_key);
          if (!obj) throw new HttpError(404, "文件不存在（R2）");
          const headers = new Headers();
          headers.set("content-type", row.content_type || "application/octet-stream");
          headers.set("content-disposition", `attachment; filename="${encodeURIComponent(row.file_name)}"`);
          return new Response(obj.body, { headers });
        }
      }

      // 404
      throw new HttpError(404, "找不到頁面");
    } catch (err) {
      if (err instanceof HttpError) {
        let session: AuthedSession | null = null;
        try {
          session = await getSession(env, request);
        } catch {
          // Ignore session errors in error handler
        }
        const body = `
          <h1>${escapeHtml(String(err.status))}</h1>
          <div class="card">
            <div class="muted">${escapeHtml(err.message)}</div>
            <div style="margin-top: 12px" class="row">
              <a class="btn btn--primary" href="/">回首頁</a>
              <a class="btn" href="javascript:history.back()">返回</a>
            </div>
          </div>
        `;
        return htmlResponse(
          renderLayout({
            title: `錯誤 ${err.status}`,
            user: session?.user,
            csrfToken: session?.csrfToken,
            body,
            flash: err.status >= 500 ? { type: "error", message: "伺服器錯誤" } : undefined,
          }),
          { status: err.status }
        );
      }
      return htmlResponse(
        renderLayout({
          title: "伺服器錯誤",
          body: `
            <h1>500</h1>
            <div class="card">
              <div class="muted">發生未預期錯誤</div>
              <div style="margin-top: 12px"><a class="btn btn--primary" href="/">回首頁</a></div>
            </div>
          `,
        }),
        { status: 500 }
      );
    }
  },
} satisfies ExportedHandler<Env>;

function renderLoginForm(opts?: { email?: string; error?: string }) {
  return `
    <h1>登入</h1>
    <div class="card">
      <div class="muted" style="margin-bottom: 10px;">使用帳號密碼登入後即可進入團隊管理工具。</div>
      ${opts?.error ? `<div class="flash flash--error">${escapeHtml(opts.error)}</div>` : ""}
      <form class="form" method="post" action="/login">
        <div>
          <label>Email</label>
          <input name="email" type="email" autocomplete="email" value="${escapeHtml(opts?.email ?? "")}" required />
        </div>
        <div>
          <label>密碼</label>
          <input name="password" type="password" autocomplete="current-password" required />
        </div>
        <div class="form__actions">
          <button class="btn btn--primary" type="submit">登入</button>
        </div>
      </form>
      <div class="muted" style="margin-top: 10px;">
        如果這是新部署，請先到 <a class="btn btn--small" href="/setup">/setup</a> 初始化管理員。
      </div>
    </div>
  `;
}

function renderSetupForm() {
  return `
    <h1>初始化管理員</h1>
    <div class="card">
      <div class="muted" style="margin-bottom: 10px;">第一次使用請建立管理員帳號（只允許在尚未有任何使用者時執行）。</div>
      <form class="form" method="post" action="/setup">
        <div>
          <label>Email</label>
          <input name="email" type="email" autocomplete="email" required />
        </div>
        <div>
          <label>顯示名稱</label>
          <input name="display_name" type="text" autocomplete="name" placeholder="例如：Long" required />
        </div>
        <div class="grid grid--2">
          <div>
            <label>密碼（至少 8 碼）</label>
            <input name="password" type="password" autocomplete="new-password" required />
          </div>
          <div>
            <label>確認密碼</label>
            <input name="password_confirm" type="password" autocomplete="new-password" required />
          </div>
        </div>
        <div class="form__actions">
          <button class="btn btn--primary" type="submit">建立管理員並登入</button>
        </div>
      </form>
    </div>
  `;
}

function renderDashboard(args: {
  user: LayoutUser;
  membersCount: number;
  events: Array<{ id: string; title: string; status: string; start_date: string | null; end_date: string | null; updated_at: number }>;
  tasks: Array<{
    id: string;
    title: string;
    description: string | null;
    status: string;
    due_date: string | null;
    assignee_user_id: string | null;
    assignee_name: string | null;
    assignee_id: string | null;
    event_id: string;
    event_title: string;
  }>;
  members: Array<{ id: string; display_name: string; email: string }>;
  csrfToken: string;
}) {
  const { user, membersCount, events, tasks, members, csrfToken } = args;
  const eventsHtml =
    events.length === 0
      ? `<div class="muted">目前尚無活動。</div>`
      : `<table>
          <thead><tr><th>活動</th><th>狀態</th><th>日期</th><th>更新</th></tr></thead>
          <tbody>
            ${events
              .map(
                (e) => `
                  <tr>
                    <td><a href="/events/${escapeHtml(e.id)}"><strong>${escapeHtml(e.title)}</strong></a></td>
                    <td><span class="${pillForStatus(e.status)}">${escapeHtml(translateEventStatus(e.status))}</span></td>
                    <td class="muted">${escapeHtml([e.start_date, e.end_date].filter(Boolean).join(" → "))}</td>
                    <td class="muted">${escapeHtml(new Date(e.updated_at).toLocaleString("zh-TW", { hour12: false }))}</td>
                  </tr>
                `
              )
              .join("")}
          </tbody>
        </table>`;

  return `
    <h1>嗨，${escapeHtml(user.displayName)}</h1>
    <div class="card">${eventsHtml}</div>
    <div class="grid grid--2">
      <div class="card">
        <div class="card__title">快速開始</div>
        <div class="row">
          <a class="btn btn--primary" href="/events/new">建立活動</a>
          <a class="btn" href="/events">查看活動</a>
          ${user.role === "admin" ? `<a class="btn" href="/members">管理成員</a>` : ""}
        </div>
      </div>
      <div class="card">
        <div class="card__title">團隊概況</div>
        <div class="row">
          <span class="pill pill--purple">啟用成員：${membersCount}</span>
          <span class="pill">你的角色：${escapeHtml(translateRole(user.role))}</span>
        </div>
      </div>
    </div>
    <h2>任務看板</h2>
    ${renderKanbanBoard({ tasks, members, user, csrfToken })}
    <h2>最近活動</h2>
  `;
}

function renderMembersList(args: {
  users: Array<{ id: string; email: string; role: "admin" | "member"; display_name: string; is_active: number; created_at: number }>;
  csrfToken: string;
  currentUserId: string;
}) {
  const rows = args.users
    .map((u) => {
      const status = u.is_active ? `<span class="pill pill--green">${escapeHtml(translateUserStatus(u.is_active))}</span>` : `<span class="pill pill--red">${escapeHtml(translateUserStatus(u.is_active))}</span>`;
      // 管理员不能删除自己
      const isCurrentUser = u.id === args.currentUserId;
      const deleteBtn = isCurrentUser && u.role === "admin"
        ? `<span class="muted">—</span>`
        : `
          <form method="post" action="/members/${escapeHtml(u.id)}" style="margin:0; display:inline;" onsubmit="return confirm('確定要移除此成員嗎？此操作無法復原。');">
            <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
            <input type="hidden" name="action" value="delete" />
            <button class="btn btn--small btn--danger" type="submit">移除</button>
          </form>
        `;
      return `
        <tr>
          <td><a href="/members/${escapeHtml(u.id)}"><strong>${escapeHtml(u.display_name)}</strong></a></td>
          <td class="muted">${escapeHtml(u.email)}</td>
          <td><span class="${pillForStatus(u.role)}">${escapeHtml(translateRole(u.role))}</span></td>
          <td>${status}</td>
          <td class="muted">${escapeHtml(new Date(u.created_at).toLocaleString("zh-TW", { hour12: false }))}</td>
          <td>${deleteBtn}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <div class="row">
      <h1 style="margin: 0;">成員</h1>
      <div class="spacer"></div>
      <a class="btn btn--primary" href="/members/new">新增成員</a>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>名稱</th><th>Email</th><th>角色</th><th>狀態</th><th>建立時間</th><th>操作</th></tr></thead>
        <tbody>${rows || ""}</tbody>
      </table>
      ${rows ? "" : `<div class="muted" style="margin-top: 10px;">尚無成員。</div>`}
    </div>
  `;
}

function renderMemberCreateForm(args: { csrfToken: string }) {
  return `
    <div class="row">
      <h1 style="margin: 0;">新增成員</h1>
      <div class="spacer"></div>
      <a class="btn" href="/members">返回</a>
    </div>
    <div class="card">
      <form class="form" method="post" action="/members" id="member-create-form">
        <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
        <div class="grid grid--2">
          <div>
            <label>Email</label>
            <input name="email" type="email" autocomplete="email" required />
          </div>
          <div>
            <label>顯示名稱</label>
            <input name="display_name" type="text" autocomplete="name" required />
          </div>
        </div>
        <div class="grid grid--2">
          <div>
            <label>角色</label>
            <select name="role">
              <option value="member">${escapeHtml(translateRole("member"))}</option>
              <option value="admin">${escapeHtml(translateRole("admin"))}</option>
            </select>
          </div>
          <div>
            <label>初始密碼（至少 8 碼，留空則自動生成）</label>
            <div class="row">
              <input name="password" type="password" autocomplete="new-password" id="password-input" style="flex: 1;" />
              <button type="button" class="btn btn--small" onclick="generateRandomPassword()">生成隨機密碼</button>
            </div>
            <div class="muted" style="margin-top: 6px; font-size: 0.9em;">
              留空密碼欄位將自動生成隨機密碼，成員首次登入時需更改密碼。
            </div>
          </div>
        </div>
        <div class="form__actions">
          <button class="btn btn--primary" type="submit">建立</button>
        </div>
      </form>
    </div>
    <script>
      function generateRandomPassword() {
        const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let password = "";
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        for (let i = 0; i < 16; i++) {
          password += charset[array[i] % charset.length];
        }
        document.getElementById("password-input").value = password;
        document.getElementById("password-input").type = "text";
        setTimeout(() => {
          document.getElementById("password-input").type = "password";
        }, 2000);
      }
    </script>
  `;
}

function renderMemberCreatedSuccess(args: { email: string; displayName: string; generatedPassword: string }) {
  return `
    <div class="row">
      <h1 style="margin: 0;">成員已建立</h1>
      <div class="spacer"></div>
      <a class="btn" href="/members">返回成員列表</a>
    </div>
    <div class="card">
      <div class="flash flash--success" style="margin-bottom: 20px;">
        成員已成功建立！已自動生成隨機密碼，成員首次登入時需更改密碼。
      </div>
      <div>
        <h3>成員資訊</h3>
        <div class="muted" style="margin-top: 10px;">
          <div><strong>Email：</strong>${escapeHtml(args.email)}</div>
          <div style="margin-top: 8px;"><strong>顯示名稱：</strong>${escapeHtml(args.displayName)}</div>
          <div style="margin-top: 16px; padding: 12px; background: rgba(255,255,255,0.05); border-radius: 4px;">
            <div><strong>生成的密碼：</strong></div>
            <code style="display: block; margin-top: 8px; padding: 8px; background: rgba(0,0,0,0.3); border-radius: 4px; font-size: 1.1em; letter-spacing: 1px;">${escapeHtml(args.generatedPassword)}</code>
            <div class="muted" style="margin-top: 8px; font-size: 0.9em;">
              ⚠️ 請妥善保管此密碼並告知成員。此密碼僅顯示一次，無法再次查看。
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderChangePasswordRequiredForm(args: { csrfToken: string }) {
  return `
    <h1>必須更改密碼</h1>
    <div class="card">
      <div class="flash flash--warning" style="margin-bottom: 20px;">
        這是您首次登入，為了安全起見，請立即更改您的密碼。
      </div>
      <form class="form" method="post" action="/change-password-required">
        <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
        <div class="grid grid--2">
          <div>
            <label>新密碼（至少 8 碼）</label>
            <input name="password" type="password" autocomplete="new-password" required />
          </div>
          <div>
            <label>確認新密碼</label>
            <input name="password_confirm" type="password" autocomplete="new-password" required />
          </div>
        </div>
        <div class="form__actions">
          <button class="btn btn--primary" type="submit">更改密碼</button>
        </div>
      </form>
    </div>
  `;
}

function renderMemberDetail(args: {
  viewer: LayoutUser;
  member: {
    id: string;
    email: string;
    role: "admin" | "member";
    display_name: string;
    bio: string | null;
    discord_handle: string | null;
    is_active: number;
    created_at: number;
  };
  csrfToken: string;
}) {
  const { viewer, member, csrfToken } = args;
  const canAdmin = viewer.role === "admin";
  const isSelf = viewer.id === member.id;
  return `
    <div class="row">
      <h1 style="margin: 0;">成員資料</h1>
      <div class="spacer"></div>
      ${canAdmin ? `<a class="btn" href="/members">返回成員列表</a>` : `<a class="btn" href="/app">返回</a>`}
    </div>

    <div class="grid grid--2">
      <div class="card">
        <div class="card__title">基本資料</div>
        <div class="muted">Email：<code class="inline">${escapeHtml(member.email)}</code></div>
        <div class="muted">角色：<span class="${pillForStatus(member.role)}">${escapeHtml(translateRole(member.role))}</span></div>
        <div class="muted">狀態：${member.is_active ? `<span class="pill pill--green">${escapeHtml(translateUserStatus(member.is_active))}</span>` : `<span class="pill pill--red">${escapeHtml(translateUserStatus(member.is_active))}</span>`}</div>
        <div class="muted">建立：${escapeHtml(new Date(member.created_at).toLocaleString("zh-TW", { hour12: false }))}</div>
      </div>

      <div class="card">
        <div class="card__title">編輯個人資料</div>
        <form class="form" method="post" action="/members/${escapeHtml(member.id)}">
          <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}" />
          <input type="hidden" name="action" value="profile" />
          <div>
            <label>顯示名稱</label>
            <input name="display_name" type="text" value="${escapeHtml(member.display_name)}" required />
          </div>
          <div>
            <label>Discord（可選）</label>
            <input name="discord_handle" type="text" value="${escapeHtml(member.discord_handle ?? "")}" placeholder="例如：name#1234 或 @name" />
          </div>
          <div>
            <label>自我介紹（可選）</label>
            <textarea name="bio" placeholder="寫點簡短的介紹...">${escapeHtml(member.bio ?? "")}</textarea>
          </div>
          <div class="form__actions">
            <button class="btn btn--primary" type="submit">儲存</button>
          </div>
        </form>
      </div>
    </div>

    <h2>密碼</h2>
    <div class="card">
      <form class="form" method="post" action="/members/${escapeHtml(member.id)}">
        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}" />
        <input type="hidden" name="action" value="password" />
        <div class="grid grid--2">
          <div>
            <label>新密碼</label>
            <input name="password" type="password" autocomplete="new-password" required />
          </div>
          <div>
            <label>確認新密碼</label>
            <input name="password_confirm" type="password" autocomplete="new-password" required />
          </div>
        </div>
        <div class="form__actions">
          <button class="btn btn--primary" type="submit">${canAdmin && !isSelf ? "重設密碼" : "變更密碼"}</button>
        </div>
      </form>
    </div>

    ${
      canAdmin
        ? `
          <h2>管理員設定</h2>
          <div class="card">
            <form class="form" method="post" action="/members/${escapeHtml(member.id)}">
              <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}" />
              <input type="hidden" name="action" value="admin_update" />
              <div class="grid grid--2">
                <div>
                  <label>角色</label>
                  <select name="role">
                    <option value="member" ${member.role === "member" ? "selected" : ""}>${escapeHtml(translateRole("member"))}</option>
                    <option value="admin" ${member.role === "admin" ? "selected" : ""}>${escapeHtml(translateRole("admin"))}</option>
                  </select>
                </div>
                <div>
                  <label>狀態</label>
                  <select name="is_active">
                    <option value="1" ${member.is_active ? "selected" : ""}>${escapeHtml(translateUserStatus(1))}</option>
                    <option value="0" ${!member.is_active ? "selected" : ""}>${escapeHtml(translateUserStatus(0))}</option>
                  </select>
                </div>
              </div>
              <div class="form__actions">
                <button class="btn btn--primary" type="submit">更新</button>
              </div>
            </form>
          </div>
        `
        : ""
    }

    ${
      // 管理员不能删除自己，只有普通成员可以删除自己，或者管理员可以删除其他成员
      !(canAdmin && isSelf) && (isSelf || canAdmin)
        ? `
          <h2>危險操作</h2>
          <div class="card">
            <div class="muted" style="margin-bottom: 10px;">
              ${isSelf ? "移除自己的帳號後，您將被登出並無法再登入此帳號。" : canAdmin ? "移除此成員後，該成員將無法再登入系統。" : ""}
            </div>
            <form method="post" action="/members/${escapeHtml(member.id)}" onsubmit="return confirm('確定要移除此成員嗎？此操作無法復原。');">
              <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}" />
              <input type="hidden" name="action" value="delete" />
              <button class="btn btn--danger" type="submit">${isSelf ? "移除我的帳號" : "移除成員"}</button>
            </form>
          </div>
        `
        : canAdmin && isSelf
        ? `
          <h2>危險操作</h2>
          <div class="card">
            <div class="muted">管理員不能移除自己的帳號。如需移除，請先將其他成員設為管理員，或由其他管理員執行移除操作。</div>
          </div>
        `
        : ""
    }
  `;
}

function renderEventsList(args: {
  events: Array<{ id: string; title: string; status: string; start_date: string | null; end_date: string | null; updated_at: number }>;
  csrfToken: string;
}) {
  const rows = args.events
    .map((e) => {
      return `
        <tr>
          <td><a href="/events/${escapeHtml(e.id)}"><strong>${escapeHtml(e.title)}</strong></a></td>
          <td><span class="${pillForStatus(e.status)}">${escapeHtml(e.status)}</span></td>
          <td class="muted">${escapeHtml([e.start_date, e.end_date].filter(Boolean).join(" → "))}</td>
          <td class="muted">${escapeHtml(new Date(e.updated_at).toLocaleString("zh-TW", { hour12: false }))}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <div class="row">
      <h1 style="margin: 0;">活動</h1>
      <div class="spacer"></div>
      <a class="btn btn--primary" href="/events/new">建立活動</a>
    </div>
    <div class="card" style="margin-top: 30px;">
      <table>
        <thead><tr><th>活動</th><th>狀態</th><th>日期</th><th>更新</th></tr></thead>
        <tbody>${rows || ""}</tbody>
      </table>
      ${rows ? "" : `<div class="muted" style="margin-top: 10px;">尚無活動。</div>`}
    </div>
  `;
}

function renderEventCreateForm(args: { csrfToken: string }) {
  return `
    <div class="row">
      <h1 style="margin: 0;">建立活動</h1>
      <div class="spacer"></div>
      <a class="btn" href="/events">返回</a>
    </div>
    <div class="card">
      <form class="form" method="post" action="/events">
        <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
        <div>
          <label>活動名稱</label>
          <input name="title" type="text" required />
        </div>
        <div>
          <label>描述（可選）</label>
          <textarea name="description" placeholder="這個活動要做什麼？"></textarea>
        </div>
        <div class="grid grid--2">
          <div>
            <label>開始日期（可選）</label>
            ${renderDateInput("start_date")}
          </div>
          <div>
            <label>結束日期（可選）</label>
            ${renderDateInput("end_date")}
          </div>
        </div>
        <div class="form__actions">
          <button class="btn btn--primary" type="submit">建立</button>
        </div>
      </form>
    </div>
  `;
}

function renderEventDetail(args: {
  viewer: LayoutUser;
  csrfToken: string;
  event: {
    id: string;
    title: string;
    description: string | null;
    start_date: string | null;
    end_date: string | null;
    status: string;
    created_by: string;
    created_at: number;
    updated_at: number;
  };
  participants: Array<{ id: string; display_name: string; email: string; role: "admin" | "member"; participant_role: string }>;
  tasks: Array<{ id: string; title: string; description: string | null; status: string; due_date: string | null; assignee_user_id: string | null; assignee_name: string | null }>;
  goals: Array<{ id: string; title: string; description: string | null; status: string; due_date: string | null }>;
  progress: Array<{ id: string; entity_type: string; entity_id: string; progress_percent: number | null; note: string; created_at: number; author_name: string }>;
  docs: Array<{ id: string; file_name: string; content_type: string; size_bytes: number; created_at: number; uploader_name: string }>;
  allUsers: Array<{ id: string; display_name: string; email: string }>;
}) {
  const { viewer, csrfToken, event, participants, tasks, goals, progress, docs, allUsers } = args;
  const dateRange = [event.start_date, event.end_date].filter(Boolean).join(" → ");

  const participantsHtml =
    participants.length === 0
      ? `<div class="muted">尚未加入參與者。</div>`
      : `<table>
          <thead><tr><th>成員</th><th>Email</th><th>身份</th><th>操作</th></tr></thead>
          <tbody>
            ${participants
              .map((p) => {
                const removeBtn =
                  viewer.role === "admin"
                    ? `
                      <form method="post" action="/events/${escapeHtml(event.id)}/participants/remove" style="margin:0;">
                        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}" />
                        <input type="hidden" name="user_id" value="${escapeHtml(p.id)}" />
                        <button class="btn btn--small btn--danger" type="submit">移除</button>
                      </form>`
                    : "";
                return `
                  <tr>
                    <td><strong>${escapeHtml(p.display_name)}</strong> <span class="muted">(${escapeHtml(translateParticipantRole(p.participant_role))})</span></td>
                    <td class="muted">${escapeHtml(p.email)}</td>
                    <td><span class="${pillForStatus(p.role)}">${escapeHtml(translateRole(p.role))}</span></td>
                    <td>${removeBtn}</td>
                  </tr>
                `;
              })
              .join("")}
          </tbody>
        </table>`;

  const addParticipantForm =
    viewer.role === "admin"
      ? `
        <form class="form" method="post" action="/events/${escapeHtml(event.id)}/participants/add">
          <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}" />
          <div class="row">
            <div style="flex:1; min-width: 260px;">
              <label>新增參與者</label>
              <select name="user_id" required>
                <option value="">選擇成員...</option>
                ${allUsers
                  .map((u) => `<option value="${escapeHtml(u.id)}">${escapeHtml(u.display_name)} (${escapeHtml(u.email)})</option>`)
                  .join("")}
              </select>
            </div>
            <div style="align-self:flex-end;">
              <button class="btn btn--primary" type="submit">加入</button>
            </div>
          </div>
        </form>
      `
      : "";

  const tasksHtml =
    tasks.length === 0
      ? `<div class="muted">尚無任務。</div>`
      : `<table>
          <thead><tr><th>任務</th><th>狀態</th><th>負責人</th><th>期限</th></tr></thead>
          <tbody>
            ${tasks
              .map(
                (t) => `
                  <tr>
                    <td>
                      <strong>${escapeHtml(t.title)}</strong>
                      ${t.description ? `<div class="muted" style="margin-top:6px;">${escapeHtml(t.description)}</div>` : ""}
                      <details style="margin-top:8px;">
                        <summary class="muted">編輯</summary>
                        ${renderTaskEditForm({ task: t, eventId: event.id, csrfToken, allUsers, isAdmin: viewer.role === "admin" })}
                      </details>
                    </td>
                    <td><span class="${pillForStatus(t.status)}">${escapeHtml(translateTaskStatus(t.status))}</span></td>
                    <td class="muted">${escapeHtml(t.assignee_name ?? "—")}</td>
                    <td class="muted">${escapeHtml(t.due_date ?? "—")}</td>
                  </tr>
                `
              )
              .join("")}
          </tbody>
        </table>`;

  const goalsHtml =
    goals.length === 0
      ? `<div class="muted">尚無目標。</div>`
      : `<table>
          <thead><tr><th>目標</th><th>狀態</th><th>期限</th></tr></thead>
          <tbody>
            ${goals
              .map(
                (g) => `
                  <tr>
                    <td>
                      <strong>${escapeHtml(g.title)}</strong>
                      ${g.description ? `<div class="muted" style="margin-top:6px;">${escapeHtml(g.description)}</div>` : ""}
                      <details style="margin-top:8px;">
                        <summary class="muted">編輯</summary>
                        ${renderGoalEditForm({ goal: g, eventId: event.id, csrfToken })}
                      </details>
                    </td>
                    <td><span class="${pillForStatus(g.status)}">${escapeHtml(translateGoalStatus(g.status))}</span></td>
                    <td class="muted">${escapeHtml(g.due_date ?? "—")}</td>
                  </tr>
                `
              )
              .join("")}
          </tbody>
        </table>`;

  const progressHtml =
    progress.length === 0
      ? `<div class="muted">尚無進度更新。</div>`
      : `<div class="grid" style="gap:10px;">
          ${progress
            .map(
              (p) => `
              <div class="card" style="box-shadow:none; background: rgba(255,255,255,0.04);">
                <div class="row">
                  <span class="pill">${escapeHtml(translateEntityType(p.entity_type))}</span>
                  ${p.progress_percent === null ? "" : `<span class="pill pill--green">${escapeHtml(String(p.progress_percent))}%</span>`}
                  <div class="spacer"></div>
                  <span class="muted">${escapeHtml(new Date(p.created_at).toLocaleString("zh-TW", { hour12: false }))}</span>
                </div>
                <div style="margin-top:8px;"><strong>${escapeHtml(p.author_name)}</strong>：${escapeHtml(p.note)}</div>
              </div>
            `
            )
            .join("")}
        </div>`;

  const docsHtml =
    docs.length === 0
      ? `<div class="muted">尚無文件。</div>`
      : `<table>
          <thead><tr><th>檔案</th><th>上傳者</th><th>時間</th><th>大小</th></tr></thead>
          <tbody>
            ${docs
              .map(
                (d) => `
                  <tr>
                    <td>
                      <a href="/docs/${escapeHtml(d.id)}"><strong>${escapeHtml(d.file_name)}</strong></a>
                      <div class="muted" style="margin-top:6px;">${escapeHtml(d.content_type)}</div>
                    </td>
                    <td class="muted">${escapeHtml(d.uploader_name)}</td>
                    <td class="muted">${escapeHtml(new Date(d.created_at).toLocaleString("zh-TW", { hour12: false }))}</td>
                    <td class="muted">${escapeHtml(String(d.size_bytes))} bytes</td>
                  </tr>
                `
              )
              .join("")}
          </tbody>
        </table>`;

  return `
    <div class="row">
      <h1 style="margin: 0;">${escapeHtml(event.title)}</h1>
      <div class="spacer"></div>
      <a class="btn" href="/events">返回活動列表</a>
    </div>

    <div class="card" style="margin-top: 12px;">
      <div class="row">
        <span class="${pillForStatus(event.status)}">${escapeHtml(translateEventStatus(event.status))}</span>
        ${dateRange ? `<span class="pill">${escapeHtml(dateRange)}</span>` : `<span class="pill">未設定日期</span>`}
        <div class="spacer"></div>
        <span class="muted">更新：${escapeHtml(new Date(event.updated_at).toLocaleString("zh-TW", { hour12: false }))}</span>
      </div>
      ${event.description ? `<div style="margin-top: 10px;" class="muted">${escapeHtml(event.description)}</div>` : ""}
      <details style="margin-top: 10px;">
        <summary class="muted">編輯活動</summary>
        <form class="form" method="post" action="/events/${escapeHtml(event.id)}/update" style="margin-top: 10px;">
          <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}" />
          <div class="grid grid--2">
            <div>
              <label>活動名稱</label>
              <input name="title" type="text" value="${escapeHtml(event.title)}" required />
            </div>
            <div>
              <label>狀態</label>
              <select name="status">
                ${["planned", "active", "completed", "cancelled"]
                  .map((s) => `<option value="${escapeHtml(s)}" ${event.status === s ? "selected" : ""}>${escapeHtml(translateEventStatus(s))}</option>`)
                  .join("")}
              </select>
            </div>
          </div>
          <div>
            <label>描述（可選）</label>
            <textarea name="description">${escapeHtml(event.description ?? "")}</textarea>
          </div>
          <div class="grid grid--2">
            <div>
              <label>開始日期（可選）</label>
              ${renderDateInput("start_date", event.start_date)}
            </div>
            <div>
              <label>結束日期（可選）</label>
              ${renderDateInput("end_date", event.end_date)}
            </div>
          </div>
          <div class="form__actions">
            <button class="btn btn--primary" type="submit">更新</button>
          </div>
        </form>
      </details>
    </div>

    <h2>參與者</h2>
    <div class="card">
      ${participantsHtml}
      ${addParticipantForm}
    </div>

    <div class="grid grid--2" style="margin-top: 16px;">
      <div class="card">
        <div class="card__title">新增任務</div>
        ${renderTaskCreateForm({ eventId: event.id, csrfToken, allUsers, isAdmin: viewer.role === "admin" })}
        <div style="margin-top: 14px;">${tasksHtml}</div>
      </div>
      <div class="card">
        <div class="card__title">新增目標</div>
        ${renderGoalCreateForm({ eventId: event.id, csrfToken })}
        <div style="margin-top: 14px;">${goalsHtml}</div>
      </div>
    </div>

    <h2>進度追蹤</h2>
    <div class="card">
      ${renderProgressCreateForm({ eventId: event.id, csrfToken, tasks, goals })}
      <div style="margin-top: 14px;">${progressHtml}</div>
    </div>

    <h2>文件</h2>
    <div class="card">
      ${renderDocUploadForm({ eventId: event.id, csrfToken })}
      <div style="margin-top: 14px;">${docsHtml}</div>
      <div class="muted" style="margin-top: 10px;">提示：文件儲存在 R2（需設定 <code class="inline">DOCS_BUCKET</code>）。</div>
    </div>
  `;
}

function renderTaskCreateForm(args: { eventId: string; csrfToken: string; allUsers: Array<{ id: string; display_name: string; email: string }>; isAdmin: boolean }) {
  const options =
    args.isAdmin && args.allUsers.length
      ? `
        <div>
          <label>負責人（可選）</label>
          <select name="assignee_user_id">
            <option value="">不指定</option>
            ${args.allUsers.map((u) => `<option value="${escapeHtml(u.id)}">${escapeHtml(u.display_name)}</option>`).join("")}
          </select>
        </div>
      `
      : `<input type="hidden" name="assignee_user_id" value="" />`;

  return `
    <form class="form" method="post" action="/tasks/create">
      <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
      <input type="hidden" name="event_id" value="${escapeHtml(args.eventId)}" />
      <div>
        <label>任務名稱</label>
        <input name="title" type="text" required />
      </div>
      <div>
        <label>描述（可選）</label>
        <textarea name="description"></textarea>
      </div>
      <div class="grid grid--2">
        ${options}
        <div>
          <label>期限（可選）</label>
          ${renderDateInput("due_date")}
        </div>
      </div>
      <div class="form__actions">
        <button class="btn btn--primary" type="submit">新增</button>
      </div>
    </form>
  `;
}

function renderTaskEditForm(args: {
  task: { id: string; title: string; description: string | null; status: string; due_date: string | null; assignee_user_id: string | null };
  eventId: string;
  csrfToken: string;
  allUsers: Array<{ id: string; display_name: string; email: string }>;
  isAdmin: boolean;
}) {
  const { task } = args;
  const assigneeSelect =
    args.isAdmin && args.allUsers.length
      ? `
        <div>
          <label>負責人</label>
          <select name="assignee_user_id">
            <option value="">不指定</option>
            ${args.allUsers
              .map((u) => `<option value="${escapeHtml(u.id)}" ${task.assignee_user_id === u.id ? "selected" : ""}>${escapeHtml(u.display_name)}</option>`)
              .join("")}
          </select>
        </div>
      `
      : `<input type="hidden" name="assignee_user_id" value="${escapeHtml(task.assignee_user_id ?? "")}" />`;

  return `
    <form class="form" method="post" action="/tasks/${escapeHtml(task.id)}/update" style="margin-top: 10px;">
      <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
      <input type="hidden" name="event_id" value="${escapeHtml(args.eventId)}" />
      <div class="grid grid--2">
        <div>
          <label>名稱</label>
          <input name="title" type="text" value="${escapeHtml(task.title)}" required />
        </div>
        <div>
          <label>狀態</label>
          <select name="status">
            ${["todo", "in_progress", "done", "blocked"]
              .map((s) => `<option value="${escapeHtml(s)}" ${task.status === s ? "selected" : ""}>${escapeHtml(translateTaskStatus(s))}</option>`)
              .join("")}
          </select>
        </div>
      </div>
      <div>
        <label>描述（可選）</label>
        <textarea name="description">${escapeHtml(task.description ?? "")}</textarea>
      </div>
      <div class="grid grid--2">
        ${assigneeSelect}
        <div>
          <label>期限（可選）</label>
          ${renderDateInput("due_date", task.due_date)}
        </div>
      </div>
      <div class="form__actions">
        <button class="btn btn--primary btn--small" type="submit">更新</button>
      </div>
    </form>
  `;
}

function renderGoalCreateForm(args: { eventId: string; csrfToken: string }) {
  return `
    <form class="form" method="post" action="/goals/create">
      <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
      <input type="hidden" name="event_id" value="${escapeHtml(args.eventId)}" />
      <div>
        <label>目標名稱</label>
        <input name="title" type="text" required />
      </div>
      <div>
        <label>描述（可選）</label>
        <textarea name="description"></textarea>
      </div>
      <div>
        <label>期限（可選）</label>
        ${renderDateInput("due_date")}
      </div>
      <div class="form__actions">
        <button class="btn btn--primary" type="submit">新增</button>
      </div>
    </form>
  `;
}

function renderGoalEditForm(args: {
  goal: { id: string; title: string; description: string | null; status: string; due_date: string | null };
  eventId: string;
  csrfToken: string;
}) {
  const { goal } = args;
  return `
    <form class="form" method="post" action="/goals/${escapeHtml(goal.id)}/update" style="margin-top: 10px;">
      <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
      <input type="hidden" name="event_id" value="${escapeHtml(args.eventId)}" />
      <div class="grid grid--2">
        <div>
          <label>名稱</label>
          <input name="title" type="text" value="${escapeHtml(goal.title)}" required />
        </div>
        <div>
          <label>狀態</label>
          <select name="status">
            ${["open", "on_track", "at_risk", "achieved", "dropped"]
              .map((s) => `<option value="${escapeHtml(s)}" ${goal.status === s ? "selected" : ""}>${escapeHtml(translateGoalStatus(s))}</option>`)
              .join("")}
          </select>
        </div>
      </div>
      <div>
        <label>描述（可選）</label>
        <textarea name="description">${escapeHtml(goal.description ?? "")}</textarea>
      </div>
      <div>
        <label>期限（可選）</label>
        ${renderDateInput("due_date", goal.due_date)}
      </div>
      <div class="form__actions">
        <button class="btn btn--primary btn--small" type="submit">更新</button>
      </div>
    </form>
  `;
}

function renderProgressCreateForm(args: {
  eventId: string;
  csrfToken: string;
  tasks: Array<{ id: string; title: string }>;
  goals: Array<{ id: string; title: string }>;
}) {
  const { tasks, goals } = args;
  return `
    <form class="form" method="post" action="/progress/create">
      <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
      <input type="hidden" name="event_id" value="${escapeHtml(args.eventId)}" />
      <div class="grid grid--2">
        <div>
          <label>類型</label>
          <select name="entity_type">
            <option value="event">event（活動）</option>
            <option value="task">task（任務）</option>
            <option value="goal">goal（目標）</option>
          </select>
        </div>
        <div>
          <label>關聯項目（可選）</label>
          <select name="entity_id">
            <option value="${escapeHtml(args.eventId)}">（活動本身）</option>
            ${tasks.map((t) => `<option value="${escapeHtml(t.id)}">任務：${escapeHtml(t.title)}</option>`).join("")}
            ${goals.map((g) => `<option value="${escapeHtml(g.id)}">目標：${escapeHtml(g.title)}</option>`).join("")}
          </select>
        </div>
      </div>
      <div class="grid grid--2">
        <div>
          <label>進度百分比（可選）</label>
          <input name="progress_percent" type="number" min="0" max="100" placeholder="0~100" />
        </div>
        <div>
          <label>說明</label>
          <input name="note" type="text" placeholder="例如：完成需求訪談、卡在 API 權限..." required />
        </div>
      </div>
      <div class="form__actions">
        <button class="btn btn--primary" type="submit">新增進度</button>
      </div>
    </form>
  `;
}

function renderDocUploadForm(args: { eventId: string; csrfToken: string }) {
  return `
    <form class="form" method="post" action="/docs/upload" enctype="multipart/form-data">
      <input type="hidden" name="csrf" value="${escapeHtml(args.csrfToken)}" />
      <input type="hidden" name="event_id" value="${escapeHtml(args.eventId)}" />
      <div class="grid grid--2">
        <div>
          <label>選擇檔案</label>
          <input name="file" type="file" required />
        </div>
        <div style="align-self: end;">
          <button class="btn btn--primary" type="submit">上傳文件</button>
        </div>
      </div>
    </form>
  `;
}

function renderKanbanBoard(args: {
  tasks: Array<{
    id: string;
    title: string;
    description: string | null;
    status: string;
    due_date: string | null;
    assignee_user_id: string | null;
    assignee_name: string | null;
    assignee_id: string | null;
    event_id: string;
    event_title: string;
  }>;
  members: Array<{ id: string; display_name: string; email: string }>;
  user: LayoutUser;
  csrfToken: string;
}) {
  const { tasks, members, user, csrfToken } = args;

  // 按状态分组任务
  const tasksByStatus: Record<string, typeof tasks> = {
    todo: [],
    in_progress: [],
    done: [],
    blocked: [],
  };

  tasks.forEach((task) => {
    const status = task.status || "todo";
    if (tasksByStatus[status]) {
      tasksByStatus[status].push(task);
    } else {
      tasksByStatus.todo.push(task);
    }
  });

  // 计算每个状态的进度百分比
  const totalTasks = tasks.length;
  const doneCount = tasksByStatus.done.length;
  const progressPercent = totalTasks > 0 ? Math.round((doneCount / totalTasks) * 100) : 0;

  // 按成员分组任务
  const tasksByMember: Record<string, typeof tasks> = {};
  members.forEach((member) => {
    tasksByMember[member.id] = tasks.filter((t) => t.assignee_id === member.id);
  });
  const unassignedTasks = tasks.filter((t) => !t.assignee_id);

  // 状态列配置
  const statusColumns = [
    { key: "todo", label: "待辦", color: "yellow" },
    { key: "in_progress", label: "進行中", color: "purple" },
    { key: "done", label: "已完成", color: "green" },
    { key: "blocked", label: "受阻", color: "red" },
  ];

  // 渲染任务卡片
  function renderTaskCard(task: typeof tasks[0], currentStatus: string) {
    const dueDateHtml = task.due_date
      ? `<div class="kanban-card__due muted">期限：${escapeHtml(task.due_date)}</div>`
      : "";
    const assigneeHtml = task.assignee_name
      ? `<div class="kanban-card__assignee">
          <span class="pill pill--small">${escapeHtml(task.assignee_name)}</span>
        </div>`
      : `<div class="kanban-card__assignee">
          <span class="pill pill--small pill--gray">未分配</span>
        </div>`;

    // 快速状态切换按钮（只显示其他状态）
    const statusOptions = [
      { key: "todo", label: "待辦" },
      { key: "in_progress", label: "進行中" },
      { key: "done", label: "已完成" },
      { key: "blocked", label: "受阻" },
    ].filter((s) => s.key !== currentStatus);

    const quickActionsHtml = statusOptions.length > 0
      ? `
        <div class="kanban-card__actions">
          ${statusOptions
            .map(
              (opt) => `
            <form method="post" action="/tasks/${escapeHtml(task.id)}/update" style="display:inline;" onsubmit="event.stopPropagation();">
              <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}" />
              <input type="hidden" name="event_id" value="${escapeHtml(task.event_id)}" />
              <input type="hidden" name="title" value="${escapeHtml(task.title)}" />
              <input type="hidden" name="description" value="${escapeHtml(task.description || "")}" />
              <input type="hidden" name="status" value="${escapeHtml(opt.key)}" />
              <input type="hidden" name="due_date" value="${escapeHtml(task.due_date || "")}" />
              <input type="hidden" name="assignee_user_id" value="${escapeHtml(task.assignee_user_id || "")}" />
              <button type="submit" class="btn btn--small btn--ghost" title="移至${escapeHtml(opt.label)}">${escapeHtml(opt.label)}</button>
            </form>
          `
            )
            .join("")}
        </div>
      `
      : "";

    return `
      <div class="kanban-card" data-task-id="${escapeHtml(task.id)}">
        <div class="kanban-card__header">
          <a href="/events/${escapeHtml(task.event_id)}" class="kanban-card__event">${escapeHtml(task.event_title)}</a>
        </div>
        <div class="kanban-card__title">${escapeHtml(task.title)}</div>
        ${task.description ? `<div class="kanban-card__description muted">${escapeHtml(task.description)}</div>` : ""}
        <div class="kanban-card__footer">
          ${assigneeHtml}
          ${dueDateHtml}
        </div>
        ${quickActionsHtml}
      </div>
    `;
  }

  // 渲染状态列
  const columnsHtml = statusColumns
    .map((col) => {
      const columnTasks = tasksByStatus[col.key] || [];
      const count = columnTasks.length;
      return `
        <div class="kanban-column">
          <div class="kanban-column__header">
            <span class="pill pill--${col.color}">${escapeHtml(col.label)}</span>
            <span class="kanban-column__count">${count}</span>
          </div>
          <div class="kanban-column__content" data-status="${escapeHtml(col.key)}">
            ${count === 0 ? `<div class="muted" style="padding: 16px; text-align: center;">尚無任務</div>` : columnTasks.map((task) => renderTaskCard(task, col.key)).join("")}
          </div>
        </div>
      `;
    })
    .join("");

  // 成员任务概览
  const memberOverviewHtml = members.length > 0
    ? `
      <div class="card" style="margin-top: 24px;">
        <div class="card__title">成員任務分配</div>
        <div class="member-overview">
          ${members
            .map((member) => {
              const memberTasks = tasksByMember[member.id] || [];
              const memberDoneCount = memberTasks.filter((t) => t.status === "done").length;
              const memberProgress = memberTasks.length > 0 ? Math.round((memberDoneCount / memberTasks.length) * 100) : 0;
              return `
                <div class="member-overview__item">
                  <div class="member-overview__name">
                    <strong>${escapeHtml(member.display_name)}</strong>
                    <span class="pill pill--small">${memberTasks.length} 任務</span>
                  </div>
                  <div class="member-overview__progress">
                    <div class="progress-bar">
                      <div class="progress-bar__fill" style="width: ${memberProgress}%"></div>
                    </div>
                    <span class="muted">${memberProgress}%</span>
                  </div>
                </div>
              `;
            })
            .join("")}
          ${unassignedTasks.length > 0
            ? `
              <div class="member-overview__item">
                <div class="member-overview__name">
                  <strong>未分配</strong>
                  <span class="pill pill--small pill--gray">${unassignedTasks.length} 任務</span>
                </div>
                <div class="member-overview__progress">
                  <div class="progress-bar">
                    <div class="progress-bar__fill" style="width: 0%"></div>
                  </div>
                  <span class="muted">—</span>
                </div>
              </div>
            `
            : ""}
        </div>
      </div>
    `
    : "";

  return `
    <div class="card">
      <div class="kanban-header">
        <div class="kanban-header__title">總體進度</div>
        <div class="kanban-header__progress">
          <div class="progress-bar progress-bar--large">
            <div class="progress-bar__fill" style="width: ${progressPercent}%"></div>
          </div>
          <span class="kanban-header__percent">${progressPercent}%</span>
        </div>
        <div class="kanban-header__stats">
          <span class="pill">總任務：${totalTasks}</span>
          <span class="pill pill--green">已完成：${doneCount}</span>
        </div>
      </div>
    </div>
    <div class="kanban-board">
      ${columnsHtml}
    </div>
    ${memberOverviewHtml}
  `;
}

