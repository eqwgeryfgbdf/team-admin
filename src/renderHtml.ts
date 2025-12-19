export type LayoutUser = {
  id: string;
  email: string;
  displayName: string;
  role: "admin" | "member";
};

export type LayoutOptions = {
  title: string;
  user?: LayoutUser;
  csrfToken?: string;
  body: string;
  flash?: { type: "info" | "error" | "success"; message: string };
};

export function escapeHtml(input: string): string {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderNav(user: LayoutUser, csrfToken: string) {
  return `
    <nav class="nav">
      <div class="nav__brand">Team Admin</div>
      <a class="nav__link" href="/app">儀表板</a>
      <a class="nav__link" href="/events">活動</a>
      ${user.role === "admin" ? `<a class="nav__link" href="/members">成員</a>` : ""}
      <a class="nav__link" href="/profile">個人資料</a>
      <form class="nav__logout" method="post" action="/logout">
        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
        <button class="btn btn--ghost" type="submit">登出</button>
      </form>
    </nav>
  `;
}

export function renderLayout(opts: LayoutOptions): string {
  const { title, user, body, flash } = opts;
  const csrfToken = opts.csrfToken ?? "";

  const flashHtml = flash
    ? `<div class="flash flash--${flash.type}">${escapeHtml(flash.message)}</div>`
    : "";

  const navHtml = user ? renderNav(user, csrfToken) : "";

  return `<!doctype html>
  <html lang="zh-Hant">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>${escapeHtml(title)} · Team Admin</title>
      <style>
        :root {
          --bg: #0b1020;
          --panel: rgba(255,255,255,0.06);
          --panel2: rgba(255,255,255,0.09);
          --text: rgba(255,255,255,0.92);
          --muted: rgba(255,255,255,0.7);
          --line: rgba(255,255,255,0.12);
          --accent: #7c3aed;
          --accent2: #22c55e;
          --danger: #ef4444;
          --warning: #f59e0b;
          --shadow: 0 12px 32px rgba(0,0,0,0.35);
          --radius: 14px;
          --radius2: 10px;
          --font: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji",
            "Segoe UI Emoji";
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          font-family: var(--font);
          color: var(--text);
          background: radial-gradient(1200px 800px at 20% 10%, rgba(124,58,237,0.22), transparent 55%),
            radial-gradient(900px 700px at 90% 10%, rgba(34,197,94,0.18), transparent 50%),
            radial-gradient(900px 700px at 60% 90%, rgba(59,130,246,0.12), transparent 55%),
            var(--bg);
          min-height: 100vh;
        }
        a { color: inherit; text-decoration: none; }
        .container { max-width: 1060px; margin: 0 auto; padding: 18px 16px 54px; }
        .nav {
          position: sticky; top: 0;
          display: flex; gap: 14px; align-items: center;
          padding: 12px 16px;
          border-bottom: 1px solid var(--line);
          background: rgba(10,14,28,0.8);
          backdrop-filter: blur(10px);
          z-index: 10;
        }
        .nav__brand { font-weight: 700; letter-spacing: 0.4px; margin-right: 6px; }
        .nav__link { color: var(--muted); padding: 8px 10px; border-radius: 10px; }
        .nav__link:hover { color: var(--text); background: rgba(255,255,255,0.06); }
        .nav__logout { margin-left: auto; }
        h1 { font-size: 28px; margin: 16px 0 10px; }
        h2 { font-size: 18px; margin: 18px 0 10px; color: var(--text); }
        .muted { color: var(--muted); }
        .grid { display: grid; gap: 14px; }
        .grid--2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        @media (max-width: 880px) { .grid--2 { grid-template-columns: 1fr; } }
        .card {
          border: 1px solid var(--line);
          background: linear-gradient(180deg, rgba(255,255,255,0.08), rgba(255,255,255,0.04));
          border-radius: var(--radius);
          box-shadow: var(--shadow);
          padding: 14px 14px;
        }
        .card__title { font-weight: 700; margin-bottom: 10px; }
        .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .spacer { flex: 1; }
        .flash { margin: 14px 0; padding: 12px 12px; border-radius: var(--radius2); border: 1px solid var(--line); }
        .flash--info { background: rgba(59,130,246,0.12); }
        .flash--success { background: rgba(34,197,94,0.12); }
        .flash--error { background: rgba(239,68,68,0.12); }
        .btn {
          display: inline-flex; align-items: center; justify-content: center;
          gap: 8px;
          padding: 9px 12px;
          border-radius: 12px;
          border: 1px solid rgba(255,255,255,0.16);
          background: rgba(255,255,255,0.08);
          color: var(--text);
          cursor: pointer;
        }
        .btn:hover { background: rgba(255,255,255,0.12); }
        .btn--primary { background: rgba(124,58,237,0.22); border-color: rgba(124,58,237,0.55); }
        .btn--primary:hover { background: rgba(124,58,237,0.28); }
        .btn--danger { background: rgba(239,68,68,0.18); border-color: rgba(239,68,68,0.55); }
        .btn--ghost { background: transparent; }
        .btn--small { padding: 6px 10px; border-radius: 10px; font-size: 13px; }
        label { display: block; font-size: 13px; color: var(--muted); margin-bottom: 6px; }
        input, textarea, select {
          width: 100%;
          padding: 10px 11px;
          border-radius: 12px;
          border: 1px solid rgba(255,255,255,0.18);
          background: rgba(5,7,16,0.55);
          color: var(--text);
          outline: none;
        }
        input:focus, textarea:focus, select:focus { border-color: rgba(124,58,237,0.7); box-shadow: 0 0 0 3px rgba(124,58,237,0.18); }
        textarea { min-height: 90px; resize: vertical; }
        .form { display: grid; gap: 12px; }
        .form__actions { display: flex; gap: 10px; justify-content: flex-end; align-items: center; flex-wrap: wrap; }
        table { width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 12px; border: 1px solid var(--line); }
        th, td { text-align: left; padding: 10px 10px; border-bottom: 1px solid rgba(255,255,255,0.08); vertical-align: top; }
        th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; background: rgba(255,255,255,0.04); }
        tr:hover td { background: rgba(255,255,255,0.03); }
        code.inline { background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.12); }
        .pill { display: inline-flex; align-items: center; padding: 4px 9px; border-radius: 999px; font-size: 12px; border: 1px solid rgba(255,255,255,0.14); color: var(--muted); }
        .pill--green { color: rgba(34,197,94,0.95); border-color: rgba(34,197,94,0.35); background: rgba(34,197,94,0.10); }
        .pill--purple { color: rgba(167,139,250,0.95); border-color: rgba(124,58,237,0.40); background: rgba(124,58,237,0.12); }
        .pill--yellow { color: rgba(245,158,11,0.95); border-color: rgba(245,158,11,0.35); background: rgba(245,158,11,0.10); }
        .pill--red { color: rgba(248,113,113,0.95); border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.10); }
      </style>
    </head>
    <body>
      ${navHtml}
      <div class="container">
        ${flashHtml}
        ${body}
      </div>
    </body>
  </html>`;
}

