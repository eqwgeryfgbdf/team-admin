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
  if (!input) return "";
  // 快速检查是否包含需要转义的字符，避免不必要的处理
  if (!/[&<>"']/.test(input)) return input;
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
        .nav__link { 
          color: var(--muted); 
          padding: 8px 10px; 
          border-radius: 10px;
          transition: color 0.15s ease, background-color 0.15s ease;
        }
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
          contain: layout style paint;
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
        .btn { 
          transition: background-color 0.15s ease, border-color 0.15s ease;
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
        input:focus, textarea:focus, select:focus { 
          border-color: rgba(124,58,237,0.7); 
          box-shadow: 0 0 0 3px rgba(124,58,237,0.18); 
        }
        textarea { min-height: 90px; resize: vertical; }
        .date-input-wrapper { 
          position: relative; 
          display: flex; 
          align-items: center;
          contain: layout;
        }
        .date-input-wrapper input[type="date"] { 
          padding-right: 40px; 
          cursor: pointer;
        }
        .date-input-wrapper input[type="date"]::-webkit-calendar-picker-indicator {
          position: absolute;
          right: 8px;
          cursor: pointer;
          opacity: 0.7;
          filter: invert(1);
          width: 20px;
          height: 20px;
          transition: opacity 0.15s ease;
        }
        .date-input-wrapper input[type="date"]::-webkit-calendar-picker-indicator:hover {
          opacity: 1;
        }
        .date-icon-btn {
          position: absolute;
          right: 8px;
          background: transparent;
          border: none;
          color: var(--muted);
          cursor: pointer;
          padding: 4px;
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1;
          transition: color 0.15s ease;
        }
        .date-icon-btn:hover { color: var(--text); }
        .date-icon-btn svg { 
          width: 18px; 
          height: 18px; 
          pointer-events: none;
        }
        .form { display: grid; gap: 12px; }
        .form__actions { display: flex; gap: 10px; justify-content: flex-end; align-items: center; flex-wrap: wrap; }
        table { width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 12px; border: 1px solid var(--line); }
        th, td { text-align: left; padding: 10px 10px; border-bottom: 1px solid rgba(255,255,255,0.08); vertical-align: top; }
        th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; background: rgba(255,255,255,0.04); }
        tr { transition: background-color 0.15s ease; }
        tr:hover td { background: rgba(255,255,255,0.03); }
        code.inline { background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.12); }
        .pill { display: inline-flex; align-items: center; padding: 4px 9px; border-radius: 999px; font-size: 12px; border: 1px solid rgba(255,255,255,0.14); color: var(--muted); }
        .pill--green { color: rgba(34,197,94,0.95); border-color: rgba(34,197,94,0.35); background: rgba(34,197,94,0.10); }
        .pill--purple { color: rgba(167,139,250,0.95); border-color: rgba(124,58,237,0.40); background: rgba(124,58,237,0.12); }
        .pill--yellow { color: rgba(245,158,11,0.95); border-color: rgba(245,158,11,0.35); background: rgba(245,158,11,0.10); }
        .pill--red { color: rgba(248,113,113,0.95); border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.10); }
      </style>
      <script>
        // 改善日期输入的用户体验 - 使用事件委托优化性能
        (function() {
          'use strict';
          
          // 缓存日期格式化选项，避免重复创建
          const dateFormatOptions = { 
            year: 'numeric', 
            month: '2-digit', 
            day: '2-digit' 
          };
          
          // 日期格式化函数（复用）
          function formatDate(value) {
            if (!value) return '';
            try {
              const date = new Date(value + 'T00:00:00');
              return date.toLocaleDateString('zh-TW', dateFormatOptions);
            } catch (e) {
              return '';
            }
          }
          
          // 更新单个输入框的 title
          function updateInputTitle(input) {
            input.title = formatDate(input.value);
          }
          
          // 打开日期选择器
          function openDatePicker(input) {
            if (typeof input.showPicker === 'function') {
              try {
                input.showPicker();
              } catch (e) {
                // 某些情况下 showPicker 可能失败，回退到 focus
                input.focus();
              }
            } else {
              input.focus();
            }
          }
          
          // 使用事件委托优化性能
          function init() {
            const dateInputs = document.querySelectorAll('input[type="date"]');
            const len = dateInputs.length;
            
            // 批量初始化 title
            for (let i = 0; i < len; i++) {
              updateInputTitle(dateInputs[i]);
            }
            
            // 使用事件委托处理所有日期输入框的事件
            document.addEventListener('click', function(e) {
              const target = e.target;
              if (target && target.type === 'date') {
                if (typeof target.showPicker === 'function') {
                  e.preventDefault();
                  openDatePicker(target);
                }
              }
            }, true); // 使用捕获阶段提高性能
            
            // 处理 focus 事件（Tab 键导航）
            let focusTimer = null;
            document.addEventListener('focus', function(e) {
              const target = e.target;
              if (target && target.type === 'date') {
                clearTimeout(focusTimer);
                focusTimer = setTimeout(function() {
                  if (document.activeElement === target) {
                    openDatePicker(target);
                  }
                }, 100);
              }
            }, true);
            
            // 批量处理 change 和 input 事件
            document.addEventListener('change', function(e) {
              const target = e.target;
              if (target && target.type === 'date') {
                updateInputTitle(target);
              }
            }, true);
            
            document.addEventListener('input', function(e) {
              const target = e.target;
              if (target && target.type === 'date') {
                updateInputTitle(target);
              }
            }, true);
          }
          
          // 如果 DOM 已加载，立即执行；否则等待 DOMContentLoaded
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', init);
          } else {
            init();
          }
        })();
      </script>
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

