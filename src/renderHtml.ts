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
      <div class="nav__left">
        <div class="nav__brand">Team Admin</div>
        <div class="nav__links">
          <a class="nav__link" href="/app">儀表板</a>
          <a class="nav__link" href="/events">活動</a>
          ${user.role === "admin" ? `<a class="nav__link" href="/members">成員</a>` : ""}
          <a class="nav__link" href="/profile">個人資料</a>
        </div>
      </div>
      <div class="nav__right">
        <button id="theme-toggle" class="btn btn--icon" aria-label="切換主題">
            <svg class="icon-sun" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
            <svg class="icon-moon" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
        </button>
        <form class="nav__logout" method="post" action="/logout">
          <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
          <button class="btn btn--ghost" type="submit">登出</button>
        </form>
      </div>
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
      <script>
        // 立即執行主題檢查，避免閃爍
        (function() {
          try {
            var localTheme = localStorage.getItem('theme');
            var supportDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
            if (localTheme === 'dark' || (!localTheme && supportDarkMode)) {
              document.documentElement.setAttribute('data-theme', 'dark');
            } else {
              document.documentElement.setAttribute('data-theme', 'light');
            }
          } catch (e) {}
        })();
      </script>
      <style>
        :root {
          /* 色彩系統 - 淺色模式 (預設) */
          --bg-primary: #ffffff;
          --bg-secondary: #f8fafc;
          --text-primary: #1e293b;
          --text-secondary: #64748b;
          --text-muted: #94a3b8;
          --accent: #06b6d4; /* 水藍色 */
          --accent-hover: #0891b2;
          --accent-light: rgba(6, 182, 212, 0.1);
          --border: #e2e8f0;
          --nav-bg: rgba(255, 255, 255, 0.85);
          --card-bg: rgba(255, 255, 255, 0.7);
          --glass-border: rgba(255, 255, 255, 0.6);
          --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
          --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
          --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
          --glow: none;
          
          /* 功能色 */
          --danger: #ef4444;
          --danger-bg: rgba(239, 68, 68, 0.1);
          --success: #22c55e;
          --success-bg: rgba(34, 197, 94, 0.1);
          --warning: #f59e0b;
          --warning-bg: rgba(245, 158, 11, 0.1);

          /* 變數 */
          --radius-lg: 20px;
          --radius-md: 14px;
          --radius-sm: 8px;
          --radius-btn: 9999px; /* 圓角按鈕 */
          --font-sans: 'Inter', ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
          --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        /* 深色模式覆寫 */
        html[data-theme="dark"] {
          --bg-primary: #0b1020; /* 深藍色 */
          --bg-secondary: #111827;
          --text-primary: #f8fafc;
          --text-secondary: #cbd5e1;
          --text-muted: #64748b;
          --accent: #8b5cf6; /* 紫色 */
          --accent-hover: #7c3aed;
          --accent-light: rgba(139, 92, 246, 0.15);
          --border: rgba(255, 255, 255, 0.08);
          --nav-bg: rgba(11, 16, 32, 0.85);
          --card-bg: rgba(17, 24, 39, 0.6);
          --glass-border: rgba(255, 255, 255, 0.08);
          --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.3);
          --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
          --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
          --glow: 0 0 15px rgba(139, 92, 246, 0.5); /* 霓虹效果 */
        }

        * { box-sizing: border-box; }
        
        body {
          margin: 0;
          font-family: var(--font-sans);
          color: var(--text-primary);
          background-color: var(--bg-primary);
          transition: background-color 0.5s ease, color 0.5s ease;
          min-height: 100vh;
          overflow-x: hidden;
          
          /* 背景動畫效果 */
          background-image: 
            radial-gradient(circle at 15% 15%, var(--accent-light) 0%, transparent 40%),
            radial-gradient(circle at 85% 85%, rgba(6, 182, 212, 0.1) 0%, transparent 40%);
          background-attachment: fixed;
        }

        html[data-theme="dark"] body {
          background-image: 
            radial-gradient(circle at 20% 20%, rgba(139, 92, 246, 0.2) 0%, transparent 50%),
            radial-gradient(circle at 80% 80%, rgba(6, 182, 212, 0.15) 0%, transparent 50%);
        }

        a { color: inherit; text-decoration: none; transition: var(--transition); }
        
        /* 佈局容器 */
        .container { 
          max-width: 1200px; 
          margin: 0 auto; 
          padding: 32px 24px 64px; 
          animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }

        /* 導航列 */
        .nav {
          position: sticky; top: 0;
          display: flex; justify-content: space-between; align-items: center;
          padding: 16px 24px;
          border-bottom: 1px solid var(--border);
          background: var(--nav-bg);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          z-index: 50;
          transition: all 0.3s ease;
        }
        
        .nav__left { display: flex; align-items: center; gap: 32px; }
        .nav__right { display: flex; align-items: center; gap: 16px; }

        .nav__brand { 
          font-weight: 800; 
          font-size: 1.25rem;
          letter-spacing: -0.025em; 
          background: linear-gradient(135deg, var(--accent), #06b6d4);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }
        html[data-theme="dark"] .nav__brand {
          background: linear-gradient(135deg, var(--accent), #c084fc);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }

        .nav__links { display: flex; gap: 8px; }

        .nav__link { 
          color: var(--text-secondary); 
          padding: 8px 16px; 
          border-radius: var(--radius-btn);
          font-size: 0.95rem;
          font-weight: 500;
        }
        
        .nav__link:hover { 
          color: var(--text-primary); 
          background: var(--bg-secondary);
        }

        .nav__logout { display: flex; }

        /* 排版 */
        h1 { font-size: 2rem; font-weight: 800; margin: 0 0 24px; letter-spacing: -0.025em; }
        h2 { font-size: 1.25rem; font-weight: 600; margin: 32px 0 16px; color: var(--text-primary); display: flex; align-items: center; gap: 8px; }
        .muted { color: var(--text-muted); }
        
        /* 網格系統 */
        .grid { display: grid; gap: 24px; }
        .grid--2 { grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); }
        
        /* 卡片 */
        .card {
          border: 1px solid var(--border);
          background: var(--card-bg);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-sm);
          padding: 24px;
          backdrop-filter: blur(12px);
          transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
        }
        
        .card:hover {
          transform: translateY(-4px);
          box-shadow: var(--shadow-lg);
          border-color: var(--accent);
        }
        
        html[data-theme="dark"] .card:hover {
          box-shadow: var(--glow);
        }

        .card__title { font-size: 1.1rem; font-weight: 700; margin-bottom: 16px; color: var(--text-primary); }

        /* 元件通用 */
        .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
        .spacer { flex: 1; }
        
        /* Flash 訊息 */
        .flash { 
          margin-bottom: 24px; padding: 16px; 
          border-radius: var(--radius-md); 
          border: 1px solid transparent; 
          display: flex; align-items: center;
          font-weight: 500;
          animation: slideDown 0.4s ease-out;
        }
        .flash--info { background: rgba(59,130,246,0.1); color: #3b82f6; border-color: rgba(59,130,246,0.2); }
        .flash--success { background: rgba(34,197,94,0.1); color: #22c55e; border-color: rgba(34,197,94,0.2); }
        .flash--error { background: rgba(239,68,68,0.1); color: #ef4444; border-color: rgba(239,68,68,0.2); }

        /* 按鈕 */
        .btn {
          display: inline-flex; align-items: center; justify-content: center;
          gap: 8px;
          padding: 10px 20px;
          border-radius: var(--radius-btn);
          border: 1px solid transparent;
          font-weight: 600;
          font-size: 0.95rem;
          cursor: pointer;
          transition: all 0.2s ease;
          position: relative;
          overflow: hidden;
        }
        
        .btn:active { transform: scale(0.97); }
        
        .btn--primary { 
          background: var(--accent); 
          color: white; 
          box-shadow: 0 4px 12px rgba(6, 182, 212, 0.3);
        }
        html[data-theme="dark"] .btn--primary {
          box-shadow: 0 4px 12px rgba(139, 92, 246, 0.4);
        }
        
        .btn--primary:hover { 
          background: var(--accent-hover); 
          transform: translateY(-1px);
          box-shadow: 0 6px 16px rgba(6, 182, 212, 0.4);
        }
        html[data-theme="dark"] .btn--primary:hover {
          box-shadow: 0 0 20px rgba(139, 92, 246, 0.6);
        }

        .btn--danger { 
          background: var(--danger-bg); 
          color: var(--danger); 
          border-color: transparent;
        }
        .btn--danger:hover { 
          background: rgba(239, 68, 68, 0.2); 
        }

        .btn--ghost { 
          background: transparent; 
          color: var(--text-secondary); 
          padding: 8px 16px;
        }
        .btn--ghost:hover { 
          background: var(--bg-secondary); 
          color: var(--text-primary); 
        }

        .btn--small { padding: 6px 12px; font-size: 0.85rem; }
        
        .btn--icon {
          padding: 8px;
          border-radius: 50%;
          color: var(--text-secondary);
          background: transparent;
        }
        .btn--icon:hover {
          background: var(--bg-secondary);
          color: var(--text-primary);
        }

        /* 表單 */
        label { display: block; font-size: 0.9rem; font-weight: 500; color: var(--text-secondary); margin-bottom: 8px; }
        
        input, textarea, select {
          width: 100%;
          padding: 12px 16px;
          border-radius: var(--radius-md);
          border: 2px solid var(--border);
          background: var(--bg-primary);
          color: var(--text-primary);
          font-size: 1rem;
          transition: all 0.2s ease;
          outline: none;
        }
        
        input:focus, textarea:focus, select:focus { 
          border-color: var(--accent);
          box-shadow: 0 0 0 4px var(--accent-light);
        }
        
        textarea { min-height: 120px; resize: vertical; line-height: 1.6; }
        
        .date-input-wrapper { 
          position: relative; 
          display: flex; 
          align-items: center; 
          cursor: pointer;
        }
        .date-input-wrapper input[type="date"] { 
          padding-right: 44px; 
          cursor: pointer; 
          caret-color: transparent; /* 隱藏游標 */
        }
        .date-input-wrapper input[type="date"]::-webkit-calendar-picker-indicator {
          position: absolute; 
          right: 12px; 
          cursor: pointer; 
          opacity: 0; 
          width: 100%; 
          height: 100%; 
          z-index: 1;
        }
        .date-icon-btn {
          position: absolute; 
          right: 12px; 
          background: transparent; 
          border: none; 
          color: var(--text-muted); 
          padding: 4px; 
          pointer-events: none; /* 讓點擊事件穿透到 input */
          transition: color 0.2s;
          z-index: 2;
        }
        .date-input-wrapper:hover .date-icon-btn,
        .date-input-wrapper:focus-within .date-icon-btn { 
          color: var(--accent); 
        }
        .date-input-wrapper:focus-within input {
          border-color: var(--accent);
          box-shadow: 0 0 0 4px var(--accent-light);
        }
        
        .form { display: grid; gap: 20px; }
        .form__actions { display: flex; gap: 12px; justify-content: flex-end; align-items: center; margin-top: 8px; }

        /* 表格 */
        table { width: 100%; border-collapse: separate; border-spacing: 0; border-radius: var(--radius-lg); border: 1px solid var(--border); overflow: hidden; }
        
        th, td { text-align: left; padding: 16px; border-bottom: 1px solid var(--border); }
        
        th { 
          color: var(--text-muted); 
          font-size: 0.8rem; 
          font-weight: 600; 
          text-transform: uppercase; 
          letter-spacing: 0.05em; 
          background: var(--bg-secondary); 
        }
        
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: var(--bg-secondary); }

        /* 標籤 Pill */
        .pill { 
          display: inline-flex; align-items: center; padding: 4px 12px; 
          border-radius: 999px; font-size: 0.85rem; font-weight: 500;
        }
        .pill--green { color: #15803d; background: #dcfce7; }
        .pill--purple { color: #7e22ce; background: #f3e8ff; }
        .pill--yellow { color: #b45309; background: #fef3c7; }
        .pill--red { color: #b91c1c; background: #fee2e2; }

        html[data-theme="dark"] .pill--green { color: #4ade80; background: rgba(34, 197, 94, 0.2); }
        html[data-theme="dark"] .pill--purple { color: #a78bfa; background: rgba(139, 92, 246, 0.2); }
        html[data-theme="dark"] .pill--yellow { color: #fbbf24; background: rgba(245, 158, 11, 0.2); }
        html[data-theme="dark"] .pill--red { color: #f87171; background: rgba(239, 68, 68, 0.2); }

        code.inline { 
          background: var(--bg-secondary); 
          padding: 2px 6px; 
          border-radius: 6px; 
          font-family: monospace; 
          font-size: 0.9em; 
          color: var(--accent);
        }

        /* 主題切換按鈕圖示 */
        .icon-moon { display: none; }
        html[data-theme="dark"] .icon-sun { display: none; }
        html[data-theme="dark"] .icon-moon { display: block; }

        /* 動畫 Keyframes */
        @keyframes slideUp {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes slideDown {
          from { opacity: 0; transform: translateY(-20px); }
          to { opacity: 1; transform: translateY(0); }
        }

        /* 響應式 */
        @media (max-width: 768px) {
          .nav { padding: 12px 16px; }
          .container { padding: 20px 16px 48px; }
          .nav__brand { font-size: 1.1rem; }
          .nav__link { padding: 6px 10px; font-size: 0.9rem; }
          .nav__links { display: none; } /* 手機版可能需要漢堡選單，暫時隱藏文字連結或保持簡約 */
          .nav__left { gap: 16px; }
          
          /* 簡單的手機版適配：在手機上顯示連結但縮小間距 */
          .nav__links { display: flex; gap: 4px; }
          .nav__link { padding: 6px 8px; font-size: 0.85rem; }
        }
      </style>
      <script>
        document.addEventListener('DOMContentLoaded', () => {
          // 日期輸入優化 - 點擊即開啟日期選擇器
          (function() {
            const dateFormatOptions = { year: 'numeric', month: '2-digit', day: '2-digit' };
            
            function formatDate(value) {
              if (!value) return '';
              try { 
                return new Date(value + 'T00:00:00').toLocaleDateString('zh-TW', dateFormatOptions); 
              } catch (e) { 
                return ''; 
              }
            }
            
            function updateInputTitle(input) { 
              input.title = formatDate(input.value); 
            }
            
            function openDatePicker(input) {
              if (!input) return;
              // 優先使用 showPicker API (現代瀏覽器)
              if (typeof input.showPicker === 'function') {
                try {
                  input.showPicker();
                } catch (e) {
                  // 如果 showPicker 失敗，使用 focus 作為備選
                  input.focus();
                }
              } else {
                // 舊版瀏覽器使用 focus
                input.focus();
              }
            }
            
            // 初始化所有日期輸入框的 title
            const dateInputs = document.querySelectorAll('input[type="date"]');
            dateInputs.forEach(input => {
              updateInputTitle(input);
              
              // 點擊輸入框時開啟日期選擇器
              input.addEventListener('click', function(e) {
                e.preventDefault();
                openDatePicker(this);
              });
              
              // Focus 時也開啟日期選擇器（Tab 鍵導航）
              input.addEventListener('focus', function() {
                // 使用 setTimeout 避免與 click 事件衝突
                setTimeout(() => {
                  if (document.activeElement === this) {
                    openDatePicker(this);
                  }
                }, 100);
              });
              
              // 防止鍵盤輸入（只允許通過日期選擇器選擇）
              input.addEventListener('keydown', function(e) {
                // 允許 Tab、Enter、Escape 等導航鍵
                if (e.key === 'Tab' || e.key === 'Enter' || e.key === 'Escape') {
                  return;
                }
                // 阻止其他鍵盤輸入
                e.preventDefault();
                // 如果按下的是數字或方向鍵，開啟日期選擇器
                if (/[0-9]/.test(e.key) || /Arrow/.test(e.key)) {
                  openDatePicker(this);
                }
              });
            });
            
            // 處理日期變更事件
            document.addEventListener('change', function(e) {
              if (e.target && e.target.type === 'date') {
                updateInputTitle(e.target);
              }
            });
            
            // 處理日期輸入事件（即時更新）
            document.addEventListener('input', function(e) {
              if (e.target && e.target.type === 'date') {
                updateInputTitle(e.target);
              }
            });
          })();

          // 主題切換邏輯
          const themeToggle = document.getElementById('theme-toggle');
          if (themeToggle) {
            themeToggle.addEventListener('click', () => {
              const currentTheme = document.documentElement.getAttribute('data-theme');
              const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
              
              document.documentElement.setAttribute('data-theme', newTheme);
              localStorage.setItem('theme', newTheme);
              
              // 添加切換動畫效果
              document.body.style.transition = 'background-color 0.5s ease, color 0.5s ease';
            });
          }
        });
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
