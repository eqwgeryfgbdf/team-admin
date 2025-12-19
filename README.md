# Team Admin（團隊管理工具）

Cloudflare Workers + D1（SQLite）打造的輕量團隊管理工具，支援：

- **帳號密碼登入**（PBKDF2 雜湊）
- **加入/移除成員**（管理員）
- **活動建立**、日期、參與人員
- **任務分配（可選）**、目標、進度追蹤
- **文件上傳/下載**（R2，metadata 存 D1）
- **Discord 發佈通知**（Webhook）

## Quick Start

### 1) 安裝依賴

```bash
npm install
```

### 2) 建立 D1 並更新 `wrangler.json`

建立 D1：

```bash
npx wrangler d1 create team-admin-db
```

然後把輸出的 `database_id` 更新到 `wrangler.json` 裡 `d1_databases[0].database_id`。

### 3) 套用 migrations（初始化 schema）

本機（建議先跑本機）：

```bash
npx wrangler d1 migrations apply DB --local
```

部署前套用到遠端：

```bash
npx wrangler d1 migrations apply DB --remote
```

### 4)（可選）建立 R2 Bucket（文件上傳）

建立 bucket：

```bash
npx wrangler r2 bucket create team-admin-docs
```

`wrangler.json` 已預設綁定 `DOCS_BUCKET`，你可依需求改 bucket 名稱。

### 5)（可選）設定 Discord Webhook

最推薦用 secret（避免把 webhook URL 放進 git）：

```bash
npx wrangler secret put DISCORD_WEBHOOK_URL
```

本機開發也可用 `.dev.vars`：

```bash
echo 'DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."' > .dev.vars
```

### 6) 啟動開發伺服器

```bash
npm run dev
```

第一次使用請到 `GET /setup` 初始化管理員帳號（只允許在資料庫還沒有任何使用者時執行）。

## 主要路徑（UI）

- `GET /`：導向（沒有使用者 → `/setup`，未登入 → `/login`，已登入 → `/app`）
- `GET/POST /setup`：初始化管理員
- `GET/POST /login`、`POST /logout`：登入/登出
- `GET /app`：儀表板
- `GET /members`、`GET /members/new`、`POST /members`：成員管理（admin）
- `GET/POST /members/:id`：個人資料/密碼（self 或 admin）
- `GET /events`、`GET /events/new`、`POST /events`：活動
- `GET /events/:id`：活動詳情（參與者、任務、目標、進度、文件）

## Notes

- **文件上傳**需要 R2：請設定 `DOCS_BUCKET`（見上方步驟）。
- **Discord 通知**只有在 `DISCORD_WEBHOOK_URL` 有設定時才會送出。
- 這是 **MVP**：後續可以加上更細的權限（只允許參與者看活動）、API token、審計 log、更多狀態/報表等。
