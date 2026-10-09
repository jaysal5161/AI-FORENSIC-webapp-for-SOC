# AEGIS // SOC Forensic Investigation Platform

> **AEGIS** is a production-grade Security Operations Center (SOC) Forensic Telemetry & Incident Investigation Platform built with the MERN stack (MongoDB, Express, React, Node.js). It empowers security analysts and incident responders to ingest heterogeneous telemetry, normalize logs to a Common Event Model (CEM), trigger deterministic MITRE ATT&CK correlation rules, and conduct end-to-end digital forensics across a 14-stage lifecycle.

---

## 1. System Architecture

```text
+--------------------------------------------------------------------------------------------------+
|                                    AEGIS SOC COMMAND CENTER                                      |
+--------------------------------------------------------------------------------------------------+
|  CLIENT (React 18 + Vite + Tailwind CSS + Lucide + Zustand + React Query + Recharts)            |
|  ├── Dashboard (KPIs, Telemetry Spikes, Threat Posture, Severity Breakdown, Top IPs/Identities)   |
|  ├── Ingestion & Parser Preview (Multi-format Drag & Drop, Preset Samples)                      |
|  ├── CEM Telemetry Explorer (Full Faceted Filter, MITRE Technique Tags, Raw Inspector)          |
|  ├── Detection Rule Engine (Threshold & Sequence Rules, MITRE Mappings, Live Trigger)           |
|  ├── Alerts Queue (Real-time Triage, Fast Case Conversion, Analyst Assignment)                  |
|  ├── Forensic Case Workspace (11-Tab Dossier: Overview, Timeline, Events, IOCs, Accounts,       |
|  │     Endpoints, Kill Chain, Evidence Locker, Impact Assessment, Analyst Sign-Off, Report)     |
|  ├── Asset & Identity Profiling (Endpoints & Accounts Inventory with Dynamic Risk Scoring)       |
|  ├── Threat Intelligence (Global Feed Indicators, Interactive Reputation Lookup)                |
|  └── Forensic Reports (Printable Dossier, Markdown & HTML Export)                                |
+-----------------------------------+--------------------------------------------------------------+
                                    | REST API (JWT Bearer Token / Role-Based Access Control)
+-----------------------------------v--------------------------------------------------------------+
|  SERVER (Node.js + Express.js + Mongoose)                                                        |
|  ├── Controllers (Auth, Logs, Events, Rules, Alerts, Cases, IOCs, Assets, Timeline, Reports)    |
|  ├── Forensic Engine Services                                                                    |
|  │   ├── parserService.js          (CSV / JSON / Syslog / Text Regex / Key-Value Extraction)     |
|  │   ├── normalizationService.js   (Maps raw logs to Common Event Model - CEM)                   |
|  │   ├── detectionService.js       (Multi-event thresholding, sequence & credential spray logic) |
|  │   ├── iocExtractionService.js   (Regex extraction of IPs, Domains, URLs, SHA256/MD5, Emails)  |
|  │   ├── threatIntelService.js     (Automated enrichment against Threat Feeds)                   |
|  │   ├── profilingService.js       (Dynamic Endpoint & Account risk calculations)                |
|  │   ├── correlationService.js     (Bi-directional host-user-IP entity graph linking)            |
|  │   ├── attackChainService.js     (Automatic kill-chain inference across 10 MITRE stages)       |
|  │   ├── timelineService.js        (Chronological multi-source forensic sequencing)              |
|  │   └── reportService.js          (Official incident report generation & Markdown/HTML export)  |
|  ├── Security Middleware (Helmet, CORS, Express-Rate-Limit, Zod Request Validators)             |
|  └── Logging & Auditing (Winston multi-transport file & console logging)                         |
+-----------------------------------+--------------------------------------------------------------+
                                    | Native Driver / Mongoose ODM
+-----------------------------------v--------------------------------------------------------------+
|  DATABASE (MongoDB)                                                                              |
|  ├── Collections: Users, Events, DetectionRules, Alerts, Cases, IOCs, Endpoints, Accounts,       |
|  │                Evidence, TimelineEntries, AttackChains, ThreatIntel, ImpactAssessments,       |
|  │                Reports                                                                        |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Forensic Investigation Lifecycle (14 Forensic Stages)

AEGIS implements all 14 core stages of modern digital forensics and incident response:

| Stage # | Stage Name | Capabilities & Implementation |
|---|---|---|
| **1** | **Ingestion** | Accepts `.csv`, `.json`, `.txt`, `.log` files via Multer (up to 25MB). Auto-detects structure without pre-configuration. |
| **2** | **Parsing** | Handles CSV headers, JSON arrays/line-delimited records, Syslog BSD timestamps, Windows Event Log text, and key-value tokens (`src=`, `dst=`). |
| **3** | **Normalization** | Maps disparate feeds into the standardized **Common Event Model (CEM)**: `timestamp`, `source`, `host`, `username`, `sourceIP`, `destinationIP`, `eventType`, `action`, `status`, `severity`, `techniqueId`, and `raw`. |
| **4** | **Detection Engine** | Evaluates enabled detection rules across incoming batches. Supports threshold windowing and sequence patterns (e.g. failed login followed by success). |
| **5** | **Alert Generation** | Produces deduplicated alerts (`ALT-YYYY-####`) tagged with MITRE ATT&CK technique IDs, severity, and matching events. |
| **6** | **Case Management** | 1-click promotion of Alerts into investigative Cases (`CASE-YYYY-####`) with automated entity linking and phase tracking (`ingestion` &rarr; `analysis` &rarr; `investigation` &rarr; `forensics` &rarr; `impact` &rarr; `review` &rarr; `closed`). |
| **7** | **Timeline Sequencing** | Chronologically reconstructs security events, alerts, and manual analyst annotations with category color-coding. |
| **8** | **IOC Extraction** | Regex extraction of IPv4 addresses, domain names, URLs, MD5/SHA1/SHA256 hashes, and email addresses with occurrence tracking. |
| **9** | **Asset Profiling** | Maintains endpoint inventories (`WS01-FIN`, `DC01-ROOT`), open ports, observed IPs, operating systems, and calculated risk scores (0–100). |
| **10** | **Identity Profiling** | Profiles user accounts, privilege tiers (`standard`, `admin`, `domain_admin`, `service`), authentication failure rates, and compromise status. |
| **11** | **Attack Chain Mapping** | Reconstructs the adversary kill chain across 10 MITRE ATT&CK stages (Initial Access &rarr; Execution &rarr; Persistence &rarr; Privilege Escalation &rarr; Defense Evasion &rarr; Credential Access &rarr; Discovery &rarr; Lateral Movement &rarr; Collection &rarr; Exfiltration). |
| **12** | **Evidence Locker** | Digital evidence repository with cryptographic checksum verification (SHA256/MD5), chain-of-custody metadata, and analyst validation flags. |
| **13** | **Impact Assessment** | Clear separation between auto-detected telemetry indicators and analyst-assessed damage (data exposure, malware strains, business disruption). |
| **14** | **Analyst Review & Reporting** | Mandatory forensic checklist verification, findings summary, and instant export of official incident reports in Markdown and printable HTML. |

---

## 3. Default Credentials

The platform is seeded with 3 pre-configured role personas:

| Role | Username | Password | Permissions |
|---|---|---|---|
| **Admin** | `admin` | `admin123` | Full access: User management, detection rule authoring, alert triage, investigation, evidence, reports |
| **Analyst** | `analyst` | `analyst123` | Operations: Ingest logs, triage alerts, manage cases, update timeline, evidence validation, reports |
| **Viewer** | `viewer` | `viewer123` | Read-only access: Executive dashboards, telemetry explorer, case reviews, report exports |

*Tip: Quick 1-click credential selector buttons are built directly into the Login portal.*

---

## 4. Quick Start & Setup Guide

### Prerequisites
- **Node.js**: v18+ (tested on Node v20 & v24)
- **MongoDB**: Local MongoDB instance (`mongodb://127.0.0.1:27017/soc_platform`) or any remote MongoDB connection string.

### Step 1: Clone and Configure Environment
```bash
# Clone the repository
git clone <repo-url> soc-platform
cd soc-platform

# Verify or edit server environment configuration
# server/.env is automatically pre-configured with:
PORT=5000
NODE_ENV=development
MONGO_URI=mongodb://127.0.0.1:27017/soc_platform
JWT_SECRET=soc_forensic_platform_super_secret_jwt_key_2026!
CLIENT_ORIGIN=http://localhost:5173
UPLOAD_DIR=./uploads
```

### Step 2: Install Dependencies
```bash
# Install server dependencies
cd server
npm install

# Install client dependencies
cd ../client
npm install
```

### Step 3: Seed Sample Telemetry & Intrusion Dataset
```bash
cd ../server
npm run seed
```
*The seed command populates the 3 users, 7 detection rules, 12 threat intelligence feeds, 240+ realistic multi-stage intrusion events, alerts, and a fully articulated demo case (`CASE-2026-0001`).*

### Step 4: Run the Development Servers
In Terminal 1 (Backend API):
```bash
cd server
npm run dev
# Express API listens on http://localhost:5000
```

In Terminal 2 (Frontend Client):
```bash
cd client
npm run dev
# Vite server resolves at http://localhost:5173
```

---

## 5. API Reference Summary

### Authentication (`/api/auth`)
- `POST /api/auth/register` — Register a new user account (Zod validated).
- `POST /api/auth/login` — Authenticate and receive a 7-day JWT token.
- `GET /api/auth/me` — Verify token and retrieve current user session.

### Log Ingestion & Normalization (`/api/logs`)
- `POST /api/logs/upload` — Multipart upload (`.csv`, `.json`, `.txt`, `.log`). Normalizes events, runs IOC extraction, threat intel lookup, profiling, and detection rules.
- `POST /api/logs/parse-preview` — Dry-run preview of the first 5 records without database commit.

### Event Telemetry (`/api/events`)
- `GET /api/events` — Query Common Event Model records with filters (`source`, `eventType`, `status`, `severity`, `host`, `username`, `sourceIP`, `dateFrom`, `dateTo`, `search`) + pagination.
- `GET /api/events/:id` — Inspect individual event metadata and raw payload.

### Detection Rules (`/api/rules`)
- `GET /api/rules` — Retrieve all detection rules.
- `POST /api/rules` — Deploy a new detection rule (Admin only).
- `PATCH /api/rules/:id` — Update rule parameters or toggle status (`enabled: true/false`).
- `DELETE /api/rules/:id` — Remove a detection rule (Admin only).
- `POST /api/rules/run-all` — Manually trigger detection engine across recent events.

### Alerts & Triage (`/api/alerts`)
- `GET /api/alerts` — List alerts with status and severity filters.
- `GET /api/alerts/:id` — Inspect alert with populated matching events.
- `PATCH /api/alerts/:id` — Update alert status (`new`, `assigned`, `investigating`, `resolved`, `dismissed`).
- `POST /api/alerts/:id/create-case` — Automatically scaffold a Case, link correlated events, extract IOCs, and build initial attack chain.

### Forensic Cases (`/api/cases`)
- `GET /api/cases` — List cases with priority and phase filters.
- `POST /api/cases` — Create a manual case dossier.
- `GET /api/cases/:id` — Comprehensive case dossier (all related assets, events, IOCs, evidence).
- `PATCH /api/cases/:id` — Update case metadata, status, or phase. *(Closed status requires review saved)*.
- `POST /api/cases/:id/add-events` — Link additional events and synchronize timeline.
- `DELETE /api/cases/:id/events/:eventId` — Unlink an event from the case.
- `GET /api/cases/:id/evidence` — List digital evidence artifacts.
- `POST /api/cases/:id/evidence` — Secure an evidence file artifact with SHA256 checksum.
- `PATCH /api/cases/:id/evidence/:evidenceId/validate` — Toggle analyst verification flag.

### Timeline, Attack Chain, Impact & Review
- `GET /api/timeline/case/:caseId` — Chronological timeline with category filtering.
- `POST /api/timeline/case/:caseId` — Add an analyst timeline annotation.
- `GET /api/attack-chain/case/:caseId` — Retrieve MITRE ATT&CK stage progression.
- `PATCH /api/attack-chain/case/:caseId` — Update attack chain stages and notes.
- `GET /api/impact/case/:caseId` — Retrieve damage assessment data.
- `PUT /api/impact/case/:caseId` — Update impact metrics and analyst breach notes.
- `POST /api/review/case/:caseId` — Save formal analyst review and verification checklist.

### Reports & Dashboard
- `GET /api/reports` — List all compiled forensic reports.
- `GET /api/reports/case/:caseId` — Retrieve report for a case.
- `POST /api/reports/case/:caseId/generate` — Compile official forensic report.
- `GET /api/reports/case/:caseId/export?format=md|html` — Download report in Markdown or HTML.
- `GET /api/dashboard/summary` — High-level SOC metrics, 24h event volume, threat distribution.

---

## 6. End-to-End Analyst Walkthrough

1. **Sign In**: Navigate to `http://localhost:5173/login` and click the **Analyst** preset button (`analyst` / `analyst123`).
2. **Review Command Center**: On the **Dashboard**, observe the active threat incident banner, KPI stat cards, and 24h telemetry curve.
3. **Ingest Security Logs**: Navigate to **Log Ingestion** (`/logs`). Drag and drop a security log file, or click **Load Multi-Stage APT Sample (CSV)** to instantly ingest sample telemetry.
4. **Inspect Normalized Telemetry**: Go to **Event Telemetry** (`/events`) to view records normalized into the Common Event Model. Click on any event to inspect its raw payload and MITRE tags.
5. **Triage Alerts**: Open **Alerts Queue** (`/alerts`). Review triggered detections such as *Multiple Failed Logins* or *LSASS Memory Dumping*. Click **Create Case** on any alert to initiate an investigation.
6. **Investigate in Forensic Workspace**: In the **Case Workspace** (`/cases/:id`), navigate across the 11 tabs:
   - **Timeline**: Trace the attacker's actions chronologically.
   - **Attack Chain**: Inspect the reconstructed MITRE ATT&CK sequence.
   - **Evidence Locker**: View secure artifacts, verify cryptographic hashes, and toggle analyst validation.
   - **Damage Assessment**: Document compromised data and business disruption.
   - **Analyst Review**: Check off validation items, enter findings, and click **Save Review Findings**.
   - **Final Report**: Compile the official report and click **Download Markdown** or **HTML Print View**.
7. **AI Natural Language to SQL Assistant**: In **Threat Intelligence** (`/threat-intel`), ask plain-English questions (*"Which IP address generated the highest number of events?"*, *"Which user has the highest number of failed login attempts?"*). Review the schema-aware generated SQL, click **Insert Query into Console** to edit, or **Run Query** to execute immediately against live MongoDB telemetry and export results.

---

## 7. AI Natural Language to SQL Assistant

Integrated directly into the **Threat Intelligence** module, the AI Assistant enables SOC analysts to query enterprise telemetry and global threat intelligence using plain English:

- **Schema Discovery**: Automatic inspection of queryable collections (`events`, `alerts`, `indicators`, `threat_intel`, `cases`), permitted columns, data types, timestamps, and indexes. Zero hallucinations.
- **Dual-Engine Architecture**: Configurable external LLM provider (`GEMINI_API_KEY`, `OPENAI_API_KEY`) with automatic fallback to a built-in deterministic SOC NLP engine.
- **Supported SQL Dialect**: Read-only `SELECT`, `WHERE`, `AND`/`OR`, `IN`, `LIKE`, `IS NULL`/`IS NOT NULL`, `COUNT(*)`, `COUNT(DISTINCT)`, `GROUP BY`, `HAVING`, `ORDER BY`, `LIMIT`, aggregations (`AVG`, `SUM`, `MIN`, `MAX`), and automated `Date` literal parsing.
- **Contextual Follow-Ups**: Remembers conversation context for iterative investigation (*"Show only the failed events"*, *"Filter to the last 24 hours"*, *"Now show the top 5"*).
- **One-Click Execution**: Direct **Run Query** execution against live database with integrated results table and CSV/JSON export, plus **Insert Query into Console** for manual review and editing.

---

## 8. OWASP Web & API Security Integrity

The platform incorporates enterprise-grade defense-in-depth protections verified by automated test suites:

- **Broken Access Control & BFLA (A01 / API1 / API5)**: Strict JWT authentication, RBAC authorization, role escalation defense on registration, and direct `/uploads` traversal shields.
- **Cryptographic Failures (A02 / API2)**: Minimum 32-character JWT secrets, bcrypt hashing with salt rounds = 10, cryptographic token signature verification.
- **Injection Immunity (A03 / API1 / API10)**: NoSQL sanitization via `express-mongo-sanitize`, SQL allowlisting blocking destructive keywords (`DROP`, `DELETE`, `UPDATE`, `INSERT`), ReDoS protection via `escapeRegex`, and stored XSS entity encoding.
- **Mass Assignment Defense (API3)**: Strict update field allowlists across all asset, alert, and account controllers.
- **Resource Consumption Caps (API4)**: Global rate limiter (2,000 req / 15m), SQL query row limits (max 500), pagination caps (max 1,000), and query execution timeouts (`maxTimeMS: 5000`).
- **Security Logging & Monitoring (A09)**: Structured Winston audit logs recording all authentication events, SQL queries, AI generations, and administrative actions in `logs/audit.log`.

Automated test suites:
```bash
node test_full_owasp_audit.js       # 21/21 OWASP Top 10 & API Security checks pass
node test_e2e_ai_sql_api.js         # 14/14 AI NL-to-SQL core questions pass
node test_rapid_lookup_and_sql.js   # 15/15 rapid lookup & SQL queries pass
node verify.js                       # 10/10 end-to-end platform workflows pass
```

---

## 9. Deploying to Vercel

The application is structured for 1-click deployment on [Vercel](https://vercel.com):
- **Frontend**: Built with Vite into `client/dist`, served globally with client-side SPA routing (`/(.*)` -> `/index.html`).
- **Backend**: Express API served via Vercel Serverless Function (`api/index.js` or `server/api/index.js`) routed seamlessly through `/api/(.*)`.
- **Hybrid Bridge**: Fully supports deployment whether Vercel's **Root Directory** is configured as `./` (repository root) or `server`!

### Step 1: Import Project to Vercel
1. Push this repository to GitHub or GitLab.
2. In the Vercel dashboard, click **"Add New..." -> "Project"** and import the repository.
3. **Root Directory**:
   - **Recommended**: Leave the Root Directory as `./` (default repository root).
   - **Alternative**: If you configured Root Directory as `server`, the built-in bridge (`server/client/package.json` + `server/vercel.json`) automatically routes and builds the client and API seamlessly.
4. **Build Settings**:
   - Leave the default settings or let `vercel.json` run `node scripts/build.js` / `npm run build`.

### Step 2: Configure Environment Variables in Vercel
In the Vercel project settings under **Environment Variables**, add:
- `MONGO_URI`: Your MongoDB Atlas connection URI (e.g., `mongodb+srv://user:pass@cluster0.mongodb.net/soc_platform?retryWrites=true&w=majority`).
- `JWT_SECRET`: Secret key for JWT tokens (at least 32 characters, e.g., `soc_forensic_platform_super_secret_jwt_key_2026_at_least_32_chars!`).
- `NODE_ENV`: `production`
- *(Optional)* `GEMINI_API_KEY`: Google Gemini API key if using cloud AI for the NL-to-SQL assistant.

### Step 3: Deploy
Click **Deploy**. Vercel will:
1. Prepare dependencies.
2. Run `scripts/build.js` to compile the Vite React frontend and mirror artifacts to distribution targets.
3. Package the Express API as an optimized serverless function.


