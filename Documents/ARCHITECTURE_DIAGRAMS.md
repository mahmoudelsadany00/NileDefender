# NileDefender — Mermaid Diagrams

All diagrams from the full project documentation, ready to use in any Mermaid-compatible renderer.

---

## 1. Architecture Diagram

```mermaid
graph TB
    subgraph Frontend["React + Vite Frontend (port 5173 dev / built into dist/)"]
        UI["🖥️ React SPA (App.jsx)"]
        WSC["🔌 Socket.IO Client"]
        API_SVC["📡 API Service Layer (api.js)"]
        THEME["🎨 Theme System (useTheme.jsx)"]
    end

    subgraph Backend ["Flask + SocketIO Backend (port 5000)"]
        API["🌐 REST API Routes"]
        WS["🔌 WebSocket (Socket.IO)"]
        BG_REMOTE["🧵 run_scan_background()"]
        BG_LOCAL["🧵 run_local_scan_background()"]
        BG_VULN["🧵 run_vuln_scan_background()"]
        AI_RPT["🤖 ai_report.py — AI PDF Generator"]
        DOCKER_URL["🐳 URL Normalization Layer"]
    end

    subgraph Recon["Recon Modules"]
        RW["📋 recon_workflow.py"]
        SE["🔍 subdomain_enum.py"]
        UC["🕷️ url_crawler.py"]
        LC["🖥️ local_crawler.py"]
    end

    subgraph Scanners["Vulnerability Scanner Modules"]
        VW["⚡ vuln_workflow.py"]
        SQLI["💉 scanners/sqli.py (sqlmap)"]
        XSS["✨ scanners/xss.py (dalfox)"]
        PT["📂 scanners/PTVuln.py"]
        HTMLI["🏷️ scanners/htmli.py"]
        CMDI["💻 scanners/Command_Injection.py"]
    end

    subgraph N8N_AI["n8n AI Workflow Engine (port 5677)"]
        WEBHOOK["📨 Webhook Trigger"]
        FILTER["⚙️ JS Endpoint Filter"]
        AGENT["🤖 AI Agent — GPT-4o-mini"]
        FETCH["🔗 fetch_url Tool"]
        SAVE_VULN["💾 save_vulnerability Tool"]
    end

    subgraph Data["Data Layer"]
        DB["📊 database.py — ORM Models"]
        SQLite[("💾 niledefender.db")]
    end

    subgraph External["External Tools"]
        HTTPX["⚡ httpx-pd"]
        SELENIUM["🦊 Firefox + GeckoDriver"]
        OSINT["🌍 crt.sh / HackerTarget / AlienVault / etc."]
        WAYBACK["📜 Wayback Machine"]
    end

    UI --> API_SVC
    UI --> WSC
    API_SVC -->|"REST /api/*"| API
    WSC <-->|"WebSocket"| WS

    API --> BG_REMOTE
    API --> BG_LOCAL
    API --> BG_VULN
    API --> AI_RPT
    API --> DOCKER_URL

    BG_REMOTE --> RW
    BG_LOCAL --> LC
    BG_VULN --> VW

    RW --> SE
    RW --> UC
    SE --> OSINT
    SE --> HTTPX
    UC --> WAYBACK
    LC --> SELENIUM

    VW --> SQLI
    VW --> XSS
    VW --> PT
    VW --> HTMLI
    VW --> CMDI
    VW --> LC
    VW -->|"POST /webhook/idor"| WEBHOOK

    WEBHOOK --> FILTER
    FILTER --> AGENT
    AGENT --> FETCH
    AGENT --> SAVE_VULN
    SAVE_VULN -->|"POST /api/scans/:id/vulnerabilities"| API
    N8N_AI -->|"POST /api/scans/:id/complete"| API

    BG_REMOTE --> DB
    BG_LOCAL --> DB
    BG_VULN --> DB
    SQLI --> DB
    XSS --> DB
    PT --> DB
    HTMLI --> DB
    CMDI --> DB
    DB --> SQLite

    classDef frontend fill:#3498db,stroke:#2980b9,color:#fff
    classDef backend fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef recon fill:#1abc9c,stroke:#16a085,color:#fff
    classDef scanner fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef n8n fill:#e67e22,stroke:#d35400,color:#fff
    classDef data fill:#2ecc71,stroke:#27ae60,color:#fff
    classDef external fill:#f39c12,stroke:#e67e22,color:#fff

    class UI,WSC,API_SVC,THEME frontend
    class API,WS,BG_REMOTE,BG_LOCAL,BG_VULN,AI_RPT,DOCKER_URL backend
    class RW,SE,UC,LC recon
    class VW,SQLI,XSS,PT,HTMLI,CMDI scanner
    class WEBHOOK,FILTER,AGENT,FETCH,SAVE_VULN n8n
    class DB,SQLite data
    class HTTPX,SELENIUM,OSINT,WAYBACK external
```

---

## 2. Database ER Diagram

```mermaid
erDiagram
    scan_history {
        int id PK
        string domain
        datetime scan_date
        string scan_type
        string status
    }

    subdomains {
        int id PK
        int scan_id FK
        string subdomain
        int is_alive
        int status_code
        string title
    }

    endpoints {
        int id PK
        int scan_id FK
        text url
        string method
        json parameters
        json body_params
        json extra_headers
        string source
        int has_parameters
        json form_details
        json param_types
    }

    vulnerabilities {
        int id PK
        int scan_id FK
        string vulnerability_type
        string severity
        text url
        string method
        string parameter
        text payload
        text evidence
        text vulnerability_data
        datetime discovered_at
    }

    scan_history ||--o{ subdomains : has
    scan_history ||--o{ endpoints : has
    scan_history ||--o{ vulnerabilities : has
```

---

## 3. Recon Workflow Phases

```mermaid
flowchart LR
    A["🔍 Phase 1: Subdomain Enumeration"] --> B["✅ Phase 2: Alive Checking"]
    B --> C["🕷️ Phase 3: URL Crawling"]
    C --> D["⚙️ Phase 4: Parameter Extraction"]
    D --> E["💾 Phase 5: Save to Database"]

    classDef phase1 fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef phase2 fill:#e67e22,stroke:#d35400,color:#fff
    classDef phase3 fill:#f39c12,stroke:#e67e22,color:#fff
    classDef phase4 fill:#3498db,stroke:#2980b9,color:#fff
    classDef phase5 fill:#2ecc71,stroke:#27ae60,color:#fff

    class A phase1
    class B phase2
    class C phase3
    class D phase4
    class E phase5
```

---

## 4. URL Crawling Strategy (Remote)

```mermaid
flowchart TB
    A["🌐 Alive URLs"] --> B["📜 Wayback Machine (Passive)"]
    A --> C["🕷️ Active Page Crawling"]
    A --> D["📂 Common Paths Check"]
    B --> E["🔗 Discovered URLs"]
    C --> E
    D --> E
    E --> F["⚙️ Extract Parameters (GET)"]
    E --> G["📝 Extract Forms (GET + POST)"]
    F --> H["💾 Save endpoints to DB"]
    G --> H

    classDef source fill:#3498db,stroke:#2980b9,color:#fff
    classDef passive fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef active fill:#e67e22,stroke:#d35400,color:#fff
    classDef discovered fill:#1abc9c,stroke:#16a085,color:#fff
    classDef extract fill:#f39c12,stroke:#e67e22,color:#fff
    classDef save fill:#2ecc71,stroke:#27ae60,color:#fff

    class A source
    class B passive
    class C active
    class D active
    class E discovered
    class F,G extract
    class H save
```

---

## 5. Local Crawler Flow

```mermaid
flowchart TB
    A["🚀 Start: Navigate to base URL"] --> B{"🔐 Login form detected?"}
    B -->|Yes| C["🔑 Try known credentials"]
    B -->|No| D["➡️ Continue"]
    C --> D
    D --> E["📋 Extract dropdown/navigation pages"]
    E --> F["🔄 BFS crawl all pages"]
    F --> G["📄 For each page:"]
    G --> H["🔗 Extract links (href, JS, iframes)"]
    G --> I["📝 Extract forms (GET + POST)"]
    G --> J["📋 Extract select/option URLs"]
    H --> F
    F --> K["🍪 Export cookies to all endpoints"]
    K --> L["✅ Return endpoint list"]

    classDef start fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef decision fill:#f39c12,stroke:#e67e22,color:#fff
    classDef auth fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef crawl fill:#3498db,stroke:#2980b9,color:#fff
    classDef extract fill:#1abc9c,stroke:#16a085,color:#fff
    classDef result fill:#2ecc71,stroke:#27ae60,color:#fff
    classDef flow fill:#e67e22,stroke:#d35400,color:#fff

    class A start
    class B decision
    class C auth
    class D flow
    class E,F,G crawl
    class H,I,J extract
    class K flow
    class L result
```

---

## 6. Remote Domain Scan — Sequence Diagram

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'actorBkg': '#3498db', 'actorTextColor': '#fff', 'actorBorder': '#2980b9', 'signalColor': '#e67e22', 'signalTextColor': '#2c3e50', 'noteBkgColor': '#f39c12', 'noteTextColor': '#fff', 'noteBorderColor': '#e67e22', 'activationBkgColor': '#1abc9c', 'activationBorderColor': '#16a085', 'sequenceNumberColor': '#fff', 'background': '#1a1a2e'}}}%%
sequenceDiagram
    participant User as 🖥️ React SPA
    participant Server as ⚙️ server.py
    participant RW as 📋 recon_workflow.py
    participant SE as 🔍 subdomain_enum.py
    participant UC as 🕷️ url_crawler.py
    participant DB as 💾 database.py

    User->>Server: POST /api/scans {domain: "example.com"}
    Server->>DB: create_scan("example.com")
    Server-->>User: {scan_id: 1, status: "running"}
    Server->>Server: Thread → run_scan_background()

    Server->>RW: ReconWorkflow("example.com").run()
    RW->>SE: SubdomainEnumerator.run_passive_recon()
    SE-->>RW: subdomains found
    RW->>SE: SubdomainEnumerator.check_alive_subdomains()
    SE-->>Server: on_alive_found callback → save_subdomain()
    Server-->>User: WebSocket: "Found alive: sub.example.com"

    RW->>UC: URLCrawler(alive_urls).crawl_urls()
    UC-->>Server: on_endpoint_found callback → save_endpoint()
    Server-->>User: WebSocket: "Found endpoint: /login POST"

    Server->>DB: update_scan_status("completed")
    Server-->>User: WebSocket: "scan_completed"
```

---

## 7. Local Target Scan — Sequence Diagram

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'actorBkg': '#e74c3c', 'actorTextColor': '#fff', 'actorBorder': '#c0392b', 'signalColor': '#9b59b6', 'signalTextColor': '#2c3e50', 'noteBkgColor': '#e67e22', 'noteTextColor': '#fff', 'noteBorderColor': '#d35400', 'activationBkgColor': '#1abc9c', 'activationBorderColor': '#16a085', 'background': '#1a1a2e'}}}%%
sequenceDiagram
    participant User as 🖥️ React SPA
    participant Server as ⚙️ server.py
    participant LC as 🖥️ local_crawler.py
    participant DB as 💾 database.py

    User->>Server: POST /api/scans {domain: "http://localhost/app/"}
    Server->>Server: is_local_target() → True
    Server->>DB: create_scan("localhost", type="local-crawl")
    Server-->>User: {scan_id: 2, status: "running"}
    Server->>Server: Thread → run_local_scan_background()

    Note over Server: 🐳 Docker URL Translation applied if RUNNING_IN_DOCKER=1

    Server->>LC: LocalCrawler(base_url).crawl()
    LC->>LC: Detect login → try credentials
    LC->>LC: Extract dropdown/navigation pages
    LC->>LC: BFS crawl all pages
    LC-->>Server: on_endpoint_found callback → save_endpoint()
    Server-->>User: WebSocket: progress updates (URLs normalized to localhost)

    Server->>DB: update_scan_status("completed")
    Server-->>User: WebSocket: "scan_completed"
```

---

## 8. Subdomain Enumeration Strategy (Detailed)

```mermaid
flowchart TB
    A["🎯 Target Domain (e.g. example.com)"] --> B{"🔀 Scan Mode?"}

    B -->|Passive| C["🔍 Passive Recon (6 OSINT Sources)"]
    B -->|Active| D["⚡ Active Recon (DNS Brute-force)"]
    B -->|All| C
    B -->|All| D

    subgraph Passive["Passive Recon — No API Keys Required"]
        C --> C1["🔒 crt.sh (Certificate Transparency)"]
        C --> C2["🎯 HackerTarget API"]
        C --> C3["☁️ ThreatCrowd API"]
        C --> C4["👽 AlienVault OTX"]
    end

    subgraph PassiveKeyed["Passive Recon — API Key Required"]
        C --> C5["🛡️ VirusTotal API 🔑"]
        C --> C6["🔐 SecurityTrails API 🔑"]
    end

    subgraph Active["Active Recon — DNS Brute-force"]
        D --> D1{"📝 Custom wordlist provided?"}
        D1 -->|Yes| D2["📄 _dns_bruteforce_wordlist()"]
        D1 -->|No| D3["📋 _dns_bruteforce_default() (~100 prefixes)"]
        D2 --> D4["⚡ _dns_resolve_list() (Multi-threaded DNS)"]
        D3 --> D4
    end

    C1 --> E["📦 Potential Subdomains (deduplicated set)"]
    C2 --> E
    C3 --> E
    C4 --> E
    C5 --> E
    C6 --> E
    D4 --> E

    E --> F["✅ check_alive_subdomains()"]

    subgraph AliveCheck["Alive Checking"]
        F --> G{"⚡ httpx-pd available?"}
        G -->|Yes| H["🚀 _check_with_httpx() — Pipe subdomains to httpx-pd, parse JSON"]
        G -->|No| I["🔄 _fallback_alive_check() — Multi-threaded HTTP/HTTPS requests"]
        H --> J["✅ Alive Subdomains (URL + Status Code + Title)"]
        I --> J
    end

    J --> K["💾 on_alive_found callback → save to DB"]
    K --> L["🕷️ Pass alive URLs to URL Crawler"]

    classDef target fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef decision fill:#f39c12,stroke:#e67e22,color:#fff
    classDef passive fill:#3498db,stroke:#2980b9,color:#fff
    classDef active fill:#e67e22,stroke:#d35400,color:#fff
    classDef source fill:#1abc9c,stroke:#16a085,color:#fff
    classDef key fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef result fill:#2ecc71,stroke:#27ae60,color:#fff
    classDef collect fill:#34495e,stroke:#2c3e50,color:#fff

    class A target
    class B,D1,G decision
    class C,C1,C2,C3,C4 passive
    class C5,C6 key
    class D,D2,D3,D4 active
    class E collect
    class F,H,I source
    class J,K,L result
```

---

## 9. Subdomain Enumeration Strategy (Compact)

```mermaid
flowchart TB
    A["🎯 Target Domain"] --> P["🔍 Passive Recon"]
    A --> AR["⚡ Active Recon"]

    P --> C1["crt.sh"]
    P --> C2["HackerTarget"]
    P --> C3["ThreatCrowd"]
    P --> C4["AlienVault OTX"]
    P --> C5["VirusTotal 🔑"]
    P --> C6["SecurityTrails 🔑"]

    AR --> W{"Wordlist?"}
    W -->|Custom| BF1["DNS Brute-force (wordlist)"]
    W -->|Default| BF2["DNS Brute-force (~100 prefixes)"]
    BF1 --> DNS["Multi-threaded DNS Resolution"]
    BF2 --> DNS

    C1 & C2 & C3 & C4 & C5 & C6 --> SUBS["Potential Subdomains"]
    DNS --> SUBS

    SUBS --> ALIVE{"Alive Check"}
    ALIVE -->|Primary| HTTPX["httpx-pd (fast)"]
    ALIVE -->|Fallback| REQ["HTTP/HTTPS requests"]
    HTTPX & REQ --> RESULT["✅ Alive Subdomains"]

    classDef target fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef passive fill:#3498db,stroke:#2980b9,color:#fff
    classDef active fill:#e67e22,stroke:#d35400,color:#fff
    classDef source fill:#1abc9c,stroke:#16a085,color:#fff
    classDef key fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef result fill:#2ecc71,stroke:#27ae60,color:#fff
    classDef check fill:#f39c12,stroke:#e67e22,color:#fff

    class A target
    class P passive
    class AR active
    class C1,C2,C3,C4 source
    class C5,C6 key
    class BF1,BF2,DNS active
    class HTTPX,REQ check
    class RESULT result
    class SUBS passive
```

---

## 10. Server.py — Flask API & Background Scans

```mermaid
flowchart TB
    REQ["🌐 Incoming Request"] --> DETECT{"🔀 Target Type?"}
    DETECT -->|"Remote (example.com)"| REMOTE["🧵 Background Thread"]
    DETECT -->|"Local (localhost)"| LOCAL["🧵 Background Thread"]

    subgraph API["REST API Routes"]
        R1["GET /api/scans"]
        R2["POST /api/scans"]
        R3["GET /api/scans/:id"]
        R4["DELETE /api/scans/:id"]
        R5["DELETE /api/scans/all"]
        R6["GET /api/scans/search"]
        R7["GET /api/scans/:id/stats"]
        R8["GET /api/scans/:id/subdomains"]
        R9["GET /api/scans/:id/endpoints"]
        R10["GET /api/scans/:id/vulnerabilities"]
        R11["POST /api/scans/:id/vulnerabilities"]
        R12["POST /api/scans/:id/vulnscan"]
        R13["POST /api/vulnscan/start"]
        R14["POST /api/scans/:id/complete"]
        R15["POST /api/scans/:id/report"]
        R16["GET /api/dashboard/stats"]
        R17["GET /api/all/subdomains"]
        R18["GET /api/all/endpoints"]
        R19["GET /api/all/vulnerabilities"]
    end

    REMOTE --> SE["🔍 subdomain_enum.py"]
    REMOTE --> UC["🕷️ url_crawler.py"]
    LOCAL --> LC["🖥️ local_crawler.py"]

    subgraph VulnScan["Vulnerability Scanning"]
        VW["⚡ vuln_workflow.py"]
        VW --> SQLI["💉 sqli.py (sqlmap)"]
        VW --> XSS["✨ xss.py (dalfox)"]
        VW --> PT["📂 PTVuln.py"]
        VW --> HTMLI["🏷️ htmli.py"]
        VW --> CMDI["💻 Command_Injection.py"]
        VW -->|"POST /webhook/idor"| N8N["🤖 n8n AI Agent"]
    end

    R13 --> DETECT_V{"🔀 Vuln Target"}
    DETECT_V --> VW

    subgraph WS["WebSocket (Socket.IO)"]
        W1["🔌 connect"]
        W2["📡 join_scan"]
        W3["📊 scan_update →"]
        W4["✅ scan_completed →"]
        W5["🛡️ vulnscan_completed →"]
        W6["❌ scan_error →"]
    end

    SE & UC & LC -->|"Callbacks"| DB["💾 Database (SQLite)"]
    SQLI & XSS & PT & HTMLI & CMDI -->|"Save vulns"| DB
    SE & UC & LC -->|"Progress"| W3
    VW -->|"Progress"| W3
    W3 -->|"Real-time"| UI["🖥️ React SPA"]
    API -->|"JSON"| UI
    R2 --> DETECT

    subgraph Docker["🐳 Docker URL Normalization"]
        DT["localhost → host.docker.internal (outgoing)"]
        DR["host.docker.internal → localhost (for DB/UI)"]
    end

    classDef api fill:#3498db,stroke:#2980b9,color:#fff
    classDef ws fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef module fill:#1abc9c,stroke:#16a085,color:#fff
    classDef db fill:#2ecc71,stroke:#27ae60,color:#fff
    classDef thread fill:#e67e22,stroke:#d35400,color:#fff
    classDef ui fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef req fill:#34495e,stroke:#2c3e50,color:#fff
    classDef vuln fill:#c0392b,stroke:#922b21,color:#fff
    classDef docker fill:#f39c12,stroke:#e67e22,color:#fff
    classDef decision fill:#f39c12,stroke:#e67e22,color:#fff

    class R1,R2,R3,R4,R5,R6,R7,R8,R9,R10,R11,R12,R13,R14,R15,R16,R17,R18,R19 api
    class W1,W2,W3,W4,W5,W6 ws
    class SE,UC,LC module
    class DB db
    class REMOTE,LOCAL thread
    class UI ui
    class REQ req
    class SQLI,XSS,PT,HTMLI,CMDI,N8N vuln
    class DT,DR docker
    class DETECT,DETECT_V decision
```

---

## 11. Database.py — Data Layer Operations

```mermaid
flowchart LR
    subgraph Callers["Who Writes"]
        S["⚙️ server.py"]
        RW["📋 recon_workflow.py"]
        VW["⚡ vuln_workflow.py"]
        LC["🖥️ local_crawler.py"]
        SQLI["💉 sqli.py"]
        XSS["✨ xss.py"]
        PT_S["📂 PTVuln.py"]
        HTMLI["🏷️ htmli.py"]
        CMDI["💻 Command_Injection.py"]
    end

    subgraph CRUD["database.py CRUD Operations"]
        direction TB
        subgraph Scan["🔄 Scan Management"]
            C1["create_scan"]
            C2["update_scan_status"]
            C3["delete_scan (cascade)"]
        end
        subgraph Sub["🌐 Subdomains"]
            C4["save_subdomain (upsert)"]
        end
        subgraph Ep["🔗 Endpoints"]
            C5["save_endpoint (upsert)"]
        end
        subgraph Vuln["⚠️ Vulnerabilities"]
            C6["save_vulnerability"]
        end
    end

    subgraph Queries["Who Reads"]
        direction TB
        Q1["get_all_scans"]
        Q2["get_scan_by_id"]
        Q3["get_subdomains"]
        Q4["get_endpoints"]
        Q5["get_vulnerabilities"]
        Q6["get_vulnerability_stats"]
        Q7["get_scan_results"]
    end

    S --> C1 & C2 & C3
    RW --> C4 & C5
    VW --> C6
    LC --> C5
    SQLI --> C6
    XSS --> C6
    PT_S --> C6
    HTMLI --> C6
    CMDI --> C6

    CRUD --> DB[("💾 niledefender.db")]
    DB --> Queries
    Queries --> S

    classDef caller fill:#e67e22,stroke:#d35400,color:#fff
    classDef write fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef read fill:#3498db,stroke:#2980b9,color:#fff
    classDef db fill:#2ecc71,stroke:#27ae60,color:#fff

    class S,RW,VW,LC,SQLI,XSS,PT_S,HTMLI,CMDI caller
    class C1,C2,C3,C4,C5,C6 write
    class Q1,Q2,Q3,Q4,Q5,Q6,Q7 read
    class DB db
```

---

## 12. Frontend — React SPA

```mermaid
flowchart TB
    subgraph Pages["📄 SPA Pages (React Router)"]
        P1["🏠 Dashboard"]
        P2["📋 Scans"]
        P3["🔎 ScanDetails"]
        P4["🌐 Subdomains"]
        P5["🔗 Endpoints"]
        P6["🛡️ Vulnerabilities"]
    end

    P1 -->|"View scan"| P3
    P2 -->|"View scan"| P3
    P1 & P2 -->|"New Scan"| MODAL["📝 NewScanModal"]

    subgraph Details["Scan Details Tabs"]
        T1["🌐 Subdomains Tab"]
        T2["🔗 Endpoints Tab"]
        T3["🛡️ Vulnerabilities Tab"]
    end

    P3 --> T1 & T2 & T3
    P3 -->|"Delete"| DEL["🗑️ DeleteModal"]
    P3 -->|"Generate Report"| REPORT["📄 AI PDF Report"]
    P3 -->|"Export"| EXPORT["📥 JSON/CSV Export"]

    subgraph Components["🧩 Shared Components"]
        SIDEBAR["📌 Sidebar.jsx"]
        STAT["📊 StatCard.jsx"]
        BADGE["🏷️ Badge.jsx"]
        THEME_SW["🎨 ThemeSwitcher.jsx"]
        NOTIF["🔔 Notification.jsx"]
    end

    subgraph JS["📡 api.js → API Service Layer"]
        A1["GET /api/dashboard/stats"]
        A2["GET /api/scans"]
        A3["POST /api/scans"]
        A4["GET /api/scans/:id"]
        A5["DELETE /api/scans/:id"]
        A6["POST /api/scans/:id/vulnscan"]
        A7["POST /api/vulnscan/start"]
        A8["POST /api/scans/:id/report"]
        A9["GET /api/all/subdomains"]
        A10["GET /api/all/endpoints"]
        A11["GET /api/all/vulnerabilities"]
    end

    P1 --> A1
    P2 --> A2
    MODAL -->|"Recon"| A3
    MODAL -->|"Vuln (new)"| A7
    MODAL -->|"Vuln (existing)"| A6
    P3 --> A4
    DEL -->|"Confirm"| A5
    REPORT --> A8
    P4 --> A9
    P5 --> A10
    P6 --> A11

    subgraph WSock["🔌 WebSocket (useSocket.js)"]
        W1["🔌 connect"]
        W2["📡 join_scan → subscribe to room"]
        W3["📊 scan_update → live progress"]
        W4["✅ scan_completed → recon done"]
        W5["🛡️ vulnscan_completed → vuln done"]
        W6["❌ scan_error → error handling"]
    end

    A3 -->|"Scan created"| W2
    W3 -->|"Progress messages"| P3
    W4 & W5 -->|"Scan complete"| TOAST["🔔 Notification Toast"]

    classDef page fill:#3498db,stroke:#2980b9,color:#fff
    classDef modal fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef tab fill:#1abc9c,stroke:#16a085,color:#fff
    classDef api fill:#e67e22,stroke:#d35400,color:#fff
    classDef ws fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef notify fill:#2ecc71,stroke:#27ae60,color:#fff
    classDef comp fill:#f39c12,stroke:#e67e22,color:#fff
    classDef action fill:#c0392b,stroke:#922b21,color:#fff

    class P1,P2,P3,P4,P5,P6 page
    class MODAL,DEL modal
    class T1,T2,T3 tab
    class A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11 api
    class W1,W2,W3,W4,W5,W6 ws
    class TOAST notify
    class SIDEBAR,STAT,BADGE,THEME_SW,NOTIF comp
    class REPORT,EXPORT action
```

---

## 13. Vulnerability Scan Flow

```mermaid
flowchart TD
    A["🚀 User: Start Vuln Scan"] --> B["⚡ VulnWorkflow"]
    B --> C{"📦 Endpoints exist?"}
    C -->|No| D["🔄 Auto-Recon: crawl target first"]
    C -->|Yes| E["📋 Load existing endpoints"]
    D --> E

    E --> F{"🏠 Local target?"}
    F -->|Yes| G["🔑 quick_login — get session cookie"]
    F -->|No| H["🌐 No auth needed"]

    G --> I["🛡️ Run Scanner Modules"]
    H --> I

    I --> I1["💉 SQLi Scanner — sqlmap"]
    I --> I2["✨ XSS Scanner — dalfox"]
    I --> I3["📂 Path Traversal Scanner — payload list"]
    I --> I4["🏷️ HTML Injection Scanner — reflection check"]
    I --> I5["💻 Command Injection Scanner — verbose/blind/OOB"]

    I1 --> J[("💾 Save vulnerabilities to DB")]
    I2 --> J
    I3 --> J
    I4 --> J
    I5 --> J

    J --> K{"🔀 Full scan mode?"}
    K -->|Yes| L["🤖 Trigger n8n IDOR Agent via webhook"]
    K -->|"No & IDOR selected"| L
    K -->|"No & IDOR not selected"| M["✅ Scan Status → completed"]
    L --> N["⏳ Status stays running — AI in progress"]
    N --> O{"📡 n8n calls /complete?"}
    O -->|Yes| P["✅ Scan Status → completed"]
    O -->|"Timeout 10min"| P
    M --> Q["📢 WebSocket: vulnscan_completed event"]
    P --> Q

    classDef start fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef workflow fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef decision fill:#f39c12,stroke:#e67e22,color:#fff
    classDef recon fill:#3498db,stroke:#2980b9,color:#fff
    classDef auth fill:#e67e22,stroke:#d35400,color:#fff
    classDef scanner fill:#c0392b,stroke:#922b21,color:#fff
    classDef save fill:#2ecc71,stroke:#27ae60,color:#fff
    classDef ai fill:#8e44ad,stroke:#6c3483,color:#fff
    classDef complete fill:#27ae60,stroke:#1e8449,color:#fff
    classDef waiting fill:#34495e,stroke:#2c3e50,color:#fff
    classDef event fill:#1abc9c,stroke:#16a085,color:#fff

    class A start
    class B workflow
    class C,F,K,O decision
    class D recon
    class E recon
    class G auth
    class H recon
    class I workflow
    class I1,I2,I3,I4,I5 scanner
    class J save
    class L ai
    class M,P complete
    class N waiting
    class Q event
```

---

## 14. n8n IDOR Agent Flow

```mermaid
flowchart TD
    A["⚡ VulnWorkflow triggers webhook"] -->|"POST scan_id + cookie"| B["📨 n8n Webhook Node"]
    B --> C["📡 Fetch endpoints from NileDefender API"]
    C -->|"GET /api/scans/:id/endpoints?docker=1"| D["⚙️ JS Filter: select IDOR-relevant endpoints"]
    D --> E{"🔀 IDOR targets found?"}
    E -->|No| F["✅ POST /complete → mark scan done"]
    E -->|Yes| G["🔄 Loop Over Items — one endpoint at a time"]
    G --> H["🤖 AI Agent: GPT-4o-mini"]
    H --> H1["1️⃣ Step 1: Context & Parameter Triage"]
    H1 --> H2["2️⃣ Step 2: Baseline fetch with session cookie"]
    H2 --> H3["3️⃣ Step 3: Modified fetch — change user/ID references"]
    H3 --> H4["4️⃣ Step 4: Compare responses — decision logic"]
    H4 --> I{"🛡️ Vulnerable?"}
    I -->|Yes| J["🚨 save_vulnerability tool → POST to NileDefender"]
    I -->|No| K["✅ Output DONE"]
    J --> K
    K --> G
    G -->|"All done"| L["📊 Aggregate results"]
    L --> F

    classDef trigger fill:#e67e22,stroke:#d35400,color:#fff
    classDef webhook fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef fetch fill:#3498db,stroke:#2980b9,color:#fff
    classDef filter fill:#1abc9c,stroke:#16a085,color:#fff
    classDef decision fill:#f39c12,stroke:#e67e22,color:#fff
    classDef loop fill:#34495e,stroke:#2c3e50,color:#fff
    classDef ai fill:#8e44ad,stroke:#6c3483,color:#fff
    classDef step fill:#3498db,stroke:#2980b9,color:#fff
    classDef vuln fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef done fill:#2ecc71,stroke:#27ae60,color:#fff
    classDef aggregate fill:#1abc9c,stroke:#16a085,color:#fff

    class A trigger
    class B webhook
    class C fetch
    class D filter
    class E,I decision
    class F,K done
    class G loop
    class H ai
    class H1,H2,H3,H4 step
    class J vuln
    class L aggregate
```

---

## 15. AI Report Generation Flow

```mermaid
flowchart LR
    A["🖱️ User clicks Generate Report"] --> B["📡 POST /api/scans/:id/report"]
    B --> C["💾 Read vulns from DB"]
    C --> D["🤖 Send to Groq LLM"]
    D --> E["📝 AI generates styled HTML report"]
    E --> F["📄 WeasyPrint: HTML → PDF bytes"]
    F --> G["📥 Stream PDF to browser download"]

    classDef user fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef api fill:#3498db,stroke:#2980b9,color:#fff
    classDef data fill:#2ecc71,stroke:#27ae60,color:#fff
    classDef ai fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef generate fill:#e67e22,stroke:#d35400,color:#fff
    classDef pdf fill:#f39c12,stroke:#e67e22,color:#fff
    classDef download fill:#1abc9c,stroke:#16a085,color:#fff

    class A user
    class B api
    class C data
    class D ai
    class E generate
    class F pdf
    class G download
```



---

## 17. Scan Status Lifecycle

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#3498db', 'primaryTextColor': '#fff', 'primaryBorderColor': '#2980b9', 'lineColor': '#e67e22', 'secondaryColor': '#2ecc71', 'tertiaryColor': '#e74c3c', 'background': '#1a1a2e'}}}%%
stateDiagram-v2
    [*] --> running : create_scan()
    running --> completed : scan finishes (no AI)
    running --> running : static scanners done, AI triggered
    running --> completed : AI agent calls /complete
    running --> completed : safety timeout (10 min)
    running --> failed : error / no results
    running --> cancelled : user cancels (delete)
    completed --> [*]
    failed --> [*]
    cancelled --> [*]
```
