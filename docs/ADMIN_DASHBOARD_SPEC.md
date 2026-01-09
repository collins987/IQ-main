# SentinelIQ Admin Dashboard - Technical Specification

**Document Version:** 1.0  
**Date:** January 9, 2026  
**Status:** Draft - Pending Review  
**Author:** Development Team  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Objectives & Goals](#2-objectives--goals)
3. [Dashboard Modules](#3-dashboard-modules)
4. [System Health Monitoring](#4-system-health-monitoring)
5. [User Management & Monitoring](#5-user-management--monitoring)
6. [Real-Time Activity Feed](#6-real-time-activity-feed)
7. [Risk & Fraud Analytics](#7-risk--fraud-analytics)
8. [Audit & Compliance](#8-audit--compliance)
9. [Technical Architecture](#9-technical-architecture)
10. [API Specifications](#10-api-specifications)
11. [Frontend Components](#11-frontend-components)
12. [Security Requirements](#12-security-requirements)
13. [Performance Requirements](#13-performance-requirements)
14. [Implementation Phases](#14-implementation-phases)
15. [Open Questions](#15-open-questions)

---

## 1. Executive Summary

### Purpose
The Admin Dashboard provides a centralized, real-time command center for administrators to monitor, manage, and respond to all activities within the SentinelIQ platform. It serves as the primary interface for:

- **System Health Monitoring** - Infrastructure status, service availability, performance metrics
- **User Oversight** - Login activity, user management, role administration
- **Risk Management** - Fraud alerts, risk scores, security incidents
- **Compliance** - Audit trails, access logs, regulatory reporting

### Target Users
- **Platform Administrators** - Full system access and configuration
- **Security Operations** - Incident response and threat monitoring
- **Compliance Officers** - Audit review and reporting (read-only subset)

### Key Value Propositions
1. Single pane of glass for entire platform operations
2. Real-time alerts and notifications
3. Rapid incident response capabilities
4. Comprehensive audit trail for compliance
5. Actionable insights through data visualization

---

## 2. Objectives & Goals

### Primary Objectives

| ID | Objective | Success Metric |
|----|-----------|----------------|
| O1 | Real-time visibility into system health | < 5 second data refresh |
| O2 | Instant awareness of security incidents | < 30 second alert latency |
| O3 | Complete user activity tracking | 100% login/action coverage |
| O4 | Rapid incident response | < 2 min from alert to action |
| O5 | Compliance audit readiness | Full audit trail accessibility |

### Non-Goals (Out of Scope for V1)
- [ ] Machine learning predictive analytics
- [ ] Custom dashboard builder
- [ ] Multi-tenant dashboard isolation
- [ ] Mobile native application
- [ ] White-label customization

---

## 3. Dashboard Modules

### 3.1 Module Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ADMIN DASHBOARD                                   │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   SYSTEM     │  │    USER      │  │    RISK      │  │   AUDIT      │ │
│  │   HEALTH     │  │   MONITOR    │  │   CENTER     │  │    LOGS      │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────────────────┤
│                     REAL-TIME ACTIVITY FEED                              │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────┐  ┌─────────────────────────────────┐   │
│  │     METRICS & CHARTS        │  │      ALERTS & NOTIFICATIONS     │   │
│  └─────────────────────────────┘  └─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Module Descriptions

| Module | Purpose | Update Frequency |
|--------|---------|------------------|
| **System Health** | Infrastructure monitoring, service status | Real-time (WebSocket) |
| **User Monitor** | Active sessions, login history, user management | Real-time + Polling |
| **Risk Center** | Fraud alerts, risk scores, security events | Real-time (WebSocket) |
| **Audit Logs** | Action history, compliance tracking | On-demand + Streaming |
| **Activity Feed** | Live stream of all system events | Real-time (WebSocket) |
| **Alerts Panel** | Critical notifications requiring attention | Real-time (Push) |

---

## 4. System Health Monitoring

### 4.1 Infrastructure Metrics

#### Service Status Dashboard
```
┌─────────────────────────────────────────────────────────────────┐
│ SERVICE STATUS                                    Last: 2s ago  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ● API Server         [████████████] 100%    Healthy           │
│  ● PostgreSQL         [████████████] 100%    Healthy           │
│  ● Redis              [████████████] 100%    Healthy           │
│  ● Kafka              [████████░░░░]  75%    Degraded          │
│  ● Vault              [████████████] 100%    Healthy           │
│  ● MinIO              [████████████] 100%    Healthy           │
│                                                                 │
│  Overall System Health: 95.8%                                   │
└─────────────────────────────────────────────────────────────────┘
```

#### Metrics to Display

| Category | Metric | Source | Alert Threshold |
|----------|--------|--------|-----------------|
| **API** | Request latency (p50, p95, p99) | Prometheus | p99 > 500ms |
| **API** | Requests per second | Prometheus | > 1000 RPS |
| **API** | Error rate (4xx, 5xx) | Prometheus | > 1% |
| **Database** | Active connections | PostgreSQL | > 80% pool |
| **Database** | Query latency | PostgreSQL | > 100ms avg |
| **Database** | Replication lag | PostgreSQL | > 1s |
| **Redis** | Memory usage | Redis INFO | > 80% |
| **Redis** | Connected clients | Redis INFO | > 500 |
| **Redis** | Stream lag | Redis | > 1000 msgs |
| **Kafka** | Consumer lag | Kafka metrics | > 10000 msgs |
| **Kafka** | Partition health | Kafka metrics | Any offline |
| **System** | CPU usage | Node exporter | > 80% |
| **System** | Memory usage | Node exporter | > 85% |
| **System** | Disk usage | Node exporter | > 90% |

### 4.2 Health Check Endpoints

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `/health` | Basic liveness | `{"status": "ok"}` |
| `/health/ready` | Readiness (all deps) | `{"status": "ready", "services": {...}}` |
| `/health/detailed` | Full diagnostic | Complete service status |
| `/metrics` | Prometheus metrics | Prometheus format |

### 4.3 Alerting Rules

```yaml
alerts:
  critical:
    - name: "API Down"
      condition: health_check_failed for 30s
      action: page_oncall
      
    - name: "Database Unreachable"
      condition: db_connection_failed for 10s
      action: page_oncall
      
    - name: "High Error Rate"
      condition: error_rate > 5% for 2m
      action: slack_alert + page_oncall

  warning:
    - name: "Elevated Latency"
      condition: p99_latency > 500ms for 5m
      action: slack_alert
      
    - name: "High Memory Usage"
      condition: memory_usage > 80% for 10m
      action: slack_alert
```

---

## 5. User Management & Monitoring

### 5.1 Active Sessions Panel

```
┌─────────────────────────────────────────────────────────────────┐
│ ACTIVE SESSIONS                                    Total: 147   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  User              Role      IP Address      Location   Since   │
│  ─────────────────────────────────────────────────────────────  │
│  john.doe@co.com   analyst   192.168.1.45    New York   2m ago  │
│  jane.smith@co.com admin     10.0.0.12       London     15m ago │
│  bob.wilson@co.com viewer    172.16.0.8      Sydney     1h ago  │
│  [+ 144 more...]                                                │
│                                                                 │
│  [View All Sessions]  [Export]  [Force Logout Selected]         │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 User Metrics

| Metric | Description | Visualization |
|--------|-------------|---------------|
| **Active Users** | Currently logged in | Counter + Trend |
| **Logins Today** | Total login count | Counter |
| **Failed Logins** | Authentication failures | Counter (red if high) |
| **New Registrations** | Users registered today | Counter |
| **Users by Role** | Distribution pie chart | Pie Chart |
| **Login Locations** | Geographic distribution | World Map |
| **Peak Hours** | Login activity over time | Line Chart |

### 5.3 User Details View

When clicking on a user, display:

```
┌─────────────────────────────────────────────────────────────────┐
│ USER DETAILS: John Doe                              [Actions ▼] │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Profile                          Security                      │
│  ────────────────────────         ────────────────────────      │
│  ID:        user-abc-123          Risk Score:    25/100 ●       │
│  Email:     john.doe@company.com  Status:        Active ✓       │
│  Role:      Analyst               Email Verified: Yes ✓         │
│  Org:       Acme Corp             2FA Enabled:    No ⚠          │
│  Created:   2025-06-15            Last Password:  30 days ago   │
│                                                                 │
│  Recent Activity                                                │
│  ────────────────────────────────────────────────────────────   │
│  • Logged in from 192.168.1.45 (New York) - 2 min ago           │
│  • Viewed user profile #456 - 15 min ago                        │
│  • Exported analytics report - 1 hour ago                       │
│  • Failed login attempt (wrong password) - 2 hours ago          │
│                                                                 │
│  [View Full Activity]  [View Audit Log]  [Edit User]            │
└─────────────────────────────────────────────────────────────────┘
```

### 5.4 User Management Actions

| Action | Permission Required | Audit Logged |
|--------|---------------------|--------------|
| View user list | `users.read_all` | Yes |
| View user details | `users.read_all` | Yes |
| Edit user profile | `users.update_any` | Yes |
| Change user role | `admin.manage_organization` | Yes |
| Disable user | `admin.disable_user` | Yes |
| Enable user | `admin.enable_user` | Yes |
| Force logout | `admin.manage_organization` | Yes |
| Delete user | `users.delete_any` | Yes |
| Reset password | `admin.manage_organization` | Yes |

---

## 6. Real-Time Activity Feed

### 6.1 Live Event Stream

```
┌─────────────────────────────────────────────────────────────────┐
│ LIVE ACTIVITY                          [Filter ▼] [Pause] [⟳]   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  10:45:32  🟢 LOGIN      john.doe@co.com logged in from NYC     │
│  10:45:30  🔴 RISK       High risk event detected - user #789   │
│  10:45:28  🟡 WARNING    Failed login attempt - jane@co.com     │
│  10:45:25  🔵 ACTION     Admin disabled user account #456       │
│  10:45:20  🟢 LOGIN      bob.wilson@co.com logged in from SYD   │
│  10:45:18  🟢 EVENT      Analytics report exported by #123      │
│  10:45:15  🔴 ALERT      Impossible travel detected - user #101 │
│  10:45:10  🔵 SYSTEM     Database backup completed              │
│  ...                                                            │
│                                                                 │
│  Showing 50 of 1,247 events today                [Load More]    │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Event Categories

| Category | Icon | Color | Examples |
|----------|------|-------|----------|
| **Login** | 🟢 | Green | User login, logout |
| **Risk** | 🔴 | Red | High risk events, fraud alerts |
| **Warning** | 🟡 | Yellow | Failed attempts, suspicious activity |
| **Action** | 🔵 | Blue | Admin actions, user changes |
| **System** | ⚪ | Gray | Backups, maintenance, deployments |
| **Audit** | 🟣 | Purple | Compliance events, data access |

### 6.3 Filter Options

```yaml
filters:
  event_type:
    - login
    - logout
    - failed_login
    - risk_event
    - admin_action
    - user_action
    - system_event
    
  severity:
    - critical
    - high
    - medium
    - low
    - info
    
  time_range:
    - last_5_minutes
    - last_15_minutes
    - last_hour
    - last_24_hours
    - custom_range
    
  user:
    - specific_user_id
    - specific_role
    - specific_organization
```

---

## 7. Risk & Fraud Analytics

### 7.1 Risk Overview Dashboard

```
┌─────────────────────────────────────────────────────────────────┐
│ RISK CENTER                                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Today's Risk Summary                                           │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │   12    │  │   45    │  │   234   │  │  1,892  │            │
│  │ BLOCKED │  │ FLAGGED │  │ REVIEWED│  │ ALLOWED │            │
│  │  🔴     │  │  🟡     │  │  🔵     │  │  🟢     │            │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
│                                                                 │
│  Risk Score Distribution          Top Triggered Rules           │
│  ┌──────────────────────┐        ┌──────────────────────────┐  │
│  │     ▓▓                │        │ 1. Impossible Travel (23)│  │
│  │   ▓▓▓▓▓▓              │        │ 2. Credential Stuffing(15)│ │
│  │ ▓▓▓▓▓▓▓▓▓▓▓▓          │        │ 3. VPN Detection     (12)│  │
│  │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    │        │ 4. New Device        (8) │  │
│  │ Low    Med    High    │        │ 5. Unusual Hour      (5) │  │
│  └──────────────────────┘        └──────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 Risk Metrics

| Metric | Description | Alert Condition |
|--------|-------------|-----------------|
| **Block Rate** | % of events blocked | > 5% (unusual) |
| **Avg Risk Score** | Mean risk score | > 0.5 (elevated) |
| **False Positive Rate** | Reviewed & cleared | > 20% (tune rules) |
| **Rule Trigger Rate** | Events triggering rules | Trend analysis |
| **Response Time** | Alert to action time | > 5 min (SLA breach) |

### 7.3 High-Risk Users Panel

```
┌─────────────────────────────────────────────────────────────────┐
│ HIGH RISK USERS (Risk Score > 70)                    Count: 8   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  User                Risk    Reason                   Action    │
│  ──────────────────────────────────────────────────────────────│
│  suspicious@test.com  95     Impossible travel        [Review]  │
│  hacker@bad.com       92     Multiple failed logins   [Block]   │
│  user789@company.com  85     Sanctioned IP detected   [Review]  │
│  compromised@org.com  78     Unusual behavior         [Review]  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.4 Fraud Detection Timeline

Visual timeline showing:
- Risk events over time (24h, 7d, 30d views)
- Blocked vs allowed ratio
- Peak fraud attempt times
- Geographic hotspots

---

## 8. Audit & Compliance

### 8.1 Audit Log Viewer

```
┌─────────────────────────────────────────────────────────────────┐
│ AUDIT LOGS                    [Export CSV] [Export PDF] [🔍]    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Timestamp            Actor           Action          Target    │
│  ─────────────────────────────────────────────────────────────  │
│  2026-01-09 10:45:32  admin@co.com   user_disabled   user#456  │
│  2026-01-09 10:44:15  john@co.com    profile_viewed  user#789  │
│  2026-01-09 10:43:00  system         backup_started  database  │
│  2026-01-09 10:42:30  jane@co.com    report_exported analytics │
│  2026-01-09 10:41:00  admin@co.com   role_changed    user#123  │
│                                                                 │
│  Page 1 of 547        [< Prev]  [1] [2] [3] ... [547]  [Next >] │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Audit Search & Filters

```yaml
audit_filters:
  actor:
    - user_id
    - user_email
    - user_role
    
  action_type:
    - authentication (login, logout, failed_login)
    - user_management (create, update, delete, disable)
    - data_access (view, export, download)
    - system (backup, config_change, deployment)
    - risk (block, allow, review)
    
  target:
    - user_id
    - resource_type
    - resource_id
    
  time_range:
    - predefined (today, yesterday, last_7_days, last_30_days)
    - custom (start_date, end_date)
    
  ip_address:
    - specific_ip
    - ip_range
    - country
```

### 8.3 Compliance Reports

| Report | Description | Schedule |
|--------|-------------|----------|
| **User Access Report** | Who accessed what data | Weekly |
| **Login Activity Report** | All authentication events | Daily |
| **Admin Actions Report** | Privileged operations | Daily |
| **Risk Events Report** | All security incidents | Daily |
| **Failed Access Report** | Blocked/denied requests | Daily |
| **Data Export Report** | All data exports | Weekly |
| **Role Changes Report** | Permission modifications | Weekly |

### 8.4 User Access Audit

Track who viewed user profiles (compliance requirement):

```
┌─────────────────────────────────────────────────────────────────┐
│ USER PROFILE ACCESS AUDIT: John Doe (user-123)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Who Viewed          When                Fields Accessed        │
│  ─────────────────────────────────────────────────────────────  │
│  admin@co.com        Today 10:45         Full profile           │
│  analyst@co.com      Today 09:30         Name, role, risk       │
│  security@co.com     Yesterday 15:20     Full profile           │
│  viewer@co.com       Yesterday 14:00     Name, role only        │
│                                                                 │
│  Total views this month: 47                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Technical Architecture

### 9.1 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      ADMIN DASHBOARD                             │
│                      (React Frontend)                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
        ┌──────────────┐       ┌──────────────┐
        │   REST API   │       │  WebSocket   │
        │  (FastAPI)   │       │   Server     │
        └──────┬───────┘       └──────┬───────┘
               │                      │
               ▼                      ▼
        ┌─────────────────────────────────────┐
        │          BACKEND SERVICES            │
        │  ┌─────────┐  ┌─────────────────┐   │
        │  │Dashboard│  │ Real-time Event │   │
        │  │ Service │  │    Publisher    │   │
        │  └────┬────┘  └────────┬────────┘   │
        │       │                │            │
        │       ▼                ▼            │
        │  ┌─────────────────────────────┐    │
        │  │     Redis Pub/Sub           │    │
        │  │  (Real-time event bus)      │    │
        │  └─────────────────────────────┘    │
        └─────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌──────────────┐ ┌────────────┐ ┌──────────────┐
│  PostgreSQL  │ │   Redis    │ │  Prometheus  │
│  (Data)      │ │  (Cache)   │ │  (Metrics)   │
└──────────────┘ └────────────┘ └──────────────┘
```

### 9.2 Real-Time Data Flow

```
Event Occurs → Redis Stream → Event Publisher → WebSocket → Dashboard
     │              │               │               │
     │              ▼               │               │
     │        PostgreSQL            │               │
     │        (Persist)             │               │
     │                              │               │
     └──────────────────────────────┴───────────────┘
                    Audit Trail
```

### 9.3 Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Frontend** | React 18 + TypeScript | Dashboard UI |
| **State Management** | Redux Toolkit + RTK Query | State & caching |
| **Charts** | Recharts / Apache ECharts | Data visualization |
| **Real-time** | Socket.IO / WebSocket | Live updates |
| **Backend** | FastAPI (Python) | API server |
| **WebSocket Server** | FastAPI WebSocket | Push notifications |
| **Database** | PostgreSQL | Persistent storage |
| **Cache** | Redis | Session, real-time |
| **Metrics** | Prometheus + Grafana | System metrics |
| **Message Queue** | Redis Streams / Kafka | Event streaming |

---

## 10. API Specifications

### 10.1 Dashboard Endpoints

#### System Health

```yaml
GET /api/admin/dashboard/health:
  description: Get system health overview
  response:
    services:
      api: { status: "healthy", latency_ms: 45 }
      database: { status: "healthy", connections: 23, pool_size: 50 }
      redis: { status: "healthy", memory_mb: 128 }
      kafka: { status: "degraded", consumer_lag: 1500 }
    overall_health: 95.8
    last_updated: "2026-01-09T10:45:00Z"

GET /api/admin/dashboard/metrics:
  description: Get detailed metrics
  parameters:
    - time_range: "1h" | "6h" | "24h" | "7d"
    - metrics: ["latency", "throughput", "errors"]
  response:
    latency:
      p50: 45
      p95: 120
      p99: 350
    throughput:
      requests_per_second: 245
    errors:
      rate_percent: 0.5
      count_5xx: 12
      count_4xx: 89
```

#### User Monitoring

```yaml
GET /api/admin/dashboard/users/active:
  description: Get active user sessions
  parameters:
    - page: 1
    - page_size: 50
    - sort_by: "login_time" | "risk_score"
  response:
    active_sessions: 147
    users:
      - id: "user-123"
        email: "john@company.com"
        role: "analyst"
        login_time: "2026-01-09T10:30:00Z"
        ip_address: "192.168.1.45"
        location: "New York, US"
        risk_score: 15
        
GET /api/admin/dashboard/users/stats:
  description: User statistics
  response:
    total_users: 1250
    active_today: 342
    new_this_week: 23
    by_role:
      admin: 5
      analyst: 45
      viewer: 1200
    login_trend: [...]
```

#### Real-Time Events

```yaml
GET /api/admin/dashboard/events:
  description: Get recent events
  parameters:
    - limit: 100
    - event_types: ["login", "risk", "admin_action"]
    - severity: ["critical", "high"]
    - since: "2026-01-09T10:00:00Z"
  response:
    events:
      - id: "evt-123"
        type: "login"
        severity: "info"
        actor_id: "user-456"
        message: "User logged in from New York"
        timestamp: "2026-01-09T10:45:32Z"
        metadata: { ip: "192.168.1.45", device: "Chrome/Windows" }

WebSocket /ws/admin/events:
  description: Real-time event stream
  authentication: JWT token in query param
  messages:
    - type: "event"
      payload: { event object }
    - type: "alert"
      payload: { alert object }
    - type: "metric_update"
      payload: { metric snapshot }
```

#### Risk Analytics

```yaml
GET /api/admin/dashboard/risk/summary:
  description: Risk overview
  parameters:
    - time_range: "24h"
  response:
    blocked: 12
    flagged: 45
    reviewed: 234
    allowed: 1892
    avg_risk_score: 0.23
    top_rules:
      - rule_id: "impossible_travel"
        triggers: 23
      - rule_id: "credential_stuffing"
        triggers: 15

GET /api/admin/dashboard/risk/high-risk-users:
  description: Users with high risk scores
  parameters:
    - threshold: 70
    - limit: 20
  response:
    users:
      - user_id: "user-789"
        email: "suspicious@test.com"
        risk_score: 95
        risk_factors: ["impossible_travel", "new_device"]
        last_event: "2026-01-09T10:40:00Z"
```

#### Audit Logs

```yaml
GET /api/admin/dashboard/audit:
  description: Query audit logs
  parameters:
    - page: 1
    - page_size: 50
    - actor_id: "user-123" (optional)
    - action_type: "user_disabled" (optional)
    - target_id: "user-456" (optional)
    - start_date: "2026-01-01"
    - end_date: "2026-01-09"
  response:
    total: 5470
    page: 1
    logs:
      - id: "audit-123"
        timestamp: "2026-01-09T10:45:32Z"
        actor:
          id: "user-admin"
          email: "admin@company.com"
          role: "admin"
        action: "user_disabled"
        target:
          type: "user"
          id: "user-456"
        ip_address: "10.0.0.12"
        metadata: { reason: "Security incident" }

POST /api/admin/dashboard/audit/export:
  description: Export audit logs
  body:
    format: "csv" | "pdf" | "json"
    filters: { ... }
    email_to: "admin@company.com" (optional)
  response:
    job_id: "export-123"
    status: "processing"
    download_url: null  # Available when complete
```

### 10.2 WebSocket Events

```typescript
// Event types pushed via WebSocket
interface DashboardEvent {
  type: 'user_login' | 'user_logout' | 'risk_alert' | 'system_alert' | 
        'admin_action' | 'metric_update' | 'user_status_change';
  timestamp: string;
  payload: EventPayload;
}

interface UserLoginEvent {
  type: 'user_login';
  payload: {
    user_id: string;
    email: string;
    role: string;
    ip_address: string;
    location: string;
    device: string;
    risk_score: number;
  };
}

interface RiskAlertEvent {
  type: 'risk_alert';
  payload: {
    event_id: string;
    user_id: string;
    risk_score: number;
    triggered_rules: string[];
    recommended_action: 'block' | 'challenge' | 'review' | 'allow';
    severity: 'critical' | 'high' | 'medium' | 'low';
  };
}

interface SystemAlertEvent {
  type: 'system_alert';
  payload: {
    service: string;
    status: 'healthy' | 'degraded' | 'down';
    message: string;
    severity: 'critical' | 'warning' | 'info';
  };
}
```

---

## 11. Frontend Components

### 11.1 Component Hierarchy

```
AdminDashboard/
├── Layout/
│   ├── Sidebar
│   ├── Header (with alerts dropdown)
│   └── MainContent
├── Pages/
│   ├── DashboardOverview
│   ├── SystemHealth
│   ├── UserManagement
│   ├── RiskCenter
│   └── AuditLogs
├── Widgets/
│   ├── MetricCard
│   ├── ServiceStatusCard
│   ├── UserSessionsTable
│   ├── ActivityFeed
│   ├── RiskDistributionChart
│   ├── AlertsPanel
│   └── AuditLogViewer
└── Shared/
    ├── DataTable (sortable, filterable)
    ├── TimeRangeSelector
    ├── ExportButton
    ├── SearchInput
    └── NotificationToast
```

### 11.2 Key Components

#### Dashboard Overview Page
```tsx
// Main dashboard with all key metrics at a glance
<DashboardOverview>
  <MetricCardsRow>
    <MetricCard title="Active Users" value={147} trend="+12%" />
    <MetricCard title="Events Today" value={2183} trend="+5%" />
    <MetricCard title="Risk Alerts" value={12} trend="-3%" severity="warning" />
    <MetricCard title="System Health" value="98.5%" status="healthy" />
  </MetricCardsRow>
  
  <GridLayout>
    <ServiceStatusPanel />
    <ActiveSessionsWidget />
    <RiskSummaryWidget />
    <RecentActivityFeed />
  </GridLayout>
</DashboardOverview>
```

#### Real-Time Activity Feed
```tsx
// Live-updating event stream
<ActivityFeed
  websocketUrl="/ws/admin/events"
  filters={selectedFilters}
  maxItems={100}
  onEventClick={handleEventDetails}
  showSeverityBadges={true}
  enableSound={criticalAlertsSound}
/>
```

### 11.3 State Management

```typescript
// Redux store structure
interface DashboardState {
  health: {
    services: ServiceStatus[];
    metrics: SystemMetrics;
    lastUpdated: string;
  };
  users: {
    activeSessions: UserSession[];
    stats: UserStats;
    selectedUser: User | null;
  };
  events: {
    feed: DashboardEvent[];
    filters: EventFilters;
    isPaused: boolean;
  };
  risk: {
    summary: RiskSummary;
    highRiskUsers: HighRiskUser[];
    topRules: RuleStats[];
  };
  audit: {
    logs: AuditLog[];
    filters: AuditFilters;
    pagination: Pagination;
  };
  alerts: {
    unread: Alert[];
    count: number;
  };
}
```

---

## 12. Security Requirements

### 12.1 Authentication & Authorization

| Requirement | Implementation |
|-------------|----------------|
| **Authentication** | JWT with refresh tokens |
| **Session Timeout** | 30 min idle, 8 hour max |
| **Role Requirement** | `admin` role required |
| **Permission Check** | Per-endpoint authorization |
| **Audit Logging** | All admin actions logged |

### 12.2 Access Control Matrix

| Feature | Admin | Security Ops | Compliance (Read-Only) |
|---------|:-----:|:------------:|:----------------------:|
| View System Health | ✅ | ✅ | ✅ |
| View User Sessions | ✅ | ✅ | ✅ |
| Force User Logout | ✅ | ✅ | ❌ |
| Disable User | ✅ | ✅ | ❌ |
| View Risk Alerts | ✅ | ✅ | ✅ |
| Take Risk Action | ✅ | ✅ | ❌ |
| View Audit Logs | ✅ | ✅ | ✅ |
| Export Audit Logs | ✅ | ✅ | ✅ |
| System Configuration | ✅ | ❌ | ❌ |

### 12.3 Security Measures

```yaml
security:
  # Rate limiting
  rate_limits:
    dashboard_api: 100 req/min
    websocket_connections: 5 per user
    export_requests: 10 per hour
    
  # Data protection
  data_protection:
    pii_masking: enabled (for non-admin viewers)
    export_encryption: AES-256
    audit_immutability: append-only
    
  # Network security
  network:
    cors_origins: ["https://admin.sentineliq.com"]
    websocket_origin_check: enabled
    ip_allowlist: optional (for production)
    
  # Session security
  session:
    secure_cookies: true
    same_site: strict
    csrf_protection: enabled
```

---

## 13. Performance Requirements

### 13.1 Performance Targets

| Metric | Target | Maximum |
|--------|--------|---------|
| **Dashboard Load Time** | < 2s | 5s |
| **API Response Time** | < 200ms | 500ms |
| **WebSocket Latency** | < 100ms | 300ms |
| **Chart Render Time** | < 500ms | 1s |
| **Search Response** | < 300ms | 1s |
| **Export Generation** | < 30s | 2 min |

### 13.2 Optimization Strategies

```yaml
optimizations:
  frontend:
    - Code splitting by route
    - Lazy loading for charts
    - Virtual scrolling for large tables
    - Debounced search inputs
    - Memoized expensive computations
    
  backend:
    - Response caching (Redis, 5-30s TTL)
    - Database query optimization
    - Connection pooling
    - Async event processing
    - Pagination for all list endpoints
    
  real_time:
    - Event batching (100ms window)
    - Delta updates (not full state)
    - Automatic reconnection
    - Backpressure handling
```

### 13.3 Scalability Considerations

```
Current Capacity (Single Instance):
- 50 concurrent dashboard users
- 1000 events/second throughput
- 10M audit log records

Horizontal Scaling:
- Stateless API servers (load balanced)
- Redis cluster for pub/sub
- Read replicas for analytics queries
- CDN for static assets
```

---

## 14. Implementation Phases

### Phase 1: Foundation (Week 1-2)
**Goal:** Basic dashboard structure with health monitoring

- [ ] Backend API scaffolding
  - [ ] `/api/admin/dashboard/health` endpoint
  - [ ] `/api/admin/dashboard/metrics` endpoint
  - [ ] Authentication middleware for admin routes
  
- [ ] Frontend foundation
  - [ ] Dashboard layout (sidebar, header, content)
  - [ ] System health panel
  - [ ] Basic metric cards
  
- [ ] Infrastructure
  - [ ] WebSocket server setup
  - [ ] Redis pub/sub configuration

**Deliverable:** Functional health monitoring dashboard

---

### Phase 2: User Monitoring (Week 3-4)
**Goal:** Complete user session and management features

- [ ] Backend API
  - [ ] `/api/admin/dashboard/users/active` endpoint
  - [ ] `/api/admin/dashboard/users/stats` endpoint
  - [ ] User detail endpoint with activity
  - [ ] User management actions (disable, force logout)
  
- [ ] Frontend
  - [ ] Active sessions table
  - [ ] User statistics widgets
  - [ ] User detail modal
  - [ ] User management actions

- [ ] Real-time
  - [ ] Login/logout event streaming
  - [ ] Session count updates

**Deliverable:** Complete user monitoring and management

---

### Phase 3: Real-Time Activity (Week 5-6)
**Goal:** Live event feed and notifications

- [ ] Backend
  - [ ] Event streaming service
  - [ ] WebSocket event publisher
  - [ ] Event filtering logic
  
- [ ] Frontend
  - [ ] Live activity feed component
  - [ ] Event filtering UI
  - [ ] Notification system
  - [ ] Sound alerts for critical events

- [ ] Integration
  - [ ] Connect to existing event sources
  - [ ] Redis Streams consumer

**Deliverable:** Real-time activity monitoring

---

### Phase 4: Risk Center (Week 7-8)
**Goal:** Risk analytics and fraud monitoring

- [ ] Backend
  - [ ] `/api/admin/dashboard/risk/summary` endpoint
  - [ ] `/api/admin/dashboard/risk/high-risk-users` endpoint
  - [ ] Risk event aggregation service
  
- [ ] Frontend
  - [ ] Risk overview dashboard
  - [ ] Risk distribution charts
  - [ ] High-risk users panel
  - [ ] Rule trigger analytics

- [ ] Integration
  - [ ] Connect to Risk Engine
  - [ ] Real-time risk alerts

**Deliverable:** Complete risk monitoring dashboard

---

### Phase 5: Audit & Compliance (Week 9-10)
**Goal:** Comprehensive audit logging and reporting

- [ ] Backend
  - [ ] `/api/admin/dashboard/audit` endpoint
  - [ ] Audit log search and filtering
  - [ ] Export functionality (CSV, PDF)
  - [ ] Scheduled report generation
  
- [ ] Frontend
  - [ ] Audit log viewer with search
  - [ ] Advanced filters
  - [ ] Export UI
  - [ ] Report scheduling

**Deliverable:** Production-ready audit system

---

### Phase 6: Polish & Production (Week 11-12)
**Goal:** Production hardening and optimization

- [ ] Performance optimization
  - [ ] Frontend bundle optimization
  - [ ] API response caching
  - [ ] Database query optimization
  
- [ ] Security hardening
  - [ ] Penetration testing
  - [ ] Security audit
  - [ ] Rate limiting tuning
  
- [ ] Documentation
  - [ ] User guide
  - [ ] API documentation
  - [ ] Runbook for operations

**Deliverable:** Production-ready admin dashboard

---

## 15. Open Questions

### Technical Decisions Needed

| # | Question | Options | Recommendation |
|---|----------|---------|----------------|
| 1 | Chart library? | Recharts, ECharts, D3 | Recharts (simpler) |
| 2 | WebSocket library? | Socket.IO, native WS | Socket.IO (reconnection) |
| 3 | Export format for large data? | Streaming CSV, Async job | Async job + email |
| 4 | Audit log retention? | 90 days, 1 year, forever | 1 year (configurable) |
| 5 | Dashboard refresh strategy? | Polling, WebSocket only | Hybrid (WS + fallback) |

### Business Decisions Needed

| # | Question | Context |
|---|----------|---------|
| 1 | Who can access dashboard? | Admin only, or tiered access? |
| 2 | Alert escalation path? | Email, Slack, PagerDuty? |
| 3 | SLA for critical alerts? | What response time is required? |
| 4 | Data retention policy? | Compliance requirements? |
| 5 | Multi-tenant dashboard? | Each org sees own data only? |

### Design Decisions Needed

| # | Question | Context |
|---|----------|---------|
| 1 | Dark mode support? | User preference or system? |
| 2 | Mobile responsiveness? | Required or desktop only? |
| 3 | Customizable widgets? | Fixed layout or drag-drop? |
| 4 | Notification sounds? | Optional or required? |

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **Risk Score** | 0-100 score indicating fraud likelihood |
| **Hard Rule** | Immediate block rule (sanctions, etc.) |
| **Velocity Check** | Time-based anomaly detection |
| **PII** | Personally Identifiable Information |
| **Audit Log** | Immutable record of actions |
| **WebSocket** | Real-time bidirectional communication |

---

## Appendix B: Related Documents

- [SentinelIQ Architecture Overview](./ARCHITECTURE.md)
- [API Documentation](http://localhost:8000/docs)
- [Risk Engine Rules](../backend/rules/fraud_rules.yaml)
- [User Permissions](../backend/app/config.py)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-09 | Dev Team | Initial draft |

---

**END OF SPECIFICATION**

*Please review and provide feedback on:*
1. *Feature prioritization*
2. *Technical decisions*
3. *Timeline estimates*
4. *Missing requirements*
