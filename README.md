# SentinelIQ - Fintech Risk & Security Intelligence Platform

**Advanced Event-Driven Risk Detection, Real-Time Fraud Prevention, and Comprehensive Security Monitoring for Financial Institutions**

---

## Overview

SentinelIQ is a modern, enterprise-grade backend system designed for financial technology (fintech) companies to detect, prevent, and respond to fraud, security threats, and suspicious activities in real-time. Built with a microservices-first architecture, SentinelIQ combines rule-based risk scoring, behavioral analysis, machine learning readiness, and comprehensive audit logging to provide financial institutions with a complete security posture.

---

## The Problem It Solves

### 1. **Real-Time Fraud Detection**
Financial institutions process millions of transactions daily. Traditional batch-based fraud detection systems introduce delays—by the time fraud is detected, customers have already suffered losses and institutions face regulatory penalties and reputational damage.

### 2. **Complex Risk Assessment**
Modern financial crimes involve sophisticated techniques:
- Credential stuffing attacks
- Money laundering through structuring
- Account takeover via compromised credentials
- Geographic anomalies (impossible travel)
- Velocity-based attacks (rapid transactions from multiple locations)
- Sanctioned entity access

These require multi-dimensional analysis across real-time events, historical behavior, and regulatory compliance frameworks.

### 3. **Regulatory Compliance & Audit Requirements**
Financial institutions must maintain immutable audit logs, demonstrate compliance with OFAC/sanctions lists, implement KYC (Know Your Customer) protocols, and satisfy PCI-DSS, GDPR, and other regulations. Manual or fragmented logging creates audit gaps and compliance risks.

### 4. **Alert Fatigue & Operational Burden**
Poorly tuned security systems generate false positives, overwhelming security teams and causing alert fatigue. This leads to genuine threats being missed while resources are wasted investigating noise.

### 5. **Lack of Centralized Intelligence**
Without a unified platform, risk signals are scattered across authentication systems, transaction databases, and security tools. This fragmentation prevents organizations from seeing the full picture of an attack or coordinating responses.

---

## Key Features & Capabilities

### **1. Event-Driven Risk Engine**
- **Real-time event processing** - Consumes authentication, transaction, and user behavior events from Redis streams
- **Multi-layered risk scoring**:
  - **Hard Rules**: Immediate blockers (sanctioned countries, credential stuffing)
  - **Velocity Checks**: Temporal anomalies (5+ login attempts in 1 minute)
  - **Behavioral Analysis**: Deviation from user baseline patterns
  - **Composite Scoring**: Combined risk assessment across multiple dimensions

### **2. Comprehensive Rule Framework**
- YAML-based configurable rules without code deployment
- Rule categories:
  - Compliance rules (OFAC, sanctions)
  - Fraud detection (account takeover, suspicious patterns)
  - Anomaly detection (geographic, velocity, behavioral)
  - Login security (brute force, credential stuffing)
- Easy rule updates without system restart

### **3. Immutable Audit & Compliance Logging**
- All events stored in MinIO object storage for regulatory compliance
- Structured JSON logging with request correlation IDs
- Audit trail for:
  - Authentication attempts
  - User actions
  - Risk decisions
  - System changes
- GDPR-ready with configurable retention policies

### **4. Authentication & Authorization**
- **JWT-based authentication** with refresh tokens
- **Role-Based Access Control (RBAC)** with fine-grained permissions
- **Organization-scoped multi-tenancy** for SaaS deployments
- Email verification workflows
- Secure password reset mechanisms
- Login attempt tracking and brute-force protection

### **5. Real-Time Monitoring & Observability**
- **Prometheus metrics** for performance monitoring
- **Structured logging** with Loki integration
- **Grafana dashboards** for visualization
- Request latency tracking and performance analytics
- Health checks and readiness probes

### **6. Security Hardening**
- **OWASP Security Headers** (HSTS, CSP, X-Frame-Options, etc.)
- **Trusted Host Middleware** to prevent DNS rebinding attacks
- **Request logging middleware** for audit trails
- **User tracking** with device fingerprinting
- **Encrypted secrets management** via HashiCorp Vault
- **Redis Stream-based event persistence** for reliability

### **7. Multi-Tenant Architecture**
- Organization isolation
- Per-organization authentication and user management
- Scalable for SaaS deployments serving multiple financial institutions

---

## Use Cases

### **1. Digital Banking Platforms**
Detect compromised accounts in real-time before attackers can access customer funds. Prevent unauthorized access and money transfers through sophisticated multi-factor risk assessment.

### **2. Payment Processors**
Identify fraudulent transactions at authorization time. Reduce chargeback rates and protect merchant accounts from compromise. Comply with PCI-DSS requirements with immutable audit trails.

### **3. Cryptocurrency Exchanges**
Monitor for suspicious withdrawal patterns, sanctioned entity interactions, and rapid account changes. Prevent money laundering through behavioral anomaly detection.

### **4. Lending Platforms**
Detect synthetic identity fraud and account takeover during loan origination. Verify borrower legitimacy through multi-signal risk analysis.

### **5. Fintech Startups & Neobanks**
Compete with legacy institutions by offering faster, smarter fraud prevention. Reduce operational burden with automated risk decisions while maintaining regulatory compliance.

### **6. Enterprise Risk & Compliance Teams**
Gain unified visibility into fraud, security, and compliance events. Investigate incidents quickly with comprehensive audit trails. Generate compliance reports for regulators.

---

## Architecture

### Technology Stack

- **Framework**: FastAPI (async Python web framework)
- **Database**: PostgreSQL (relational data, audit logs)
- **Cache/Event Streaming**: Redis (event streams, rate limiting)
- **Object Storage**: MinIO (immutable log archival)
- **Secrets Management**: HashiCorp Vault (encrypted configuration)
- **Monitoring**: 
  - Prometheus (metrics collection)
  - Loki (log aggregation)
  - Grafana (visualization)
- **Containerization**: Docker & Docker Compose
- **Email**: Mailhog (development) / SMTP (production)

### Core Components

```
├── app/
│   ├── routes/              # HTTP endpoint handlers
│   │   ├── auth.py         # Authentication endpoints
│   │   ├── users.py        # User management
│   │   ├── admin.py        # Admin operations
│   │   ├── events.py       # Event streaming
│   │   ├── analytics.py    # Analytics & reporting
│   │   └── password_reset.py # Password recovery
│   ├── services/           # Business logic
│   │   ├── risk_engine.py  # Risk scoring & fraud detection
│   │   ├── auth_service.py # Authentication logic
│   │   ├── email_service.py# Email delivery
│   │   ├── redis_stream.py # Event processing
│   │   └── alerts.py       # Alert generation
│   ├── core/               # Infrastructure
│   │   ├── db.py          # Database connection
│   │   ├── security.py    # Encryption & hashing
│   │   ├── logging.py     # Structured logging
│   │   └── auth_utils.py  # JWT & token utilities
│   ├── models/             # Data models
│   └── schemas/            # Request/response validation
├── rules/
│   └── fraud_rules.yaml    # Configurable risk rules
└── docker-compose.yml      # Full stack orchestration
```

---

## Admin Dashboard

SentinelIQ includes a modern, production-ready admin dashboard built with React 18, TypeScript, and Tailwind CSS.

### Features

- **Real-Time Monitoring**: Live event streaming via WebSocket
- **System Health**: Service status, latency metrics, error rates
- **User Management**: Active sessions, user profiles, force logout
- **Risk Analytics**: Risk distribution, high-risk user tracking
- **Audit Logs**: Searchable, filterable audit trail with export
- **Activity Feed**: Live event stream with severity filtering

### Quick Start

```bash
# Start the backend first
cd backend
docker-compose up -d
uvicorn app.main:app --reload --port 8000

# Start the frontend
cd ../frontend
npm install
npm run dev
```

The dashboard will be available at `http://localhost:3000`.

### Default Login
```
Email: admin@sentineliq.com
Password: admin123
```

### Screenshots

The dashboard provides:
- **Overview Page**: Stats cards, health status, risk summary, login trends
- **User Management**: Paginated user list, detailed profiles, session management
- **Risk Center**: Risk metrics, distribution charts, high-risk user alerts
- **Audit Logs**: Filterable audit trail with CSV/JSON export
- **Activity Feed**: Real-time event stream with WebSocket
- **System Health**: Service monitoring with health gauges

See [frontend/README.md](frontend/README.md) for detailed frontend documentation.

---

## Getting Started

### Prerequisites
- Docker & Docker Compose
- Python 3.11+ (for local development)
- Node.js 18+ (for frontend development)
- PostgreSQL client (optional, for debugging)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/sentineliq.git
cd sentineliq

# Build and start all services
docker compose up --build

# API will be available at http://localhost:8000
# Documentation at http://localhost:8000/docs
# Dashboard at http://localhost:3000
# Grafana at http://localhost:3001 (admin:admin)
```

### Health Check
```bash
curl http://localhost:8000/health
# Response: {"status": "ok"}
```

### API Documentation
FastAPI auto-generates OpenAPI (Swagger) documentation. Visit `http://localhost:8000/docs` to explore all endpoints interactively.

---

## Key Endpoints

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - Authenticate and receive JWT token
- `POST /auth/refresh` - Refresh expired token
- `POST /auth/logout` - Revoke token

### User Management
- `GET /users/profile` - Get current user profile
- `PUT /users/profile` - Update user settings
- `POST /users/password/reset-request` - Request password reset
- `POST /users/password/reset` - Complete password reset

### Risk & Events
- `POST /events/stream` - Submit events for risk analysis
- `GET /analytics/dashboard` - View risk metrics and trends

### Admin
- `GET /admin/users` - List all users
- `DELETE /admin/users/{user_id}` - Deactivate user

---

## Configuration

### Environment Variables
```bash
DATABASE_URL=postgresql://user:password@postgres:5432/sentineliq
REDIS_URL=redis://redis:6379
VAULT_ADDR=http://vault:8200
JWT_SECRET=your-secret-key-here
EMAIL_FROM=noreply@sentineliq.com
```

### Fraud Rules
Customize fraud detection rules in `rules/fraud_rules.yaml` without redeploying:
```yaml
rules:
  hard_rules:
    - id: "sanctioned_region"
      name: "Sanctioned Region Access"
      conditions:
        country_code:
          in: ["KP", "IR", "SY", "CU"]
      action: "block"
```

---

## User Visibility & Access Control

### Overview
When users log into SentinelIQ, their profile details (name, ID, risk score, etc.) can be viewed by other users based on **role-based permissions**. This enables:
- Admins to monitor all user activity and risk scores
- Analysts to review user profiles for fraud investigation
- Viewers to see basic user information within their organization

### User Roles & What They Can See

| Role | Description | User Access |
|------|-------------|-------------|
| **Admin** | Full system access | View ALL users with FULL details (name, email, risk score, login history, etc.) |
| **Analyst** | Data analysis & investigation | View org users with metadata (name, role, risk score, login time) |
| **Viewer** | Read-only access | View org users with public fields only (name, role, status) |

### Example: Viewing a Logged-In User

When user **John Doe** logs in, here's what each role sees:

```
ADMIN sees:
{
  "id": "user-123",
  "first_name": "John",
  "last_name": "Doe",
  "email": "john.doe@company.com",     ← Full PII
  "role": "analyst",
  "risk_score": 25,                     ← Risk assessment
  "last_login_at": "2026-01-09T10:30:00",
  "last_login_ip": "192.168.1.100",    ← Full IP
  "is_active": true,
  "status": "active"
}

ANALYST sees:
{
  "id": "user-123",
  "first_name": "John",
  "last_name": "Doe",
  "role": "analyst",
  "status": "active",
  "last_login_at": "2026-01-09T10:30:00",
  "email_verified": true
}

VIEWER sees:
{
  "id": "user-123",
  "first_name": "John",
  "last_name": "Doe",
  "role": "analyst",
  "status": "active"
}
```

### User Visibility Levels
| Visibility | Default For | Who Can View |
|------------|-------------|--------------|
| `global` | System users | All authenticated users |
| `public` | Public profiles | Anyone with `users.read_public` |
| `org` | **New users (default)** | Members of the same organization |
| `private` | Sensitive accounts | Only self and admins |

### User Permissions Matrix

| Permission | Admin | Analyst | Viewer |
|------------|:-----:|:-------:|:------:|
| `users.read_all` | ✅ | ❌ | ❌ |
| `users.read_metadata` | ✅ | ✅ | ❌ |
| `users.read_own_org` | ✅ | ✅ | ✅ |
| `users.read_public` | ✅ | ✅ | ✅ |
| `users.read_audit` | ✅ | ❌ | ❌ |
| `users.manage` | ✅ | ❌ | ❌ |

### API Endpoints for Viewing Users

| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `/users/` | GET | List all visible users | All (filtered by role) |
| `/users/me` | GET | Get own profile (full) | Self |
| `/users/{id}` | GET | Get user by ID | Based on visibility |
| `/users/{id}/activity` | GET | User's action history | Self, Admin |
| `/users/{id}/audit` | GET | Who viewed this user | Admin only |
| `/users/{id}/permissions` | GET | User's role permissions | Self, Admin |

### Field Visibility by Access Level

| Access Level | Fields Shown | PII Handling |
|--------------|--------------|--------------|
| **full** | All fields | Unmasked |
| **metadata** | Public + login info, risk score | Partially masked |
| **public** | ID, name, role, status | No PII |
| **redacted** | ID, first name, role only | Fully masked |

---

## Compliance & Security

- **PCI-DSS**: Immutable audit logging, encrypted secrets management
- **OFAC Compliance**: Sanctions list checking in hard rules
- **GDPR**: Data retention policies, user data export capabilities
- **SOC 2**: Comprehensive audit trails, monitoring, and alerting
- **HIPAA-Ready**: Encrypted data at rest and in transit
- **User Access Auditing**: All profile access logged for compliance

---

## Monitoring & Observability

### Metrics Available
- Request latency (p50, p95, p99)
- Error rates by endpoint
- Authentication success/failure rates
- Risk event volumes
- Database query performance
- User profile access counts

### View Metrics
```bash
# Prometheus metrics endpoint
curl http://localhost:9090/metrics

# Grafana dashboards
http://localhost:3000
```

### Logs
Logs are aggregated in Loki and queryable via Grafana. Key log types:
- Application logs (request/response)
- Risk decisions (fraud alerts)
- Audit logs (user actions)
- **User access logs** (profile views)
- System events (startup/shutdown)

---

## Development & Testing

```bash
# Run unit tests
docker compose run --rm api pytest tests/

# Run system user tests
docker compose run --rm api pytest tests/test_system_user.py -v

# View API documentation
http://localhost:8000/docs

# Access PostgreSQL CLI
docker compose exec postgres psql -U sentineliq

# Monitor Redis events
docker compose exec redis redis-cli XREAD COUNT 10 STREAMS events 0
```

---

## Production Deployment

### Recommended Architecture
- **Kubernetes** for orchestration
- **Managed PostgreSQL** (AWS RDS, Google Cloud SQL)
- **Managed Redis** (AWS ElastiCache)
- **Object Storage** (AWS S3, Google Cloud Storage)
- **Secret Management** (AWS Secrets Manager, HashiCorp Vault)
- **Load Balancing** (NGINX, AWS ALB)
- **CDN** for static assets

### Security Considerations
- Enable HTTPS/TLS for all endpoints
- Rotate JWT secrets regularly
- Use strong database passwords and network isolation
- Enable WAF (Web Application Firewall) rules
- Implement rate limiting per API client
- Monitor for suspicious patterns in logs
- **Review user access audit logs regularly**

---

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Create a feature branch (`git checkout -b feature/amazing-feature`)
2. Commit changes with clear messages
3. Write tests for new functionality
4. Submit a pull request

---

## Support & Documentation

- **API Docs**: http://localhost:8000/docs
- **GitHub Issues**: [Report bugs or request features]
- **Email**: support@sentineliq.com

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Roadmap

- [x] System user with global visibility
- [x] User access audit logging
- [x] Role-based field visibility
- [ ] Machine learning model integration for behavioral anomaly detection
- [ ] Advanced analytics dashboard with drill-down capabilities
- [ ] GraphQL API support
- [ ] Webhook notifications for risk events
- [ ] Mobile SDK for app-based authentication
- [ ] Third-party integrations (Slack, PagerDuty, Splunk)
- [ ] Real-time data pipeline to data warehouses

---

**SentinelIQ: Protecting Financial Systems in Real-Time** 🛡️