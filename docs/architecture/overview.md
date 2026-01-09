# Architecture Overview

## System Architecture

SentinelIQ is an event-driven fintech risk intelligence platform built with a microservices-ready architecture.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENTS                                         │
│                   (Web Dashboard, Mobile Apps, APIs)                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LOAD BALANCER / API GATEWAY                        │
│                              (NGINX / AWS ALB)                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FASTAPI APPLICATION                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Auth API   │  │  Events API  │  │ Analytics API│  │   Admin API  │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                         RISK ENGINE                                   │  │
│  │   Hard Rules → Velocity Checks → Behavioral Analysis → Risk Score    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   PostgreSQL    │  │     Redis       │  │     MinIO       │
│   (Primary DB)  │  │ (Event Streams) │  │  (Audit Logs)   │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Core Components

### 1. Risk Engine
The heart of SentinelIQ - evaluates events in real-time using:
- **Hard Rules**: Immediate blockers (sanctions, known threats)
- **Velocity Checks**: Temporal anomalies (rate limiting)
- **Behavioral Analysis**: User baseline deviation

### 2. Event Stream Processing
Redis Streams provide:
- Durable event storage
- Consumer group support
- At-least-once delivery guarantees

### 3. Audit Logging
Immutable audit trail with:
- Cryptographic chaining (tamper detection)
- S3-compatible storage (MinIO/AWS S3)
- Compliance-ready retention

## Data Flow

1. **Event Ingestion**: Client submits event → API validates → Redis Stream
2. **Risk Evaluation**: Risk Engine consumes → Evaluates rules → Scores event
3. **Decision Storage**: Decision logged → PostgreSQL + MinIO
4. **Alert Generation**: High-risk events → Alert stream → Notifications

## Security Layers

| Layer | Implementation |
|-------|----------------|
| Transport | TLS 1.3 |
| Authentication | JWT + Refresh Tokens |
| Authorization | RBAC with permissions |
| Data at Rest | AES-256 encryption |
| Secrets | HashiCorp Vault |
