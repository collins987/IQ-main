# Deployment Guide

## Development Environment

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)
- Git

### Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/sentineliq.git
cd sentineliq

# Copy environment template
cp .env.example .env

# Start all services
docker-compose up --build

# Verify deployment
curl http://localhost:8000/health
```

### Services & Ports

| Service | Port | URL |
|---------|------|-----|
| API | 8000 | http://localhost:8000 |
| API Docs | 8000 | http://localhost:8000/docs |
| PostgreSQL | 5432 | - |
| Redis | 6379 | - |
| Grafana | 3001 | http://localhost:3001 |
| Prometheus | 9090 | http://localhost:9090 |
| MinIO Console | 9001 | http://localhost:9001 |
| MailHog | 8025 | http://localhost:8025 |
| Vault | 8200 | http://localhost:8200 |

## Production Deployment

### Recommended Infrastructure

```
┌──────────────────────────────────────────────────────────────┐
│                         AWS / GCP / Azure                     │
├──────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │   AWS ALB   │    │   AWS ECS   │    │   AWS RDS   │      │
│  │ (Load Bal.) │───▶│ (Containers)│───▶│ (PostgreSQL)│      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
│                            │                                  │
│                            ▼                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │ ElastiCache │    │    AWS S3   │    │  Secrets    │      │
│  │   (Redis)   │    │ (Audit Logs)│    │   Manager   │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
└──────────────────────────────────────────────────────────────┘
```

### Environment Variables (Production)

```bash
# Database
DATABASE_URL=postgresql://user:password@rds-endpoint:5432/sentineliq

# Redis
REDIS_URL=redis://elasticache-endpoint:6379

# Security
SECRET_KEY=<generate-secure-256-bit-key>
JWT_SECRET=<generate-secure-key>

# S3/MinIO
MINIO_ENDPOINT=s3.amazonaws.com
MINIO_ACCESS_KEY=<aws-access-key>
MINIO_SECRET_KEY=<aws-secret-key>
MINIO_SECURE=true

# Email
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=<sendgrid-api-key>
SMTP_TLS=true
```

### Security Checklist

- [ ] Enable HTTPS/TLS for all endpoints
- [ ] Use managed secrets (AWS Secrets Manager / Vault)
- [ ] Enable database encryption at rest
- [ ] Configure network isolation (VPC)
- [ ] Set up WAF rules
- [ ] Enable audit logging
- [ ] Configure backup retention
- [ ] Set up monitoring alerts

## Kubernetes Deployment

See [kubernetes/](./kubernetes/) for Helm charts and manifests.

```bash
# Deploy to Kubernetes
helm install sentineliq ./kubernetes/helm/sentineliq \
  --namespace sentineliq \
  --create-namespace \
  -f values.production.yaml
```
