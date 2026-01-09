# API Reference

## Base URL

- **Development**: `http://localhost:8000`
- **Production**: `https://api.sentineliq.com`

## Interactive Documentation

FastAPI auto-generates OpenAPI documentation:

- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

## Authentication

All protected endpoints require a JWT token in the Authorization header:

```
Authorization: Bearer <access_token>
```

### Obtain Token

```bash
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "your_password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbG...",
  "refresh_token": "abc123...",
  "token_type": "bearer"
}
```

## Endpoints Overview

### Authentication (`/auth`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Authenticate user |
| POST | `/auth/token/refresh` | Refresh access token |
| POST | `/auth/logout` | Revoke tokens |
| POST | `/auth/logout/all` | Revoke all user sessions |

### Users (`/users`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/users/register` | Register new user |
| GET | `/users/profile` | Get current user profile |
| PUT | `/users/profile` | Update profile |

### Admin (`/admin`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/users` | List all users |
| PUT | `/admin/users/{id}/disable` | Disable user |
| PUT | `/admin/users/{id}/enable` | Enable user |
| GET | `/admin/audit-logs` | View audit logs |

### Analytics (`/analytics`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/analytics/dashboard` | Dashboard metrics |
| GET | `/analytics/risk-summary` | Risk score summary |

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message here"
}
```

### Common Status Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Invalid/missing token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |
