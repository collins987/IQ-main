# SentinelIQ Admin Dashboard

Modern, real-time admin dashboard for the SentinelIQ security intelligence platform.

## Tech Stack

- **Framework**: React 18 with Vite
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **State Management**: Redux Toolkit with RTK Query
- **Routing**: React Router DOM v6
- **Charts**: Recharts
- **Icons**: Heroicons

## Quick Start

```bash
# Install dependencies
npm install

# Start development server (runs on port 3000)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Development

The frontend proxies API requests to the backend:
- API requests (`/api/*`) → `http://localhost:8000`
- WebSocket (`/ws/*`) → `ws://localhost:8000`

### Backend Setup

Before starting the frontend, ensure the backend is running:

```bash
cd ../backend
docker-compose up -d   # Start PostgreSQL, Redis, etc.
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Default Login

```
Email: admin@sentineliq.com
Password: admin123
```

## Project Structure

```
src/
├── components/
│   ├── common/         # Shared components (LoadingSpinner, etc.)
│   ├── dashboard/      # Dashboard-specific components
│   └── layout/         # Layout components (Sidebar, Header)
├── features/           # Redux slices
├── hooks/              # Custom React hooks
├── layouts/            # Page layouts
├── pages/              # Route pages
├── services/           # RTK Query API definitions
├── store/              # Redux store configuration
└── utils/              # Utility functions
```

## Features

### Dashboard Overview
- Real-time stats cards (users, sessions, risk events)
- System health monitoring
- Risk summary with distribution chart
- Login trend visualization
- Recent events feed
- Active sessions list

### User Management
- User list with search and filtering
- Detailed user profiles
- Force logout functionality
- Risk score indicators
- Role and status badges

### Risk Center
- Risk event metrics (allowed, flagged, reviewed, blocked)
- Risk distribution visualization
- High-risk user monitoring
- Risk rule statistics

### Audit Logs
- Comprehensive audit trail
- Advanced filtering (action, actor, date range)
- CSV/JSON export functionality
- Paginated results

### Activity Feed
- Real-time event streaming via WebSocket
- Severity-based filtering
- Event type categorization
- Live/paused toggle

### System Health
- Service status monitoring (Database, Redis, Kafka, Vault)
- Health percentage gauge
- Performance metrics (latency, throughput, errors)
- Database performance stats

## API Integration

All data is fetched from the real backend API - no mock data:

- `GET /api/admin/dashboard/health` - System health
- `GET /api/admin/dashboard/metrics` - Performance metrics
- `GET /api/admin/dashboard/users/active` - Active sessions
- `GET /api/admin/dashboard/users/stats` - User statistics
- `GET /api/admin/dashboard/events` - Activity events
- `GET /api/admin/dashboard/risk/summary` - Risk analytics
- `GET /api/admin/dashboard/audit` - Audit logs
- `WebSocket /api/admin/dashboard/ws/events` - Live events

## Styling

Custom Tailwind theme with SentinelIQ brand colors:

```css
sentinel-500: #0ea5e9  /* Primary brand color */
dashboard-bg: #0f172a  /* Dark background */
dashboard-card: #1e293b  /* Card background */
```

## Scripts

```bash
npm run dev      # Development server
npm run build    # Production build
npm run lint     # ESLint
npm run preview  # Preview build
```

