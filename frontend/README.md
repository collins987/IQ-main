# SentinelIQ Frontend

This folder is reserved for the frontend application.

## Recommended Stack

- **Framework**: React 18+ / Next.js 14+
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **State Management**: Zustand or React Query
- **UI Components**: shadcn/ui

## Getting Started

```bash
# Initialize a new Next.js project
npx create-next-app@latest . --typescript --tailwind --eslint

# Or React with Vite
npm create vite@latest . -- --template react-ts
```

## Folder Structure (Recommended)

```
frontend/
├── public/
├── src/
│   ├── components/
│   ├── hooks/
│   ├── lib/
│   ├── pages/ or app/
│   ├── services/
│   ├── stores/
│   └── types/
├── package.json
└── tsconfig.json
```

## Integration with Backend

The backend API is available at `http://localhost:8000`.

API Documentation: `http://localhost:8000/docs`
