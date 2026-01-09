import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { RootState } from '../store';

// Types for API responses
export interface ServiceHealth {
  status: 'healthy' | 'unhealthy' | 'degraded' | 'not_configured' | 'unavailable';
  latency_ms?: number;
  connections_active?: number;
  connections_max?: number;
  memory_mb?: number;
  connected_clients?: number;
  consumer_lag?: number;
  error?: string;
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'critical';
  timestamp: string;
  services: {
    database: ServiceHealth;
    redis: ServiceHealth;
    kafka: ServiceHealth;
    vault: ServiceHealth;
  };
  overall_health_percent: number;
}

export interface SystemMetrics {
  time_range: string;
  latency: {
    p50_ms: number;
    p95_ms: number;
    p99_ms: number;
  };
  throughput: {
    requests_per_second: number;
    total_requests: number;
  };
  errors: {
    rate_percent: number;
    count_5xx: number;
    count_4xx: number;
  };
  database: {
    avg_query_ms: number;
    slow_queries: number;
    connections_used: number;
  };
}

export interface ActiveUser {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  login_time: string | null;
  ip_address: string | null;
  risk_score: number;
  status: string;
  org_id: string | null;
}

export interface ActiveUsersResponse {
  active_sessions: number;
  users: ActiveUser[];
  pagination: {
    page: number;
    page_size: number;
    total: number;
    total_pages: number;
  };
}

export interface UserStats {
  total_users: number;
  active_today: number;
  new_this_week: number;
  active_sessions: number;
  by_role: Record<string, number>;
  by_status: Record<string, number>;
  verification: {
    verified: number;
    unverified: number;
    rate_percent: number;
  };
  login_trend: Array<{
    date: string;
    logins: number;
  }>;
}

export interface UserDetail {
  profile: {
    id: string;
    email: string;
    first_name: string;
    last_name: string;
    role: string;
    org_id: string | null;
    created_at: string | null;
    updated_at: string | null;
  };
  security: {
    risk_score: number;
    status: string;
    is_active: boolean;
    email_verified: boolean;
    is_system_user: boolean;
    visibility: string;
  };
  session: {
    last_login_at: string | null;
    last_login_ip: string | null;
    last_device_info: string | null;
    active_sessions: number;
  };
  activity: {
    failed_logins_24h: number;
    recent_actions: Array<{
      action: string;
      target: string;
      timestamp: string | null;
    }>;
  };
}

export interface DashboardEvent {
  id: string;
  type: string;
  action: string;
  severity: 'info' | 'warning' | 'high' | 'critical';
  actor_id: string;
  target: string | null;
  message: string;
  timestamp: string | null;
  metadata: Record<string, unknown> | null;
}

export interface EventsResponse {
  events: DashboardEvent[];
  count: number;
}

export interface RiskSummary {
  time_range: string;
  summary: {
    blocked: number;
    flagged: number;
    reviewed: number;
    allowed: number;
  };
  avg_risk_score: number;
  total_events: number;
  risk_distribution: {
    low: number;
    medium: number;
    high: number;
  };
}

export interface HighRiskUser {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  risk_score: number;
  role: string;
  status: string;
  last_login_at: string | null;
  risk_factors: string[];
}

export interface HighRiskUsersResponse {
  threshold: number;
  users: HighRiskUser[];
  count: number;
}

export interface RiskRule {
  rule_id: string;
  name: string;
  triggers: number;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string | null;
  actor: {
    id: string;
    email: string;
  };
  action: string;
  target: string | null;
  metadata: Record<string, unknown> | null;
}

export interface AuditLogsResponse {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  logs: AuditLogEntry[];
}

export interface AuditLogFilters {
  page?: number;
  page_size?: number;
  actor_id?: string;
  action_type?: string;
  target_id?: string;
  start_date?: string;
  end_date?: string;
}

// Create the API
export const dashboardApi = createApi({
  reducerPath: 'dashboardApi',
  baseQuery: fetchBaseQuery({
    baseUrl: '/api/admin/dashboard',
    prepareHeaders: (headers, { getState }) => {
      const token = (getState() as RootState).auth.token;
      if (token) {
        headers.set('Authorization', `Bearer ${token}`);
      }
      return headers;
    },
  }),
  tagTypes: ['Health', 'Metrics', 'Users', 'Events', 'Risk', 'Audit'],
  endpoints: (builder) => ({
    // System Health
    getSystemHealth: builder.query<SystemHealth, void>({
      query: () => '/health',
      providesTags: ['Health'],
    }),

    // System Metrics
    getSystemMetrics: builder.query<SystemMetrics, string>({
      query: (timeRange) => `/metrics?time_range=${timeRange}`,
      providesTags: ['Metrics'],
    }),

    // Active Users
    getActiveUsers: builder.query<
      ActiveUsersResponse,
      { page?: number; page_size?: number; sort_by?: string }
    >({
      query: ({ page = 1, page_size = 50, sort_by = 'login_time' }) =>
        `/users/active?page=${page}&page_size=${page_size}&sort_by=${sort_by}`,
      providesTags: ['Users'],
    }),

    // User Stats
    getUserStats: builder.query<UserStats, void>({
      query: () => '/users/stats',
      providesTags: ['Users'],
    }),

    // User Detail
    getUserDetail: builder.query<UserDetail, string>({
      query: (userId) => `/users/${userId}`,
      providesTags: (_result, _error, id) => [{ type: 'Users', id }],
    }),

    // Force Logout User
    forceLogoutUser: builder.mutation<{ success: boolean; message: string; tokens_revoked: number }, string>({
      query: (userId) => ({
        url: `/users/${userId}/force-logout`,
        method: 'POST',
      }),
      invalidatesTags: ['Users'],
    }),

    // Events
    getEvents: builder.query<
      EventsResponse,
      { limit?: number; event_types?: string; severity?: string; since?: string }
    >({
      query: ({ limit = 100, event_types, severity, since }) => {
        const params = new URLSearchParams();
        params.append('limit', String(limit));
        if (event_types) params.append('event_types', event_types);
        if (severity) params.append('severity', severity);
        if (since) params.append('since', since);
        return `/events?${params.toString()}`;
      },
      providesTags: ['Events'],
    }),

    // Risk Summary
    getRiskSummary: builder.query<RiskSummary, string>({
      query: (timeRange) => `/risk/summary?time_range=${timeRange}`,
      providesTags: ['Risk'],
    }),

    // High Risk Users
    getHighRiskUsers: builder.query<HighRiskUsersResponse, { threshold?: number; limit?: number }>({
      query: ({ threshold = 70, limit = 20 }) =>
        `/risk/high-risk-users?threshold=${threshold}&limit=${limit}`,
      providesTags: ['Risk'],
    }),

    // Risk Rules
    getRiskRules: builder.query<{ rules: RiskRule[] }, void>({
      query: () => '/risk/rules',
      providesTags: ['Risk'],
    }),

    // Audit Logs
    getAuditLogs: builder.query<AuditLogsResponse, AuditLogFilters>({
      query: (filters) => {
        const params = new URLSearchParams();
        if (filters.page) params.append('page', String(filters.page));
        if (filters.page_size) params.append('page_size', String(filters.page_size));
        if (filters.actor_id) params.append('actor_id', filters.actor_id);
        if (filters.action_type) params.append('action_type', filters.action_type);
        if (filters.target_id) params.append('target_id', filters.target_id);
        if (filters.start_date) params.append('start_date', filters.start_date);
        if (filters.end_date) params.append('end_date', filters.end_date);
        return `/audit?${params.toString()}`;
      },
      providesTags: ['Audit'],
    }),

    // Audit Action Types
    getAuditActionTypes: builder.query<{ actions: string[] }, void>({
      query: () => '/audit/actions',
      providesTags: ['Audit'],
    }),

    // Export Audit Logs
    exportAuditLogs: builder.mutation<
      { success: boolean; format: string; count: number; message: string },
      AuditLogFilters & { format: 'csv' | 'json' }
    >({
      query: ({ format, ...filters }) => ({
        url: `/audit/export?format=${format}`,
        method: 'POST',
        params: filters,
      }),
    }),
  }),
});

// Export hooks
export const {
  useGetSystemHealthQuery,
  useGetSystemMetricsQuery,
  useGetActiveUsersQuery,
  useGetUserStatsQuery,
  useGetUserDetailQuery,
  useForceLogoutUserMutation,
  useGetEventsQuery,
  useGetRiskSummaryQuery,
  useGetHighRiskUsersQuery,
  useGetRiskRulesQuery,
  useGetAuditLogsQuery,
  useGetAuditActionTypesQuery,
  useExportAuditLogsMutation,
} = dashboardApi;
