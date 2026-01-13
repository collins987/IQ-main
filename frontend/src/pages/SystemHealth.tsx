import { useGetSystemHealthQuery, useGetSystemMetricsQuery } from '../services/dashboardApi';
import { useAppSelector } from '../store/hooks';
import { formatNumber } from '../utils/helpers';
import LoadingSpinner from '../components/common/LoadingSpinner';
import clsx from 'clsx';
import {
  ServerIcon,
  CircleStackIcon,
  CpuChipIcon,
  GlobeAltIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  SignalIcon,
} from '@heroicons/react/24/outline';

export default function SystemHealth() {
  const { selectedTimeRange } = useAppSelector((state) => state.dashboard);
  const { isAuthenticated } = useAppSelector((state) => state.auth);
  
  const { data: health, isLoading: healthLoading, error: healthError } = useGetSystemHealthQuery(undefined, { skip: !isAuthenticated });
  const { data: metrics, isLoading: metricsLoading } = useGetSystemMetricsQuery(selectedTimeRange, { skip: !isAuthenticated });
  
  const isLoading = healthLoading || metricsLoading;
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <LoadingSpinner size="lg" />
      </div>
    );
  }
  
  const statusConfig = {
    healthy: {
      icon: CheckCircleIcon,
      color: 'text-green-400',
      bg: 'bg-green-500/10',
      label: 'All Systems Operational',
    },
    degraded: {
      icon: ExclamationTriangleIcon,
      color: 'text-yellow-400',
      bg: 'bg-yellow-500/10',
      label: 'Performance Degraded',
    },
    critical: {
      icon: XCircleIcon,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
      label: 'Critical Issues Detected',
    },
  };
  
  const currentStatus = health?.status ? statusConfig[health.status] : statusConfig.healthy;
  const StatusIcon = currentStatus.icon;
  
  const serviceIcons: Record<string, typeof ServerIcon> = {
    database: CircleStackIcon,
    redis: CpuChipIcon,
    kafka: SignalIcon,
    vault: GlobeAltIcon,
  };
  
  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ServerIcon className="h-8 w-8 text-sentinel-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">System Health</h1>
            <p className="text-gray-400 mt-1">
              Monitor infrastructure and service health
            </p>
          </div>
        </div>
        
        <span className="text-sm text-gray-400">
          Last checked: {health?.timestamp ? new Date(health.timestamp).toLocaleTimeString() : 'N/A'}
        </span>
      </div>
      
      {/* Overall Status */}
      <div className={clsx('card', currentStatus.bg)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <StatusIcon className={clsx('h-12 w-12', currentStatus.color)} />
            <div>
              <h2 className={clsx('text-2xl font-bold', currentStatus.color)}>
                {currentStatus.label}
              </h2>
              <p className="text-gray-400 mt-1">
                Overall health: {health?.overall_health_percent ?? 0}%
              </p>
            </div>
          </div>
          
          {/* Health Percentage Gauge */}
          <div className="w-32 h-32 relative">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                className="text-dashboard-border"
                strokeWidth="8"
                stroke="currentColor"
                fill="transparent"
                r="40"
                cx="50"
                cy="50"
              />
              <circle
                className={health?.status === 'healthy' ? 'text-green-500' : health?.status === 'degraded' ? 'text-yellow-500' : 'text-red-500'}
                strokeWidth="8"
                strokeLinecap="round"
                stroke="currentColor"
                fill="transparent"
                r="40"
                cx="50"
                cy="50"
                style={{
                  strokeDasharray: `${(health?.overall_health_percent ?? 0) * 2.51} 251`,
                  transition: 'stroke-dasharray 0.5s ease',
                }}
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-2xl font-bold text-white">{health?.overall_health_percent ?? 0}%</span>
            </div>
          </div>
        </div>
      </div>
      
      {/* Services Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {health?.services && Object.entries(health.services).map(([name, service]) => {
          const ServiceIcon = serviceIcons[name] || ServerIcon;
          const isHealthy = service.status === 'healthy';
          const isUnavailable = service.status === 'not_configured' || service.status === 'unavailable';
          
          return (
            <div key={name} className="card">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <ServiceIcon className="h-5 w-5 text-gray-400" />
                  <h3 className="font-medium text-white capitalize">{name}</h3>
                </div>
                <span
                  className={clsx(
                    'w-3 h-3 rounded-full',
                    isHealthy && 'bg-green-500 animate-pulse',
                    isUnavailable && 'bg-gray-500',
                    !isHealthy && !isUnavailable && 'bg-yellow-500 animate-pulse'
                  )}
                />
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-400">Status</span>
                  <span
                    className={clsx(
                      'text-sm font-medium capitalize',
                      isHealthy && 'text-green-400',
                      isUnavailable && 'text-gray-500',
                      !isHealthy && !isUnavailable && 'text-yellow-400'
                    )}
                  >
                    {service.status.replace('_', ' ')}
                  </span>
                </div>
                
                {service.latency_ms !== undefined && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-400">Latency</span>
                    <span className="text-sm text-white">{service.latency_ms}ms</span>
                  </div>
                )}
                
                {service.connections_active !== undefined && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-400">Connections</span>
                    <span className="text-sm text-white">
                      {service.connections_active}/{service.connections_max}
                    </span>
                  </div>
                )}
                
                {service.memory_mb !== undefined && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-400">Memory</span>
                    <span className="text-sm text-white">{service.memory_mb} MB</span>
                  </div>
                )}
                
                {service.error && (
                  <p className="text-xs text-red-400 mt-2">{service.error}</p>
                )}
              </div>
            </div>
          );
        })}
      </div>
      
      {/* Performance Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Latency */}
        <div className="card">
          <h3 className="card-title mb-4">Response Latency</h3>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-green-400">{metrics?.latency.p50_ms ?? 0}</p>
              <p className="text-sm text-gray-400 mt-1">P50 (ms)</p>
            </div>
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-yellow-400">{metrics?.latency.p95_ms ?? 0}</p>
              <p className="text-sm text-gray-400 mt-1">P95 (ms)</p>
            </div>
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-red-400">{metrics?.latency.p99_ms ?? 0}</p>
              <p className="text-sm text-gray-400 mt-1">P99 (ms)</p>
            </div>
          </div>
        </div>
        
        {/* Throughput */}
        <div className="card">
          <h3 className="card-title mb-4">Throughput</h3>
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-sentinel-400">
                {metrics?.throughput.requests_per_second ?? 0}
              </p>
              <p className="text-sm text-gray-400 mt-1">Requests/sec</p>
            </div>
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-white">
                {formatNumber(metrics?.throughput.total_requests ?? 0)}
              </p>
              <p className="text-sm text-gray-400 mt-1">Total Requests</p>
            </div>
          </div>
        </div>
        
        {/* Errors */}
        <div className="card">
          <h3 className="card-title mb-4">Error Rates</h3>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-yellow-400">
                {metrics?.errors.rate_percent ?? 0}%
              </p>
              <p className="text-sm text-gray-400 mt-1">Error Rate</p>
            </div>
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-orange-400">{metrics?.errors.count_4xx ?? 0}</p>
              <p className="text-sm text-gray-400 mt-1">4xx Errors</p>
            </div>
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-red-400">{metrics?.errors.count_5xx ?? 0}</p>
              <p className="text-sm text-gray-400 mt-1">5xx Errors</p>
            </div>
          </div>
        </div>
        
        {/* Database */}
        <div className="card">
          <h3 className="card-title mb-4">Database Performance</h3>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-sentinel-400">
                {metrics?.database.avg_query_ms ?? 0}
              </p>
              <p className="text-sm text-gray-400 mt-1">Avg Query (ms)</p>
            </div>
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-yellow-400">
                {metrics?.database.slow_queries ?? 0}
              </p>
              <p className="text-sm text-gray-400 mt-1">Slow Queries</p>
            </div>
            <div className="text-center p-4 rounded-lg bg-dashboard-bg">
              <p className="text-3xl font-bold text-white">
                {metrics?.database.connections_used ?? 0}
              </p>
              <p className="text-sm text-gray-400 mt-1">Connections</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
