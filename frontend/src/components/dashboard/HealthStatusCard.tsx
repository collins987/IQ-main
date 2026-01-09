import type { SystemHealth } from '../../services/dashboardApi';
import { formatPercent } from '../../utils/helpers';
import clsx from 'clsx';
import {
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
} from '@heroicons/react/24/solid';

interface HealthStatusCardProps {
  health?: SystemHealth;
  error?: string;
}

export default function HealthStatusCard({ health, error }: HealthStatusCardProps) {
  if (error) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">System Health</h3>
        </div>
        <div className="p-4 bg-red-500/10 rounded-lg text-red-400 text-sm">
          Failed to load health status: {error}
        </div>
      </div>
    );
  }
  
  if (!health) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">System Health</h3>
        </div>
        <p className="text-gray-400">Loading...</p>
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
      label: 'Some Systems Degraded',
    },
    critical: {
      icon: XCircleIcon,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
      label: 'Critical Issues Detected',
    },
  };
  
  const config = statusConfig[health.status];
  const StatusIcon = config.icon;
  
  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">System Health</h3>
        <span
          className={clsx(
            'badge',
            health.status === 'healthy' && 'badge-success',
            health.status === 'degraded' && 'badge-warning',
            health.status === 'critical' && 'badge-danger'
          )}
        >
          {formatPercent(health.overall_health_percent, 0)}
        </span>
      </div>
      
      {/* Overall Status */}
      <div className={clsx('p-4 rounded-lg mb-4', config.bg)}>
        <div className="flex items-center gap-3">
          <StatusIcon className={clsx('h-6 w-6', config.color)} />
          <span className={clsx('font-medium', config.color)}>{config.label}</span>
        </div>
      </div>
      
      {/* Services Grid */}
      <div className="grid grid-cols-2 gap-3">
        {Object.entries(health.services).map(([name, service]) => (
          <ServiceStatusItem key={name} name={name} service={service} />
        ))}
      </div>
    </div>
  );
}

interface ServiceStatusItemProps {
  name: string;
  service: {
    status: string;
    latency_ms?: number;
    error?: string;
  };
}

function ServiceStatusItem({ name, service }: ServiceStatusItemProps) {
  const isHealthy = service.status === 'healthy';
  const isUnavailable = service.status === 'not_configured' || service.status === 'unavailable';
  
  return (
    <div className="flex items-center justify-between p-3 rounded-lg bg-dashboard-bg">
      <div className="flex items-center gap-2">
        <span
          className={clsx(
            'w-2 h-2 rounded-full',
            isHealthy && 'bg-green-500 animate-pulse',
            isUnavailable && 'bg-gray-500',
            !isHealthy && !isUnavailable && 'bg-yellow-500 animate-pulse'
          )}
        />
        <span className="text-sm font-medium text-gray-300 capitalize">{name}</span>
      </div>
      <div className="text-right">
        <span
          className={clsx(
            'text-xs',
            isHealthy && 'text-green-400',
            isUnavailable && 'text-gray-500',
            !isHealthy && !isUnavailable && 'text-yellow-400'
          )}
        >
          {service.status}
        </span>
        {service.latency_ms !== undefined && (
          <p className="text-xs text-gray-500">{service.latency_ms}ms</p>
        )}
      </div>
    </div>
  );
}
