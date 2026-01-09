import type { RiskSummary } from '../../services/dashboardApi';
import { formatNumber, formatPercent } from '../../utils/helpers';
import clsx from 'clsx';
import {
  ShieldCheckIcon,
  ExclamationCircleIcon,
  EyeIcon,
  NoSymbolIcon,
} from '@heroicons/react/24/outline';

interface RiskSummaryCardProps {
  summary?: RiskSummary;
  timeRange: string;
}

export default function RiskSummaryCard({ summary, timeRange }: RiskSummaryCardProps) {
  if (!summary) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Risk Summary</h3>
        </div>
        <p className="text-gray-400">Loading...</p>
      </div>
    );
  }
  
  const timeLabels: Record<string, string> = {
    '1h': 'Last Hour',
    '6h': 'Last 6 Hours',
    '24h': 'Last 24 Hours',
    '7d': 'Last 7 Days',
  };
  
  const metrics = [
    {
      label: 'Allowed',
      value: summary.summary.allowed,
      icon: ShieldCheckIcon,
      color: 'text-green-400',
      bg: 'bg-green-500/10',
    },
    {
      label: 'Flagged',
      value: summary.summary.flagged,
      icon: ExclamationCircleIcon,
      color: 'text-yellow-400',
      bg: 'bg-yellow-500/10',
    },
    {
      label: 'Reviewed',
      value: summary.summary.reviewed,
      icon: EyeIcon,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
    },
    {
      label: 'Blocked',
      value: summary.summary.blocked,
      icon: NoSymbolIcon,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
    },
  ];
  
  // Calculate total for percentages
  const total = Object.values(summary.summary).reduce((acc, val) => acc + val, 0);
  
  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">Risk Summary</h3>
        <span className="text-sm text-gray-400">{timeLabels[timeRange]}</span>
      </div>
      
      {/* Metrics Grid */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        {metrics.map((metric) => {
          const MetricIcon = metric.icon;
          return (
            <div key={metric.label} className={clsx('p-3 rounded-lg', metric.bg)}>
              <div className="flex items-center gap-2 mb-1">
                <MetricIcon className={clsx('h-4 w-4', metric.color)} />
                <span className="text-xs text-gray-400">{metric.label}</span>
              </div>
              <p className={clsx('text-xl font-bold', metric.color)}>
                {formatNumber(metric.value)}
              </p>
            </div>
          );
        })}
      </div>
      
      {/* Risk Distribution */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-gray-400">Risk Distribution</span>
          <span className="text-sm text-gray-400">
            Avg Score: <span className="text-white font-medium">{summary.avg_risk_score}</span>
          </span>
        </div>
        
        {/* Progress Bar */}
        <div className="h-3 bg-dashboard-bg rounded-full overflow-hidden flex">
          {summary.risk_distribution.low > 0 && (
            <div
              className="bg-green-500 h-full"
              style={{
                width: `${(summary.risk_distribution.low / (summary.risk_distribution.low + summary.risk_distribution.medium + summary.risk_distribution.high)) * 100}%`,
              }}
            />
          )}
          {summary.risk_distribution.medium > 0 && (
            <div
              className="bg-yellow-500 h-full"
              style={{
                width: `${(summary.risk_distribution.medium / (summary.risk_distribution.low + summary.risk_distribution.medium + summary.risk_distribution.high)) * 100}%`,
              }}
            />
          )}
          {summary.risk_distribution.high > 0 && (
            <div
              className="bg-red-500 h-full"
              style={{
                width: `${(summary.risk_distribution.high / (summary.risk_distribution.low + summary.risk_distribution.medium + summary.risk_distribution.high)) * 100}%`,
              }}
            />
          )}
        </div>
        
        {/* Legend */}
        <div className="flex items-center justify-between mt-2 text-xs">
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 bg-green-500 rounded-full" />
            <span className="text-gray-400">Low ({summary.risk_distribution.low})</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 bg-yellow-500 rounded-full" />
            <span className="text-gray-400">Medium ({summary.risk_distribution.medium})</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 bg-red-500 rounded-full" />
            <span className="text-gray-400">High ({summary.risk_distribution.high})</span>
          </div>
        </div>
      </div>
      
      {/* Total Events */}
      <div className="text-center pt-3 border-t border-dashboard-border">
        <p className="text-sm text-gray-400">
          Total Events: <span className="text-white font-medium">{formatNumber(total)}</span>
        </p>
      </div>
    </div>
  );
}
