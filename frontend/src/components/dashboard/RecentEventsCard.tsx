import type { DashboardEvent } from '../../services/dashboardApi';
import { formatRelativeTime } from '../../utils/helpers';
import { Link } from 'react-router-dom';
import clsx from 'clsx';
import {
  UserPlusIcon,
  ArrowRightOnRectangleIcon,
  ShieldExclamationIcon,
  Cog6ToothIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

interface RecentEventsCardProps {
  events: DashboardEvent[];
}

const eventIcons: Record<string, typeof UserPlusIcon> = {
  login: ArrowRightOnRectangleIcon,
  logout: ArrowRightOnRectangleIcon,
  user_action: UserPlusIcon,
  admin_action: Cog6ToothIcon,
  risk: ShieldExclamationIcon,
  system: Cog6ToothIcon,
};

const severityColors: Record<string, string> = {
  info: 'text-blue-400 bg-blue-500/10',
  warning: 'text-yellow-400 bg-yellow-500/10',
  high: 'text-red-400 bg-red-500/10',
  critical: 'text-red-600 bg-red-600/20',
};

export default function RecentEventsCard({ events }: RecentEventsCardProps) {
  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">Recent Events</h3>
        <Link to="/activity" className="text-sm text-sentinel-400 hover:text-sentinel-300">
          View all →
        </Link>
      </div>
      
      {events.length === 0 ? (
        <div className="py-8 text-center text-gray-400">
          <ExclamationTriangleIcon className="h-10 w-10 mx-auto mb-2 opacity-50" />
          <p>No recent events</p>
        </div>
      ) : (
        <div className="space-y-3">
          {events.map((event) => {
            const Icon = eventIcons[event.type] || Cog6ToothIcon;
            const colorClass = severityColors[event.severity] || severityColors.info;
            
            return (
              <div
                key={event.id}
                className="flex items-start gap-3 p-3 rounded-lg bg-dashboard-bg hover:bg-dashboard-hover/50 transition-colors"
              >
                <div className={clsx('p-2 rounded-lg', colorClass.split(' ')[1])}>
                  <Icon className={clsx('h-4 w-4', colorClass.split(' ')[0])} />
                </div>
                
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white truncate">{event.message}</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {event.action} • {event.target || 'System'}
                  </p>
                </div>
                
                <div className="text-right flex-shrink-0">
                  <span className={clsx('badge text-[10px]', `badge-${event.severity === 'high' || event.severity === 'critical' ? 'danger' : event.severity === 'warning' ? 'warning' : 'info'}`)}>
                    {event.severity}
                  </span>
                  <p className="text-xs text-gray-500 mt-1">
                    {formatRelativeTime(event.timestamp)}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
