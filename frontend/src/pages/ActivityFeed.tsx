import { useState, useEffect } from 'react';
import { useAppSelector, useAppDispatch } from '../store/hooks';
import { useGetEventsQuery } from '../services/dashboardApi';
import { clearEvents } from '../features/dashboardSlice';
import { formatRelativeTime } from '../utils/helpers';
import LoadingSpinner from '../components/common/LoadingSpinner';
import clsx from 'clsx';
import {
  BoltIcon,
  ArrowPathIcon,
  FunnelIcon,
  PauseIcon,
  PlayIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';

const severityConfig = {
  info: { color: 'text-blue-400', bg: 'bg-blue-500/10' },
  warning: { color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
  high: { color: 'text-red-400', bg: 'bg-red-500/10' },
  critical: { color: 'text-red-600', bg: 'bg-red-600/20' },
};

const eventTypeConfig: Record<string, { label: string; color: string }> = {
  login: { label: 'Login', color: 'text-green-400' },
  logout: { label: 'Logout', color: 'text-gray-400' },
  user_action: { label: 'User', color: 'text-blue-400' },
  admin_action: { label: 'Admin', color: 'text-purple-400' },
  risk: { label: 'Risk', color: 'text-red-400' },
  system: { label: 'System', color: 'text-yellow-400' },
};

export default function ActivityFeed() {
  const dispatch = useAppDispatch();
  const { liveEventsEnabled, recentEvents } = useAppSelector((state) => state.dashboard);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  
  // Fetch historical events
  const { data: historicalEvents, isLoading, refetch } = useGetEventsQuery({
    limit: 100,
    severity: severityFilter !== 'all' ? severityFilter : undefined,
  });
  
  // Combine live events with historical events
  const allEvents = [
    ...recentEvents,
    ...(historicalEvents?.events.filter(
      (e) => !recentEvents.some((re) => re.id === e.id)
    ) ?? []),
  ];
  
  // Apply filters
  const filteredEvents = allEvents.filter((event) => {
    if (severityFilter !== 'all' && event.severity !== severityFilter) return false;
    if (typeFilter !== 'all' && event.type !== typeFilter) return false;
    return true;
  });
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <LoadingSpinner size="lg" />
      </div>
    );
  }
  
  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <BoltIcon className="h-8 w-8 text-sentinel-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">Activity Feed</h1>
            <p className="text-gray-400 mt-1">
              Real-time stream of all system events
            </p>
          </div>
        </div>
        
        {/* Live Status */}
        <div className="flex items-center gap-3">
          <div
            className={clsx(
              'flex items-center gap-2 px-4 py-2 rounded-lg',
              liveEventsEnabled ? 'bg-green-500/10' : 'bg-gray-500/10'
            )}
          >
            {liveEventsEnabled ? (
              <>
                <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                <span className="text-sm text-green-400">Live</span>
              </>
            ) : (
              <>
                <PauseIcon className="h-4 w-4 text-gray-400" />
                <span className="text-sm text-gray-400">Paused</span>
              </>
            )}
          </div>
          
          <button
            onClick={() => refetch()}
            className="btn-ghost p-2"
            title="Refresh"
          >
            <ArrowPathIcon className="h-5 w-5" />
          </button>
          
          <button
            onClick={() => dispatch(clearEvents())}
            className="btn-ghost p-2"
            title="Clear live events"
          >
            <TrashIcon className="h-5 w-5" />
          </button>
        </div>
      </div>
      
      {/* Filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center gap-4">
          <div className="flex items-center gap-2">
            <FunnelIcon className="h-5 w-5 text-gray-400" />
            <span className="text-sm text-gray-400">Filters:</span>
          </div>
          
          <div className="flex items-center gap-4">
            <div>
              <label className="block text-xs text-gray-500 mb-1">Severity</label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="input py-1.5 w-32"
              >
                <option value="all">All</option>
                <option value="info">Info</option>
                <option value="warning">Warning</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            
            <div>
              <label className="block text-xs text-gray-500 mb-1">Type</label>
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="input py-1.5 w-32"
              >
                <option value="all">All</option>
                <option value="login">Login</option>
                <option value="logout">Logout</option>
                <option value="user_action">User Action</option>
                <option value="admin_action">Admin Action</option>
                <option value="risk">Risk</option>
                <option value="system">System</option>
              </select>
            </div>
          </div>
          
          <div className="ml-auto text-sm text-gray-400">
            {filteredEvents.length} events
          </div>
        </div>
      </div>
      
      {/* Events List */}
      <div className="space-y-3">
        {filteredEvents.length === 0 ? (
          <div className="card py-12 text-center">
            <BoltIcon className="h-12 w-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">No events to display</p>
            <p className="text-sm text-gray-500 mt-1">Events will appear here in real-time</p>
          </div>
        ) : (
          filteredEvents.map((event, index) => {
            const severity = severityConfig[event.severity] || severityConfig.info;
            const eventType = eventTypeConfig[event.type] || { label: event.type, color: 'text-gray-400' };
            const isNew = index < recentEvents.length && recentEvents.some((e) => e.id === event.id);
            
            return (
              <div
                key={event.id}
                className={clsx(
                  'card p-4 transition-all duration-300',
                  isNew && 'border-l-2 border-sentinel-500 animate-slide-in'
                )}
              >
                <div className="flex items-start gap-4">
                  {/* Severity Indicator */}
                  <div className={clsx('p-2 rounded-lg', severity.bg)}>
                    <div className={clsx('w-2 h-2 rounded-full', severity.color.replace('text-', 'bg-'))} />
                  </div>
                  
                  {/* Event Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={clsx('text-xs font-medium px-2 py-0.5 rounded', eventType.color, 'bg-dashboard-bg')}>
                        {eventType.label}
                      </span>
                      <span className={clsx('text-xs font-medium', severity.color)}>
                        {event.severity.toUpperCase()}
                      </span>
                      {isNew && (
                        <span className="text-xs text-sentinel-400 font-medium">NEW</span>
                      )}
                    </div>
                    
                    <p className="text-white font-medium">{event.message}</p>
                    
                    <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                      <span>Action: {event.action}</span>
                      {event.target && <span>Target: {event.target}</span>}
                      {event.actor_id && <span>Actor: {event.actor_id.slice(0, 8)}...</span>}
                    </div>
                  </div>
                  
                  {/* Timestamp */}
                  <div className="text-right flex-shrink-0">
                    <p className="text-sm text-gray-400">
                      {formatRelativeTime(event.timestamp)}
                    </p>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
