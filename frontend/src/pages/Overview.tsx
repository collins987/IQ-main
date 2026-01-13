import { useAppSelector } from '../store/hooks';
import {
  useGetSystemHealthQuery,
  useGetUserStatsQuery,
  useGetRiskSummaryQuery,
  useGetEventsQuery,
} from '../services/dashboardApi';
import StatsCard from '../components/dashboard/StatsCard';
import HealthStatusCard from '../components/dashboard/HealthStatusCard';
import RiskSummaryCard from '../components/dashboard/RiskSummaryCard';
import LoginTrendChart from '../components/dashboard/LoginTrendChart';
import RecentEventsCard from '../components/dashboard/RecentEventsCard';
import ActiveSessionsCard from '../components/dashboard/ActiveSessionsCard';
import LoadingSpinner from '../components/common/LoadingSpinner';
import {
  UsersIcon,
  UserGroupIcon,
  ShieldExclamationIcon,
  ClockIcon,
} from '@heroicons/react/24/outline';

export default function Overview() {
  const { selectedTimeRange } = useAppSelector((state) => state.dashboard);
  const { isAuthenticated } = useAppSelector((state) => state.auth);
  
  // Fetch all dashboard data - skip if not authenticated
  const { data: health, isLoading: healthLoading, error: healthError } = useGetSystemHealthQuery(undefined, { skip: !isAuthenticated });
  const { data: userStats, isLoading: statsLoading } = useGetUserStatsQuery(undefined, { skip: !isAuthenticated });
  const { data: riskSummary, isLoading: riskLoading } = useGetRiskSummaryQuery(selectedTimeRange, { skip: !isAuthenticated });
  const { data: events, isLoading: eventsLoading } = useGetEventsQuery({ limit: 10 }, { skip: !isAuthenticated });
  
  const isLoading = healthLoading || statsLoading || riskLoading || eventsLoading;
  
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
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard Overview</h1>
          <p className="text-gray-400 mt-1">
            Real-time security intelligence and system monitoring
          </p>
        </div>
        <div className="text-sm text-gray-400">
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>
      
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatsCard
          title="Total Users"
          value={userStats?.total_users ?? 0}
          change="+12%"
          changeType="increase"
          icon={UsersIcon}
        />
        <StatsCard
          title="Active Sessions"
          value={userStats?.active_sessions ?? 0}
          subtitle="Currently online"
          icon={UserGroupIcon}
        />
        <StatsCard
          title="Risk Events"
          value={riskSummary?.summary.flagged ?? 0}
          change="-5%"
          changeType="decrease"
          icon={ShieldExclamationIcon}
        />
        <StatsCard
          title="Active Today"
          value={userStats?.active_today ?? 0}
          subtitle="Logged in today"
          icon={ClockIcon}
        />
      </div>
      
      {/* System Health & Risk Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <HealthStatusCard
          health={health}
          error={healthError ? String(healthError) : undefined}
        />
        <RiskSummaryCard
          summary={riskSummary}
          timeRange={selectedTimeRange}
        />
      </div>
      
      {/* Charts & Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Login Trend Chart */}
        <div className="lg:col-span-2">
          <LoginTrendChart data={userStats?.login_trend ?? []} />
        </div>
        
        {/* Active Sessions */}
        <ActiveSessionsCard />
      </div>
      
      {/* Recent Events */}
      <RecentEventsCard events={events?.events ?? []} />
    </div>
  );
}
