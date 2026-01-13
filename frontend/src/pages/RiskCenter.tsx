import { useState } from 'react';
import { useAppSelector } from '../store/hooks';
import {
  useGetRiskSummaryQuery,
  useGetHighRiskUsersQuery,
  useGetRiskRulesQuery,
} from '../services/dashboardApi';
import {
  formatNumber,
  getInitials,
  getRiskLevel,
  getRiskColorClass,
  getRiskBgClass,
  formatRelativeTime,
} from '../utils/helpers';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { Link } from 'react-router-dom';
import clsx from 'clsx';
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  EyeIcon,
  NoSymbolIcon,
  AdjustmentsHorizontalIcon,
} from '@heroicons/react/24/outline';

export default function RiskCenter() {
  const { selectedTimeRange } = useAppSelector((state) => state.dashboard);
  const { isAuthenticated } = useAppSelector((state) => state.auth);
  const [riskThreshold, setRiskThreshold] = useState(70);
  
  const { data: summary, isLoading: summaryLoading } = useGetRiskSummaryQuery(selectedTimeRange, { skip: !isAuthenticated });
  const { data: highRiskUsers, isLoading: usersLoading } = useGetHighRiskUsersQuery({
    threshold: riskThreshold,
    limit: 20,
  }, { skip: !isAuthenticated });
  const { data: rules, isLoading: rulesLoading } = useGetRiskRulesQuery(undefined, { skip: !isAuthenticated });
  
  const isLoading = summaryLoading || usersLoading || rulesLoading;
  
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
          <h1 className="text-2xl font-bold text-white">Risk Center</h1>
          <p className="text-gray-400 mt-1">
            Monitor risk events and manage high-risk users
          </p>
        </div>
      </div>
      
      {/* Risk Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard
          icon={CheckCircleIcon}
          label="Allowed"
          value={summary?.summary.allowed ?? 0}
          color="green"
        />
        <MetricCard
          icon={ExclamationTriangleIcon}
          label="Flagged"
          value={summary?.summary.flagged ?? 0}
          color="yellow"
        />
        <MetricCard
          icon={EyeIcon}
          label="Reviewed"
          value={summary?.summary.reviewed ?? 0}
          color="blue"
        />
        <MetricCard
          icon={NoSymbolIcon}
          label="Blocked"
          value={summary?.summary.blocked ?? 0}
          color="red"
        />
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution */}
        <div className="card lg:col-span-2">
          <div className="card-header">
            <h3 className="card-title">Risk Distribution</h3>
            <span className="text-sm text-gray-400">
              Avg Score: {summary?.avg_risk_score ?? 0}
            </span>
          </div>
          
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="p-4 rounded-lg bg-green-500/10 text-center">
              <p className="text-3xl font-bold text-green-400">
                {summary?.risk_distribution.low ?? 0}
              </p>
              <p className="text-sm text-gray-400 mt-1">Low Risk</p>
              <p className="text-xs text-gray-500">Score &lt; 30</p>
            </div>
            <div className="p-4 rounded-lg bg-yellow-500/10 text-center">
              <p className="text-3xl font-bold text-yellow-400">
                {summary?.risk_distribution.medium ?? 0}
              </p>
              <p className="text-sm text-gray-400 mt-1">Medium Risk</p>
              <p className="text-xs text-gray-500">Score 30-70</p>
            </div>
            <div className="p-4 rounded-lg bg-red-500/10 text-center">
              <p className="text-3xl font-bold text-red-400">
                {summary?.risk_distribution.high ?? 0}
              </p>
              <p className="text-sm text-gray-400 mt-1">High Risk</p>
              <p className="text-xs text-gray-500">Score &gt; 70</p>
            </div>
          </div>
          
          {/* Visual Distribution Bar */}
          <div className="h-6 bg-dashboard-bg rounded-full overflow-hidden flex">
            {summary && (
              <>
                {summary.risk_distribution.low > 0 && (
                  <div
                    className="bg-green-500 h-full transition-all duration-500"
                    style={{
                      width: `${(summary.risk_distribution.low / (summary.risk_distribution.low + summary.risk_distribution.medium + summary.risk_distribution.high || 1)) * 100}%`,
                    }}
                  />
                )}
                {summary.risk_distribution.medium > 0 && (
                  <div
                    className="bg-yellow-500 h-full transition-all duration-500"
                    style={{
                      width: `${(summary.risk_distribution.medium / (summary.risk_distribution.low + summary.risk_distribution.medium + summary.risk_distribution.high || 1)) * 100}%`,
                    }}
                  />
                )}
                {summary.risk_distribution.high > 0 && (
                  <div
                    className="bg-red-500 h-full transition-all duration-500"
                    style={{
                      width: `${(summary.risk_distribution.high / (summary.risk_distribution.low + summary.risk_distribution.medium + summary.risk_distribution.high || 1)) * 100}%`,
                    }}
                  />
                )}
              </>
            )}
          </div>
        </div>
        
        {/* Risk Rules */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Risk Rules</h3>
            <AdjustmentsHorizontalIcon className="h-5 w-5 text-gray-400" />
          </div>
          
          <div className="space-y-3">
            {rules?.rules.map((rule) => (
              <div
                key={rule.rule_id}
                className="flex items-center justify-between p-3 rounded-lg bg-dashboard-bg"
              >
                <span className="text-sm text-white">{rule.name}</span>
                <span className="text-sm text-gray-400">{rule.triggers} triggers</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      
      {/* High Risk Users */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center gap-2">
            <ShieldExclamationIcon className="h-5 w-5 text-red-400" />
            <h3 className="card-title">High Risk Users</h3>
          </div>
          
          {/* Threshold Selector */}
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-400">Threshold:</span>
            <select
              value={riskThreshold}
              onChange={(e) => setRiskThreshold(Number(e.target.value))}
              className="input py-1 w-24"
            >
              <option value={50}>50+</option>
              <option value={60}>60+</option>
              <option value={70}>70+</option>
              <option value={80}>80+</option>
              <option value={90}>90+</option>
            </select>
          </div>
        </div>
        
        {highRiskUsers?.users.length === 0 ? (
          <div className="py-8 text-center">
            <CheckCircleIcon className="h-12 w-12 text-green-400 mx-auto mb-3" />
            <p className="text-gray-400">No users above risk threshold {riskThreshold}</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Role</th>
                  <th>Risk Score</th>
                  <th>Status</th>
                  <th>Last Login</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {highRiskUsers?.users.map((user) => {
                  const riskLevel = getRiskLevel(user.risk_score);
                  
                  return (
                    <tr key={user.id}>
                      <td>
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 bg-red-600 rounded-full flex items-center justify-center text-white font-medium">
                            {getInitials(user.first_name, user.last_name)}
                          </div>
                          <div>
                            <p className="font-medium text-white">
                              {user.first_name} {user.last_name}
                            </p>
                            <p className="text-sm text-gray-500">{user.email}</p>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className="text-sm text-gray-300 capitalize">{user.role}</span>
                      </td>
                      <td>
                        <div className={clsx('inline-flex items-center gap-2 px-3 py-1 rounded-lg', getRiskBgClass(riskLevel))}>
                          <span className={clsx('font-bold', getRiskColorClass(riskLevel))}>
                            {user.risk_score}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="text-sm text-gray-300 capitalize">
                          {user.status || 'active'}
                        </span>
                      </td>
                      <td>
                        <span className="text-gray-400">
                          {user.last_login_at ? formatRelativeTime(user.last_login_at) : 'Never'}
                        </span>
                      </td>
                      <td>
                        <Link
                          to={`/users/${user.id}`}
                          className="text-sentinel-400 hover:text-sentinel-300 text-sm font-medium"
                        >
                          Investigate
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

interface MetricCardProps {
  icon: React.ForwardRefExoticComponent<React.SVGProps<SVGSVGElement>>;
  label: string;
  value: number;
  color: 'green' | 'yellow' | 'blue' | 'red';
}

function MetricCard({ icon: Icon, label, value, color }: MetricCardProps) {
  const colorClasses = {
    green: 'text-green-400 bg-green-500/10',
    yellow: 'text-yellow-400 bg-yellow-500/10',
    blue: 'text-blue-400 bg-blue-500/10',
    red: 'text-red-400 bg-red-500/10',
  };
  
  return (
    <div className={clsx('card py-4', colorClasses[color].split(' ')[1])}>
      <div className="flex items-center gap-3">
        <Icon className={clsx('h-8 w-8', colorClasses[color].split(' ')[0])} />
        <div>
          <p className={clsx('text-2xl font-bold', colorClasses[color].split(' ')[0])}>
            {formatNumber(value)}
          </p>
          <p className="text-sm text-gray-400">{label}</p>
        </div>
      </div>
    </div>
  );
}
