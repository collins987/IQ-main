import { useGetActiveUsersQuery } from '../../services/dashboardApi';
import { formatRelativeTime, getInitials, getRiskLevel, getRiskColorClass } from '../../utils/helpers';
import { Link } from 'react-router-dom';
import clsx from 'clsx';
import LoadingSpinner from '../common/LoadingSpinner';
import { useAppSelector } from '../../store/hooks';

export default function ActiveSessionsCard() {
  const { isAuthenticated } = useAppSelector((state) => state.auth);
  const { data, isLoading, error } = useGetActiveUsersQuery({
    page: 1,
    page_size: 5,
    sort_by: 'login_time',
  }, { skip: !isAuthenticated });
  
  if (isLoading) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Active Sessions</h3>
        </div>
        <div className="flex items-center justify-center h-48">
          <LoadingSpinner />
        </div>
      </div>
    );
  }
  
  if (error) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Active Sessions</h3>
        </div>
        <p className="text-red-400 text-sm">Failed to load active sessions</p>
      </div>
    );
  }
  
  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">Active Sessions</h3>
        <span className="badge badge-success">{data?.active_sessions ?? 0} online</span>
      </div>
      
      {data?.users.length === 0 ? (
        <p className="text-gray-400 text-center py-4">No active sessions</p>
      ) : (
        <div className="space-y-3">
          {data?.users.map((user) => {
            const riskLevel = getRiskLevel(user.risk_score);
            
            return (
              <Link
                key={user.id}
                to={`/users/${user.id}`}
                className="flex items-center gap-3 p-2 rounded-lg hover:bg-dashboard-hover transition-colors"
              >
                {/* Avatar */}
                <div className="w-10 h-10 bg-sentinel-600 rounded-full flex items-center justify-center text-white font-medium">
                  {getInitials(user.first_name, user.last_name)}
                </div>
                
                {/* User Info */}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">
                    {user.first_name} {user.last_name}
                  </p>
                  <p className="text-xs text-gray-500 truncate">{user.email}</p>
                </div>
                
                {/* Risk Score */}
                <div className="text-right">
                  <span className={clsx('text-xs font-medium', getRiskColorClass(riskLevel))}>
                    {user.risk_score}
                  </span>
                  <p className="text-xs text-gray-500">
                    {formatRelativeTime(user.login_time)}
                  </p>
                </div>
              </Link>
            );
          })}
        </div>
      )}
      
      <div className="mt-4 pt-4 border-t border-dashboard-border">
        <Link
          to="/users"
          className="block w-full text-center text-sm text-sentinel-400 hover:text-sentinel-300"
        >
          View all users →
        </Link>
      </div>
    </div>
  );
}
