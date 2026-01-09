import { useParams, useNavigate } from 'react-router-dom';
import {
  useGetUserDetailQuery,
  useForceLogoutUserMutation,
} from '../services/dashboardApi';
import {
  formatDate,
  formatRelativeTime,
  getInitials,
  getRiskLevel,
  getRiskColorClass,
  getRiskBgClass,
  getRoleBadgeClass,
  getStatusBadgeClass,
} from '../utils/helpers';
import LoadingSpinner from '../components/common/LoadingSpinner';
import clsx from 'clsx';
import {
  ArrowLeftIcon,
  ShieldCheckIcon,
  UserIcon,
  ClockIcon,
  ComputerDesktopIcon,
  ExclamationTriangleIcon,
  ArrowRightOnRectangleIcon,
} from '@heroicons/react/24/outline';
import { useState } from 'react';

export default function UserDetail() {
  const { userId } = useParams<{ userId: string }>();
  const navigate = useNavigate();
  const [showConfirmLogout, setShowConfirmLogout] = useState(false);
  
  const { data: user, isLoading, error } = useGetUserDetailQuery(userId!, {
    skip: !userId,
  });
  
  const [forceLogout, { isLoading: isLoggingOut }] = useForceLogoutUserMutation();
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <LoadingSpinner size="lg" />
      </div>
    );
  }
  
  if (error || !user) {
    return (
      <div className="card max-w-lg mx-auto mt-12">
        <div className="text-center py-8">
          <ExclamationTriangleIcon className="h-12 w-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">User Not Found</h2>
          <p className="text-gray-400 mb-4">
            The requested user could not be found or you don't have permission to view them.
          </p>
          <button onClick={() => navigate('/users')} className="btn-primary">
            Back to Users
          </button>
        </div>
      </div>
    );
  }
  
  const riskLevel = getRiskLevel(user.security.risk_score);
  
  const handleForceLogout = async () => {
    try {
      await forceLogout(userId!).unwrap();
      setShowConfirmLogout(false);
    } catch (err) {
      console.error('Failed to force logout:', err);
    }
  };
  
  return (
    <div className="space-y-6 animate-fade-in">
      {/* Back Button */}
      <button
        onClick={() => navigate('/users')}
        className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
      >
        <ArrowLeftIcon className="h-4 w-4" />
        <span>Back to Users</span>
      </button>
      
      {/* Header */}
      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 bg-sentinel-600 rounded-full flex items-center justify-center text-white text-xl font-bold">
              {getInitials(user.profile.first_name, user.profile.last_name)}
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">
                {user.profile.first_name} {user.profile.last_name}
              </h1>
              <p className="text-gray-400">{user.profile.email}</p>
              <div className="flex items-center gap-2 mt-2">
                <span className={clsx('badge capitalize', getRoleBadgeClass(user.profile.role))}>
                  {user.profile.role}
                </span>
                <span className={clsx('badge capitalize', getStatusBadgeClass(user.security.status))}>
                  {user.security.status}
                </span>
                {user.security.is_system_user && (
                  <span className="badge badge-info">System User</span>
                )}
              </div>
            </div>
          </div>
          
          {/* Actions */}
          <div className="flex items-center gap-3">
            {user.session.active_sessions > 0 && (
              <button
                onClick={() => setShowConfirmLogout(true)}
                className="btn-danger flex items-center gap-2"
                disabled={isLoggingOut}
              >
                <ArrowRightOnRectangleIcon className="h-4 w-4" />
                Force Logout
              </button>
            )}
          </div>
        </div>
      </div>
      
      {/* Details Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Profile Info */}
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <UserIcon className="h-5 w-5 text-sentinel-400" />
            <h3 className="card-title">Profile</h3>
          </div>
          <dl className="space-y-3">
            <div>
              <dt className="text-sm text-gray-400">User ID</dt>
              <dd className="text-sm text-white font-mono mt-0.5">{user.profile.id}</dd>
            </div>
            <div>
              <dt className="text-sm text-gray-400">Organization</dt>
              <dd className="text-sm text-white mt-0.5">{user.profile.org_id || 'None'}</dd>
            </div>
            <div>
              <dt className="text-sm text-gray-400">Created</dt>
              <dd className="text-sm text-white mt-0.5">
                {user.profile.created_at ? formatDate(user.profile.created_at) : 'N/A'}
              </dd>
            </div>
            <div>
              <dt className="text-sm text-gray-400">Updated</dt>
              <dd className="text-sm text-white mt-0.5">
                {user.profile.updated_at ? formatDate(user.profile.updated_at) : 'N/A'}
              </dd>
            </div>
          </dl>
        </div>
        
        {/* Security Info */}
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <ShieldCheckIcon className="h-5 w-5 text-sentinel-400" />
            <h3 className="card-title">Security</h3>
          </div>
          
          {/* Risk Score */}
          <div className={clsx('p-4 rounded-lg mb-4', getRiskBgClass(riskLevel))}>
            <p className="text-sm text-gray-400">Risk Score</p>
            <div className="flex items-center gap-2 mt-1">
              <span className={clsx('text-3xl font-bold', getRiskColorClass(riskLevel))}>
                {user.security.risk_score}
              </span>
              <span className={clsx('badge capitalize', getRiskBgClass(riskLevel), getRiskColorClass(riskLevel))}>
                {riskLevel}
              </span>
            </div>
          </div>
          
          <dl className="space-y-3">
            <div className="flex items-center justify-between">
              <dt className="text-sm text-gray-400">Email Verified</dt>
              <dd>
                <span className={clsx('badge', user.security.email_verified ? 'badge-success' : 'badge-warning')}>
                  {user.security.email_verified ? 'Yes' : 'No'}
                </span>
              </dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-sm text-gray-400">Account Active</dt>
              <dd>
                <span className={clsx('badge', user.security.is_active ? 'badge-success' : 'badge-danger')}>
                  {user.security.is_active ? 'Yes' : 'No'}
                </span>
              </dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-sm text-gray-400">Visibility</dt>
              <dd className="text-sm text-white capitalize">{user.security.visibility}</dd>
            </div>
          </dl>
        </div>
        
        {/* Session Info */}
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <ClockIcon className="h-5 w-5 text-sentinel-400" />
            <h3 className="card-title">Session</h3>
          </div>
          
          <dl className="space-y-3">
            <div>
              <dt className="text-sm text-gray-400">Active Sessions</dt>
              <dd className="text-xl font-bold text-green-400 mt-0.5">
                {user.session.active_sessions}
              </dd>
            </div>
            <div>
              <dt className="text-sm text-gray-400">Last Login</dt>
              <dd className="text-sm text-white mt-0.5">
                {user.session.last_login_at
                  ? formatRelativeTime(user.session.last_login_at)
                  : 'Never'}
              </dd>
            </div>
            <div>
              <dt className="text-sm text-gray-400">Last IP</dt>
              <dd className="text-sm text-white font-mono mt-0.5">
                {user.session.last_login_ip || 'N/A'}
              </dd>
            </div>
            <div>
              <dt className="text-sm text-gray-400">Device</dt>
              <dd className="text-sm text-white mt-0.5">
                {user.session.last_device_info || 'Unknown'}
              </dd>
            </div>
          </dl>
        </div>
      </div>
      
      {/* Activity */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="card-title">Recent Activity</h3>
          {user.activity.failed_logins_24h > 0 && (
            <span className="badge badge-warning">
              {user.activity.failed_logins_24h} failed login(s) in 24h
            </span>
          )}
        </div>
        
        {user.activity.recent_actions.length === 0 ? (
          <p className="text-gray-400 text-center py-4">No recent activity</p>
        ) : (
          <div className="space-y-2">
            {user.activity.recent_actions.map((action, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-3 rounded-lg bg-dashboard-bg"
              >
                <div>
                  <p className="text-sm text-white">{action.action.replace(/_/g, ' ')}</p>
                  {action.target && (
                    <p className="text-xs text-gray-500">Target: {action.target}</p>
                  )}
                </div>
                <span className="text-xs text-gray-400">
                  {action.timestamp ? formatRelativeTime(action.timestamp) : 'N/A'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Confirm Logout Modal */}
      {showConfirmLogout && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="card max-w-md mx-4">
            <h3 className="text-lg font-semibold text-white mb-4">Confirm Force Logout</h3>
            <p className="text-gray-400 mb-6">
              Are you sure you want to force logout{' '}
              <span className="text-white">{user.profile.email}</span>? This will revoke all their
              active sessions.
            </p>
            <div className="flex items-center justify-end gap-3">
              <button
                onClick={() => setShowConfirmLogout(false)}
                className="btn-secondary"
                disabled={isLoggingOut}
              >
                Cancel
              </button>
              <button
                onClick={handleForceLogout}
                className="btn-danger"
                disabled={isLoggingOut}
              >
                {isLoggingOut ? 'Logging out...' : 'Force Logout'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
