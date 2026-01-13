import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAppSelector } from '../store/hooks';
import { useGetActiveUsersQuery, useGetUserStatsQuery } from '../services/dashboardApi';
import {
  formatDate,
  getInitials,
  getRiskLevel,
  getRiskColorClass,
  getRoleBadgeClass,
  getStatusBadgeClass,
  maskEmail,
} from '../utils/helpers';
import LoadingSpinner from '../components/common/LoadingSpinner';
import clsx from 'clsx';
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  ArrowUpIcon,
  ArrowDownIcon,
} from '@heroicons/react/24/outline';

type SortField = 'login_time' | 'risk_score' | 'email';

export default function Users() {
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState<SortField>('login_time');
  const [searchQuery, setSearchQuery] = useState('');
  const { isAuthenticated } = useAppSelector((state) => state.auth);
  
  const { data: userStats, isLoading: statsLoading } = useGetUserStatsQuery(undefined, { skip: !isAuthenticated });
  const { data: usersData, isLoading: usersLoading, isFetching } = useGetActiveUsersQuery({
    page,
    page_size: 20,
    sort_by: sortBy,
  }, { skip: !isAuthenticated });
  
  const isLoading = statsLoading || usersLoading;
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <LoadingSpinner size="lg" />
      </div>
    );
  }
  
  // Filter users by search query (client-side for active users)
  const filteredUsers = usersData?.users.filter(
    (user) =>
      user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.first_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.last_name?.toLowerCase().includes(searchQuery.toLowerCase())
  ) ?? [];
  
  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">User Management</h1>
          <p className="text-gray-400 mt-1">
            Monitor and manage user accounts and sessions
          </p>
        </div>
      </div>
      
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card py-4">
          <p className="text-sm text-gray-400">Total Users</p>
          <p className="text-2xl font-bold text-white mt-1">{userStats?.total_users ?? 0}</p>
        </div>
        <div className="card py-4">
          <p className="text-sm text-gray-400">Active Sessions</p>
          <p className="text-2xl font-bold text-green-400 mt-1">{usersData?.active_sessions ?? 0}</p>
        </div>
        <div className="card py-4">
          <p className="text-sm text-gray-400">Verified</p>
          <p className="text-2xl font-bold text-blue-400 mt-1">
            {userStats?.verification.verified ?? 0}
            <span className="text-sm text-gray-500 ml-1">
              ({userStats?.verification.rate_percent ?? 0}%)
            </span>
          </p>
        </div>
        <div className="card py-4">
          <p className="text-sm text-gray-400">New This Week</p>
          <p className="text-2xl font-bold text-sentinel-400 mt-1">{userStats?.new_this_week ?? 0}</p>
        </div>
      </div>
      
      {/* Users Table */}
      <div className="card">
        {/* Table Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          {/* Search */}
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search users..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input pl-10 w-full md:w-80"
            />
          </div>
          
          {/* Sort */}
          <div className="flex items-center gap-2">
            <FunnelIcon className="h-5 w-5 text-gray-400" />
            <span className="text-sm text-gray-400">Sort by:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortField)}
              className="input py-1.5 w-40"
            >
              <option value="login_time">Last Login</option>
              <option value="risk_score">Risk Score</option>
              <option value="email">Email</option>
            </select>
          </div>
        </div>
        
        {/* Table */}
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Last Login</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center text-gray-400 py-8">
                    No users found
                  </td>
                </tr>
              ) : (
                filteredUsers.map((user) => {
                  const riskLevel = getRiskLevel(user.risk_score);
                  
                  return (
                    <tr key={user.id}>
                      <td>
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 bg-sentinel-600 rounded-full flex items-center justify-center text-white font-medium">
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
                        <span className={clsx('badge capitalize', getRoleBadgeClass(user.role))}>
                          {user.role}
                        </span>
                      </td>
                      <td>
                        <span className={clsx('badge capitalize', getStatusBadgeClass(user.status))}>
                          {user.status || 'active'}
                        </span>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div
                            className={clsx(
                              'w-2 h-2 rounded-full',
                              riskLevel === 'low' && 'bg-green-500',
                              riskLevel === 'medium' && 'bg-yellow-500',
                              riskLevel === 'high' && 'bg-red-500',
                              riskLevel === 'critical' && 'bg-red-600'
                            )}
                          />
                          <span className={clsx('font-medium', getRiskColorClass(riskLevel))}>
                            {user.risk_score}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="text-gray-400">
                          {user.login_time ? formatDate(user.login_time) : 'Never'}
                        </span>
                      </td>
                      <td>
                        <Link
                          to={`/users/${user.id}`}
                          className="text-sentinel-400 hover:text-sentinel-300 text-sm font-medium"
                        >
                          View Details
                        </Link>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        
        {/* Pagination */}
        {usersData && usersData.pagination.total_pages > 1 && (
          <div className="flex items-center justify-between mt-4 pt-4 border-t border-dashboard-border">
            <p className="text-sm text-gray-400">
              Showing {(page - 1) * 20 + 1} to {Math.min(page * 20, usersData.pagination.total)} of{' '}
              {usersData.pagination.total} users
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1 || isFetching}
                className="btn-ghost px-3 py-1.5"
              >
                Previous
              </button>
              <span className="text-sm text-gray-400">
                Page {page} of {usersData.pagination.total_pages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(usersData.pagination.total_pages, p + 1))}
                disabled={page === usersData.pagination.total_pages || isFetching}
                className="btn-ghost px-3 py-1.5"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
