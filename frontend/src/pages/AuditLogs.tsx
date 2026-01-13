import { useState, Fragment } from 'react';
import { Dialog, Transition } from '@headlessui/react';
import { useAppSelector } from '../store/hooks';
import { useGetAuditLogsQuery, useGetAuditActionTypesQuery, useExportAuditLogsMutation } from '../services/dashboardApi';
import { formatDate } from '../utils/helpers';
import LoadingSpinner from '../components/common/LoadingSpinner';
import clsx from 'clsx';
import {
  DocumentArrowDownIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';

interface AuditLogMetadata {
  [key: string]: unknown;
}

interface SelectedLog {
  id: string;
  timestamp: string | null;
  actor: { id: string; email: string };
  action: string;
  target: string | null;
  metadata: AuditLogMetadata | null;
}

export default function AuditLogs() {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    actor_id: '',
    action_type: '',
    start_date: '',
    end_date: '',
  });
  const [showFilters, setShowFilters] = useState(false);
  const [selectedLog, setSelectedLog] = useState<SelectedLog | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const { isAuthenticated } = useAppSelector((state) => state.auth);
  
  const { data: logs, isLoading, isFetching } = useGetAuditLogsQuery({
    page,
    page_size: 50,
    ...Object.fromEntries(Object.entries(filters).filter(([_, v]) => v)),
  }, { skip: !isAuthenticated });
  
  const { data: actionTypes } = useGetAuditActionTypesQuery(undefined, { skip: !isAuthenticated });
  const [exportLogs, { isLoading: isExporting }] = useExportAuditLogsMutation();
  
  const handleExport = async (format: 'csv' | 'json') => {
    try {
      await exportLogs({
        format,
        ...Object.fromEntries(Object.entries(filters).filter(([_, v]) => v)),
      }).unwrap();
    } catch (err) {
      console.error('Export failed:', err);
    }
  };
  
  const clearFilters = () => {
    setFilters({
      actor_id: '',
      action_type: '',
      start_date: '',
      end_date: '',
    });
    setPage(1);
  };
  
  const hasActiveFilters = Object.values(filters).some((v) => v);
  
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
          <h1 className="text-2xl font-bold text-white">Audit Logs</h1>
          <p className="text-gray-400 mt-1">
            Comprehensive audit trail of all system activities
          </p>
        </div>
        
        {/* Export Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleExport('csv')}
            disabled={isExporting}
            className="btn-secondary flex items-center gap-2"
          >
            <DocumentArrowDownIcon className="h-4 w-4" />
            Export CSV
          </button>
          <button
            onClick={() => handleExport('json')}
            disabled={isExporting}
            className="btn-secondary flex items-center gap-2"
          >
            <DocumentArrowDownIcon className="h-4 w-4" />
            Export JSON
          </button>
        </div>
      </div>
      
      {/* Filters Card */}
      <div className="card">
        <button
          onClick={() => setShowFilters(!showFilters)}
          className="flex items-center justify-between w-full"
        >
          <div className="flex items-center gap-2">
            <FunnelIcon className="h-5 w-5 text-gray-400" />
            <span className="font-medium text-white">Filters</span>
            {hasActiveFilters && (
              <span className="badge badge-info">{Object.values(filters).filter((v) => v).length} active</span>
            )}
          </div>
          <span className="text-gray-400 text-sm">{showFilters ? 'Hide' : 'Show'}</span>
        </button>
        
        {showFilters && (
          <div className="mt-4 pt-4 border-t border-dashboard-border">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Action Type</label>
                <select
                  value={filters.action_type}
                  onChange={(e) => {
                    setFilters({ ...filters, action_type: e.target.value });
                    setPage(1);
                  }}
                  className="input"
                >
                  <option value="">All Actions</option>
                  {actionTypes?.actions.map((action) => (
                    <option key={action} value={action}>
                      {action.replace(/_/g, ' ')}
                    </option>
                  ))}
                </select>
              </div>
              
              <div>
                <label className="block text-sm text-gray-400 mb-1">Actor ID</label>
                <input
                  type="text"
                  value={filters.actor_id}
                  onChange={(e) => {
                    setFilters({ ...filters, actor_id: e.target.value });
                    setPage(1);
                  }}
                  placeholder="Filter by actor ID"
                  className="input"
                />
              </div>
              
              <div>
                <label className="block text-sm text-gray-400 mb-1">Start Date</label>
                <input
                  type="datetime-local"
                  value={filters.start_date}
                  onChange={(e) => {
                    setFilters({ ...filters, start_date: e.target.value });
                    setPage(1);
                  }}
                  className="input"
                />
              </div>
              
              <div>
                <label className="block text-sm text-gray-400 mb-1">End Date</label>
                <input
                  type="datetime-local"
                  value={filters.end_date}
                  onChange={(e) => {
                    setFilters({ ...filters, end_date: e.target.value });
                    setPage(1);
                  }}
                  className="input"
                />
              </div>
            </div>
            
            {hasActiveFilters && (
              <button
                onClick={clearFilters}
                className="mt-4 flex items-center gap-1 text-sm text-red-400 hover:text-red-300"
              >
                <XMarkIcon className="h-4 w-4" />
                Clear all filters
              </button>
            )}
          </div>
        )}
      </div>
      
      {/* Logs Table */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <p className="text-sm text-gray-400">
            {logs?.total ?? 0} total records
          </p>
          {isFetching && <LoadingSpinner size="sm" />}
        </div>
        
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {logs?.logs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center text-gray-400 py-8">
                    No audit logs found
                  </td>
                </tr>
              ) : (
                logs?.logs.map((log) => (
                  <tr key={log.id}>
                    <td>
                      <span className="text-sm text-gray-300 font-mono">
                        {log.timestamp ? formatDate(log.timestamp, 'MMM d, HH:mm:ss') : 'N/A'}
                      </span>
                    </td>
                    <td>
                      <div>
                        <p className="text-sm text-white">{log.actor.email}</p>
                        <p className="text-xs text-gray-500 font-mono">{log.actor.id.slice(0, 8)}...</p>
                      </div>
                    </td>
                    <td>
                      <span className={clsx(
                        'badge',
                        log.action.includes('failed') || log.action.includes('forbidden') ? 'badge-danger' :
                        log.action.includes('disabled') ? 'badge-warning' :
                        log.action.includes('enabled') || log.action.includes('registered') ? 'badge-success' :
                        'badge-info'
                      )}>
                        {log.action.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td>
                      <span className="text-sm text-gray-400 font-mono">
                        {log.target ? (log.target.length > 20 ? log.target.slice(0, 20) + '...' : log.target) : '-'}
                      </span>
                    </td>
                    <td>
                      {log.metadata ? (
                        <button
                          onClick={() => {
                            setSelectedLog(log as SelectedLog);
                            setIsModalOpen(true);
                          }}
                          className="text-sm text-sentinel-400 hover:text-sentinel-300"
                        >
                          View
                        </button>
                      ) : (
                        <span className="text-gray-500">-</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        
        {/* Pagination */}
        {logs && logs.total_pages > 1 && (
          <div className="flex items-center justify-between mt-4 pt-4 border-t border-dashboard-border">
            <p className="text-sm text-gray-400">
              Page {page} of {logs.total_pages}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1 || isFetching}
                className="btn-ghost px-3 py-1.5"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => Math.min(logs.total_pages, p + 1))}
                disabled={page === logs.total_pages || isFetching}
                className="btn-ghost px-3 py-1.5"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Audit Log Details Modal */}
      <Transition appear show={isModalOpen} as={Fragment}>
        <Dialog as="div" className="relative z-50" onClose={() => setIsModalOpen(false)}>
          <Transition.Child
            as={Fragment}
            enter="ease-out duration-300"
            enterFrom="opacity-0"
            enterTo="opacity-100"
            leave="ease-in duration-200"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
          >
            <div className="fixed inset-0 bg-black/60" />
          </Transition.Child>

          <div className="fixed inset-0 overflow-y-auto">
            <div className="flex min-h-full items-center justify-center p-4">
              <Transition.Child
                as={Fragment}
                enter="ease-out duration-300"
                enterFrom="opacity-0 scale-95"
                enterTo="opacity-100 scale-100"
                leave="ease-in duration-200"
                leaveFrom="opacity-100 scale-100"
                leaveTo="opacity-0 scale-95"
              >
                <Dialog.Panel className="w-full max-w-2xl transform overflow-hidden rounded-xl bg-dashboard-card border border-dashboard-border p-6 shadow-xl transition-all">
                  <div className="flex items-center justify-between mb-4">
                    <Dialog.Title className="text-lg font-semibold text-white">
                      Audit Log Details
                    </Dialog.Title>
                    <button
                      onClick={() => setIsModalOpen(false)}
                      className="text-gray-400 hover:text-white transition-colors"
                    >
                      <XMarkIcon className="h-5 w-5" />
                    </button>
                  </div>

                  {selectedLog && (
                    <div className="space-y-4">
                      {/* Log Info */}
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="text-xs text-gray-500">Timestamp</label>
                          <p className="text-sm text-white font-mono">
                            {selectedLog.timestamp ? formatDate(selectedLog.timestamp, 'MMM d, yyyy HH:mm:ss') : 'N/A'}
                          </p>
                        </div>
                        <div>
                          <label className="text-xs text-gray-500">Action</label>
                          <p className="text-sm text-white">{selectedLog.action.replace(/_/g, ' ')}</p>
                        </div>
                        <div>
                          <label className="text-xs text-gray-500">Actor</label>
                          <p className="text-sm text-white">{selectedLog.actor.email}</p>
                          <p className="text-xs text-gray-500 font-mono">{selectedLog.actor.id}</p>
                        </div>
                        <div>
                          <label className="text-xs text-gray-500">Target</label>
                          <p className="text-sm text-white font-mono">{selectedLog.target || '-'}</p>
                        </div>
                      </div>

                      {/* Metadata */}
                      {selectedLog.metadata && (
                        <div>
                          <label className="text-xs text-gray-500 mb-2 block">Metadata</label>
                          <div className="bg-dashboard-bg rounded-lg p-4 overflow-auto max-h-64">
                            <pre className="text-sm text-gray-300 font-mono whitespace-pre-wrap">
                              {JSON.stringify(selectedLog.metadata, null, 2)}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </Dialog.Panel>
              </Transition.Child>
            </div>
          </div>
        </Dialog>
      </Transition>
    </div>
  );
}
