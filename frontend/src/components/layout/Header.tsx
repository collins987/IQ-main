import { Menu, Transition } from '@headlessui/react';
import { Fragment } from 'react';
import {
  BellIcon,
  UserCircleIcon,
  ArrowRightOnRectangleIcon,
  Cog6ToothIcon,
  SignalIcon,
  SignalSlashIcon,
} from '@heroicons/react/24/outline';
import { useAppSelector, useAppDispatch } from '../../store/hooks';
import { logout } from '../../features/authSlice';
import { toggleLiveEvents, setTimeRange } from '../../features/dashboardSlice';
import { useNavigate } from 'react-router-dom';
import clsx from 'clsx';

const timeRanges = [
  { value: '1h', label: '1 Hour' },
  { value: '6h', label: '6 Hours' },
  { value: '24h', label: '24 Hours' },
  { value: '7d', label: '7 Days' },
] as const;

export default function Header() {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const { user } = useAppSelector((state) => state.auth);
  const { liveEventsEnabled, selectedTimeRange, notifications } = useAppSelector(
    (state) => state.dashboard
  );
  
  const handleLogout = () => {
    dispatch(logout());
    navigate('/login');
  };
  
  return (
    <header className="flex h-16 items-center justify-between border-b border-dashboard-border bg-dashboard-card px-6">
      {/* Left side - Time range selector */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">Time Range:</span>
          <div className="flex rounded-lg bg-dashboard-bg p-1">
            {timeRanges.map((range) => (
              <button
                key={range.value}
                onClick={() => dispatch(setTimeRange(range.value))}
                className={clsx(
                  'px-3 py-1 text-xs font-medium rounded-md transition-colors',
                  selectedTimeRange === range.value
                    ? 'bg-sentinel-600 text-white'
                    : 'text-gray-400 hover:text-white'
                )}
              >
                {range.label}
              </button>
            ))}
          </div>
        </div>
        
        {/* Live indicator */}
        <button
          onClick={() => dispatch(toggleLiveEvents())}
          className={clsx(
            'flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors',
            liveEventsEnabled
              ? 'bg-green-500/20 text-green-400'
              : 'bg-gray-500/20 text-gray-400'
          )}
        >
          {liveEventsEnabled ? (
            <>
              <SignalIcon className="h-4 w-4" />
              <span>Live</span>
              <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            </>
          ) : (
            <>
              <SignalSlashIcon className="h-4 w-4" />
              <span>Paused</span>
            </>
          )}
        </button>
      </div>
      
      {/* Right side - Notifications & User menu */}
      <div className="flex items-center gap-4">
        {/* Notifications */}
        <Menu as="div" className="relative">
          <Menu.Button className="relative p-2 text-gray-400 hover:text-white transition-colors">
            <BellIcon className="h-6 w-6" />
            {notifications.length > 0 && (
              <span className="absolute top-1 right-1 w-4 h-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                {notifications.length > 9 ? '9+' : notifications.length}
              </span>
            )}
          </Menu.Button>
          <Transition
            as={Fragment}
            enter="transition ease-out duration-100"
            enterFrom="transform opacity-0 scale-95"
            enterTo="transform opacity-100 scale-100"
            leave="transition ease-in duration-75"
            leaveFrom="transform opacity-100 scale-100"
            leaveTo="transform opacity-0 scale-95"
          >
            <Menu.Items className="absolute right-0 mt-2 w-80 origin-top-right rounded-xl bg-dashboard-card border border-dashboard-border shadow-xl focus:outline-none z-50">
              <div className="p-4">
                <h3 className="text-sm font-semibold text-white mb-3">Notifications</h3>
                {notifications.length === 0 ? (
                  <p className="text-sm text-gray-400">No new notifications</p>
                ) : (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {notifications.map((notification) => (
                      <div
                        key={notification.id}
                        className={clsx(
                          'p-3 rounded-lg text-sm',
                          notification.type === 'error' && 'bg-red-500/10 text-red-400',
                          notification.type === 'warning' && 'bg-yellow-500/10 text-yellow-400',
                          notification.type === 'success' && 'bg-green-500/10 text-green-400',
                          notification.type === 'info' && 'bg-blue-500/10 text-blue-400'
                        )}
                      >
                        {notification.message}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Menu.Items>
          </Transition>
        </Menu>
        
        {/* User menu */}
        <Menu as="div" className="relative">
          <Menu.Button className="flex items-center gap-3 p-2 rounded-lg hover:bg-dashboard-hover transition-colors">
            <UserCircleIcon className="h-8 w-8 text-gray-400" />
            <div className="text-left hidden sm:block">
              <p className="text-sm font-medium text-white">
                {user?.first_name} {user?.last_name}
              </p>
              <p className="text-xs text-gray-400 capitalize">{user?.role}</p>
            </div>
          </Menu.Button>
          <Transition
            as={Fragment}
            enter="transition ease-out duration-100"
            enterFrom="transform opacity-0 scale-95"
            enterTo="transform opacity-100 scale-100"
            leave="transition ease-in duration-75"
            leaveFrom="transform opacity-100 scale-100"
            leaveTo="transform opacity-0 scale-95"
          >
            <Menu.Items className="absolute right-0 mt-2 w-48 origin-top-right rounded-xl bg-dashboard-card border border-dashboard-border shadow-xl focus:outline-none z-50">
              <div className="p-2">
                <Menu.Item>
                  {({ active }) => (
                    <button
                      className={clsx(
                        'flex items-center gap-2 w-full px-3 py-2 rounded-lg text-sm',
                        active ? 'bg-dashboard-hover text-white' : 'text-gray-300'
                      )}
                    >
                      <Cog6ToothIcon className="h-4 w-4" />
                      Settings
                    </button>
                  )}
                </Menu.Item>
                <Menu.Item>
                  {({ active }) => (
                    <button
                      onClick={handleLogout}
                      className={clsx(
                        'flex items-center gap-2 w-full px-3 py-2 rounded-lg text-sm',
                        active ? 'bg-red-500/20 text-red-400' : 'text-gray-300'
                      )}
                    >
                      <ArrowRightOnRectangleIcon className="h-4 w-4" />
                      Logout
                    </button>
                  )}
                </Menu.Item>
              </div>
            </Menu.Items>
          </Transition>
        </Menu>
      </div>
    </header>
  );
}
