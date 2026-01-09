import { NavLink } from 'react-router-dom';
import {
  HomeIcon,
  UsersIcon,
  ShieldExclamationIcon,
  DocumentTextIcon,
  BoltIcon,
  ServerIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline';
import { useAppDispatch } from '../../store/hooks';
import { toggleSidebar } from '../../features/dashboardSlice';
import clsx from 'clsx';

interface SidebarProps {
  collapsed: boolean;
}

const navigation = [
  { name: 'Overview', href: '/overview', icon: HomeIcon },
  { name: 'Users', href: '/users', icon: UsersIcon },
  { name: 'Risk Center', href: '/risk', icon: ShieldExclamationIcon },
  { name: 'Audit Logs', href: '/audit', icon: DocumentTextIcon },
  { name: 'Activity Feed', href: '/activity', icon: BoltIcon },
  { name: 'System Health', href: '/health', icon: ServerIcon },
];

export default function Sidebar({ collapsed }: SidebarProps) {
  const dispatch = useAppDispatch();
  
  return (
    <aside
      className={clsx(
        'flex flex-col border-r border-dashboard-border bg-dashboard-card transition-all duration-300',
        collapsed ? 'w-20' : 'w-64'
      )}
    >
      {/* Logo */}
      <div className="flex h-16 items-center justify-between px-4 border-b border-dashboard-border">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-gradient-to-br from-sentinel-500 to-sentinel-700 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">S</span>
            </div>
            <span className="font-semibold text-white">SentinelIQ</span>
          </div>
        )}
        {collapsed && (
          <div className="w-8 h-8 bg-gradient-to-br from-sentinel-500 to-sentinel-700 rounded-lg flex items-center justify-center mx-auto">
            <span className="text-white font-bold text-lg">S</span>
          </div>
        )}
      </div>
      
      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200',
                isActive
                  ? 'bg-sentinel-600/20 text-white border-l-2 border-sentinel-500'
                  : 'text-gray-400 hover:text-white hover:bg-dashboard-hover'
              )
            }
            title={collapsed ? item.name : undefined}
          >
            <item.icon className="h-5 w-5 flex-shrink-0" />
            {!collapsed && <span className="text-sm font-medium">{item.name}</span>}
          </NavLink>
        ))}
      </nav>
      
      {/* Collapse Toggle */}
      <div className="border-t border-dashboard-border p-3">
        <button
          onClick={() => dispatch(toggleSidebar())}
          className="flex items-center justify-center w-full px-3 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-dashboard-hover transition-colors"
        >
          {collapsed ? (
            <ChevronRightIcon className="h-5 w-5" />
          ) : (
            <>
              <ChevronLeftIcon className="h-5 w-5" />
              <span className="ml-2 text-sm">Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
}
