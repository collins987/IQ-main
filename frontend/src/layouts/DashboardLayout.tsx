import { Outlet } from 'react-router-dom';
import Sidebar from '../components/layout/Sidebar';
import Header from '../components/layout/Header';
import { useAppSelector } from '../store/hooks';
import { useWebSocket } from '../hooks/useWebSocket';

export default function DashboardLayout() {
  const { sidebarCollapsed, liveEventsEnabled } = useAppSelector((state) => state.dashboard);
  
  // Connect to WebSocket for live events
  useWebSocket(liveEventsEnabled);
  
  return (
    <div className="flex h-screen overflow-hidden bg-dashboard-bg">
      {/* Sidebar */}
      <Sidebar collapsed={sidebarCollapsed} />
      
      {/* Main Content Area */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Header */}
        <Header />
        
        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
