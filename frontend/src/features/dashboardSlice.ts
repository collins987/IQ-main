import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import type { DashboardEvent } from '../services/dashboardApi';

interface DashboardState {
  selectedTimeRange: '1h' | '6h' | '24h' | '7d';
  sidebarCollapsed: boolean;
  liveEventsEnabled: boolean;
  recentEvents: DashboardEvent[];
  notifications: Array<{
    id: string;
    type: 'info' | 'warning' | 'error' | 'success';
    message: string;
    timestamp: string;
  }>;
}

const initialState: DashboardState = {
  selectedTimeRange: '24h',
  sidebarCollapsed: false,
  liveEventsEnabled: true,
  recentEvents: [],
  notifications: [],
};

const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    setTimeRange: (state, action: PayloadAction<DashboardState['selectedTimeRange']>) => {
      state.selectedTimeRange = action.payload;
    },
    toggleSidebar: (state) => {
      state.sidebarCollapsed = !state.sidebarCollapsed;
    },
    toggleLiveEvents: (state) => {
      state.liveEventsEnabled = !state.liveEventsEnabled;
    },
    addEvent: (state, action: PayloadAction<DashboardEvent>) => {
      state.recentEvents = [action.payload, ...state.recentEvents.slice(0, 99)];
    },
    clearEvents: (state) => {
      state.recentEvents = [];
    },
    addNotification: (
      state,
      action: PayloadAction<{
        type: 'info' | 'warning' | 'error' | 'success';
        message: string;
      }>
    ) => {
      state.notifications.push({
        id: crypto.randomUUID(),
        ...action.payload,
        timestamp: new Date().toISOString(),
      });
    },
    removeNotification: (state, action: PayloadAction<string>) => {
      state.notifications = state.notifications.filter((n) => n.id !== action.payload);
    },
    clearNotifications: (state) => {
      state.notifications = [];
    },
  },
});

export const {
  setTimeRange,
  toggleSidebar,
  toggleLiveEvents,
  addEvent,
  clearEvents,
  addNotification,
  removeNotification,
  clearNotifications,
} = dashboardSlice.actions;

export default dashboardSlice.reducer;
