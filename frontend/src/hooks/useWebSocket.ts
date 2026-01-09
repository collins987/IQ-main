import { useEffect, useRef, useCallback } from 'react';
import { useAppDispatch, useAppSelector } from '../store/hooks';
import { addEvent, addNotification } from '../features/dashboardSlice';
import type { DashboardEvent } from '../services/dashboardApi';

export function useWebSocket(enabled: boolean) {
  const dispatch = useAppDispatch();
  const { token } = useAppSelector((state) => state.auth);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  
  const connect = useCallback(() => {
    if (!token || !enabled) return;
    
    // Close existing connection
    if (wsRef.current) {
      wsRef.current.close();
    }
    
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/admin/dashboard/ws/events?token=${token}`;
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        dispatch(addNotification({
          type: 'success',
          message: 'Live events connected',
        }));
      };
      
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.type === 'heartbeat') {
            // Respond to heartbeat
            ws.send('ping');
            return;
          }
          
          if (data.type === 'connected' || data.type === 'pong') {
            return;
          }
          
          // Handle event data
          if (data.type && data.payload) {
            const dashboardEvent: DashboardEvent = {
              id: data.payload.id || crypto.randomUUID(),
              type: data.type,
              action: data.payload.action || data.type,
              severity: data.payload.severity || 'info',
              actor_id: data.payload.actor_id || '',
              target: data.payload.target || null,
              message: data.payload.message || data.type,
              timestamp: data.timestamp,
              metadata: data.payload.metadata || null,
            };
            
            dispatch(addEvent(dashboardEvent));
            
            // Show notification for high severity events
            if (dashboardEvent.severity === 'high' || dashboardEvent.severity === 'critical') {
              dispatch(addNotification({
                type: dashboardEvent.severity === 'critical' ? 'error' : 'warning',
                message: dashboardEvent.message,
              }));
            }
          }
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
        }
      };
      
      ws.onclose = (event) => {
        console.log('WebSocket closed:', event.code, event.reason);
        wsRef.current = null;
        
        // Attempt to reconnect after delay
        if (enabled && !event.wasClean) {
          reconnectTimeoutRef.current = window.setTimeout(() => {
            console.log('Attempting to reconnect WebSocket...');
            connect();
          }, 5000);
        }
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
      
    } catch (err) {
      console.error('Failed to create WebSocket:', err);
    }
  }, [token, enabled, dispatch]);
  
  // Connect on mount, disconnect on unmount
  useEffect(() => {
    if (enabled) {
      connect();
    }
    
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [enabled, connect]);
  
  // Ping to keep connection alive
  useEffect(() => {
    if (!enabled) return;
    
    const pingInterval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send('ping');
      }
    }, 25000);
    
    return () => clearInterval(pingInterval);
  }, [enabled]);
  
  return wsRef.current;
}
