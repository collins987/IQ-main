import { useEffect, useRef, useCallback } from 'react';
import { useAppDispatch, useAppSelector } from '../store/hooks';
import { addEvent, addNotification } from '../features/dashboardSlice';
import type { DashboardEvent } from '../services/dashboardApi';

// Use VITE_API_WS_URL from environment, fallback to ws://localhost:8000
const WS_BASE_URL = import.meta.env.VITE_API_WS_URL || (window.location.protocol === 'https:' ? 'wss://localhost:8000' : 'ws://localhost:8000');

// Configuration constants
const MAX_RECONNECT_ATTEMPTS = 5;
const INITIAL_RECONNECT_DELAY_MS = 1000;
const MAX_RECONNECT_DELAY_MS = 30000;
const PING_INTERVAL_MS = 25000;

export function useWebSocket(enabled: boolean) {
  const dispatch = useAppDispatch();
  const { token, isAuthenticated } = useAppSelector((state) => state.auth);
  
  // Refs to persist across renders without triggering re-renders
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const isConnectingRef = useRef(false);
  const isMountedRef = useRef(false);
  const pingIntervalRef = useRef<number | null>(null);
  
  // Calculate exponential backoff delay
  const getReconnectDelay = useCallback(() => {
    const delay = Math.min(
      INITIAL_RECONNECT_DELAY_MS * Math.pow(2, reconnectAttemptsRef.current),
      MAX_RECONNECT_DELAY_MS
    );
    return delay;
  }, []);
  
  // Clean up function
  const cleanup = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
    if (wsRef.current) {
      // Prevent onclose from triggering reconnect
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.onmessage = null;
      wsRef.current.onopen = null;
      if (wsRef.current.readyState === WebSocket.OPEN || 
          wsRef.current.readyState === WebSocket.CONNECTING) {
        wsRef.current.close(1000, 'Component unmounting');
      }
      wsRef.current = null;
    }
    isConnectingRef.current = false;
  }, []);
  
  const connect = useCallback(() => {
    // Guards: Don't connect if conditions aren't met
    if (!isMountedRef.current) return;
    if (!token || !isAuthenticated || !enabled) return;
    if (isConnectingRef.current) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    if (wsRef.current?.readyState === WebSocket.CONNECTING) return;
    
    // Check max reconnect attempts
    if (reconnectAttemptsRef.current >= MAX_RECONNECT_ATTEMPTS) {
      console.warn(`WebSocket: Max reconnect attempts (${MAX_RECONNECT_ATTEMPTS}) reached. Stopping.`);
      dispatch(addNotification({
        type: 'warning',
        message: 'Live events disconnected. Refresh page to reconnect.',
      }));
      return;
    }
    
    isConnectingRef.current = true;
    
    // Close any existing connection cleanly
    if (wsRef.current) {
      wsRef.current.onclose = null; // Prevent onclose handler
      wsRef.current.close();
      wsRef.current = null;
    }
    
    // Compose WebSocket URL from env, fallback to backend default
    let wsUrl = `${WS_BASE_URL}/api/admin/dashboard/ws/events?token=${token}`;
    // Remove any accidental double slashes
    wsUrl = wsUrl.replace(/([^:]\/)\/+/, '$1/');
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      
      ws.onopen = () => {
        if (!isMountedRef.current) {
          ws.close();
          return;
        }
        
        console.log('WebSocket: Connected successfully');
        isConnectingRef.current = false;
        reconnectAttemptsRef.current = 0; // Reset on successful connection
        
        dispatch(addNotification({
          type: 'success',
          message: 'Live events connected',
        }));
        
        // Start ping interval
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
        }
        pingIntervalRef.current = window.setInterval(() => {
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            wsRef.current.send('ping');
          }
        }, PING_INTERVAL_MS);
      };
      
      ws.onmessage = (event) => {
        if (!isMountedRef.current) return;
        
        try {
          const data = JSON.parse(event.data);
          
          // Handle heartbeat - respond with ping
          if (data.type === 'heartbeat') {
            ws.send('ping');
            return;
          }
          
          // Ignore connection confirmations
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
          console.error('WebSocket: Failed to parse message:', err);
        }
      };
      
      ws.onclose = (event) => {
        if (!isMountedRef.current) return;
        
        isConnectingRef.current = false;
        wsRef.current = null;
        
        // Stop ping interval
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
          pingIntervalRef.current = null;
        }
        
        // Don't reconnect on clean close or auth failures (1008, 4001, 4003, 4401)
        if (event.wasClean || event.code === 1008 || event.code === 4001 || event.code === 4003 || event.code === 4401) {
          console.log(`WebSocket: Closed cleanly or auth failed (code: ${event.code})`);
          return;
        }
        
        // Attempt reconnect with exponential backoff
        if (enabled && isMountedRef.current) {
          reconnectAttemptsRef.current++;
          const delay = getReconnectDelay();
          console.log(`WebSocket: Connection lost. Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current}/${MAX_RECONNECT_ATTEMPTS})`);
          
          reconnectTimeoutRef.current = window.setTimeout(() => {
            if (isMountedRef.current) {
              connect();
            }
          }, delay);
        }
      };
      
      ws.onerror = () => {
        // Error details aren't exposed for security reasons
        // onclose will handle reconnection
        isConnectingRef.current = false;
      };
      
    } catch (err) {
      console.error('WebSocket: Failed to create connection:', err);
      isConnectingRef.current = false;
    }
  }, [token, isAuthenticated, enabled, dispatch, getReconnectDelay]);
  
  // Main effect: Connect when enabled and authenticated
  useEffect(() => {
    isMountedRef.current = true;
    
    // Only connect if all conditions are met
    if (enabled && isAuthenticated && token) {
      // Small delay to avoid race conditions with React StrictMode
      const connectDelay = setTimeout(() => {
        if (isMountedRef.current) {
          connect();
        }
      }, 100);
      
      return () => {
        clearTimeout(connectDelay);
      };
    }
    
    return () => {
      isMountedRef.current = false;
      cleanup();
    };
  }, [enabled, isAuthenticated, token, connect, cleanup]);
  
  // Cleanup on unmount
  useEffect(() => {
    return () => {
      isMountedRef.current = false;
      cleanup();
    };
  }, [cleanup]);
  
  return wsRef.current;
}
