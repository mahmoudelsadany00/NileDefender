import { useEffect, useRef, useState, useCallback } from 'react';
import { io } from 'socket.io-client';

/**
 * Custom hook for Socket.IO connection.
 * Handles connect/disconnect state, joining scan rooms, and event listeners.
 */
export function useSocket() {
  const socketRef = useRef(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const socket = io(window.location.origin, {
      transports: ['websocket', 'polling'],
    });

    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));

    socketRef.current = socket;

    return () => {
      socket.disconnect();
    };
  }, []);

  const joinScan = useCallback((scanId) => {
    socketRef.current?.emit('join_scan', { scan_id: scanId });
  }, []);

  const onScanUpdate = useCallback((callback) => {
    const socket = socketRef.current;
    if (!socket) return () => {};
    socket.on('scan_update', callback);
    return () => socket.off('scan_update', callback);
  }, []);

  const onScanCompleted = useCallback((callback) => {
    const socket = socketRef.current;
    if (!socket) return () => {};
    socket.on('scan_completed', callback);
    return () => socket.off('scan_completed', callback);
  }, []);

  const onVulnscanCompleted = useCallback((callback) => {
    const socket = socketRef.current;
    if (!socket) return () => {};
    socket.on('vulnscan_completed', callback);
    return () => socket.off('vulnscan_completed', callback);
  }, []);

  const onScanError = useCallback((callback) => {
    const socket = socketRef.current;
    if (!socket) return () => {};
    socket.on('scan_error', callback);
    return () => socket.off('scan_error', callback);
  }, []);

  return {
    socket: socketRef.current,
    connected,
    joinScan,
    onScanUpdate,
    onScanCompleted,
    onVulnscanCompleted,
    onScanError,
  };
}
