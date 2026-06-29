import { createContext, useContext, useCallback, useState } from 'react';

const NotificationContext = createContext(null);

export function NotificationProvider({ children }) {
  const [notification, setNotification] = useState(null);

  const showNotification = useCallback((message, type = 'info') => {
    setNotification({ message, type, id: Date.now() });
    setTimeout(() => setNotification(null), 3200);
  }, []);

  return (
    <NotificationContext.Provider value={showNotification}>
      {children}
      {notification && (
        <div
          key={notification.id}
          className={`notification-toast notification-${notification.type} show`}
        >
          <span>{notification.type === 'success' ? '✓' : notification.type === 'error' ? '✕' : 'ℹ'}</span>
          <span>{notification.message}</span>
        </div>
      )}
    </NotificationContext.Provider>
  );
}

export function useNotification() {
  return useContext(NotificationContext);
}
