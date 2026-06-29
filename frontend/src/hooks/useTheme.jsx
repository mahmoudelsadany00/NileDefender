import { useState, useEffect, createContext, useContext } from 'react';

const STORAGE_KEY = 'niledefender-theme';

export const themes = [
  {
    id: 'dark',
    name: 'Shadow Ops',
    description: 'Default dark theme',
    icon: '🌑',
    preview: ['#0b0f19', '#111827', '#38bdf8', '#34d399'],
  },
  {
    id: 'midnight',
    name: 'Midnight Blue',
    description: 'Deep navy tones',
    icon: '🌌',
    preview: ['#0a0e1a', '#0f1629', '#6366f1', '#818cf8'],
  },
  {
    id: 'obsidian',
    name: 'Obsidian Dark',
    description: 'Pure dark, minimal contrast',
    icon: '⬛',
    preview: ['#09090b', '#111113', '#a1a1aa', '#52525b'],
  },
  {
    id: 'arctic',
    name: 'Arctic Frost',
    description: 'Cool icy palette',
    icon: '❄️',
    preview: ['#f0f4f8', '#ffffff', '#0ea5e9', '#0284c7'],
  },
];

const ThemeContext = createContext();

export function ThemeProvider({ children }) {
  const [themeId, setThemeId] = useState(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) || 'dark';
    } catch {
      return 'dark';
    }
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', themeId);
    try {
      localStorage.setItem(STORAGE_KEY, themeId);
    } catch {
      // localStorage unavailable
    }
  }, [themeId]);

  const currentTheme = themes.find((t) => t.id === themeId) || themes[0];

  return (
    <ThemeContext.Provider value={{ themeId, setThemeId, currentTheme, themes }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) throw new Error('useTheme must be used within ThemeProvider');
  return context;
}
