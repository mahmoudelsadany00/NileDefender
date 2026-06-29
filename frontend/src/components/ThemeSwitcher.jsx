import { useState, useRef, useEffect } from 'react';
import { useTheme } from '../hooks/useTheme';

export default function ThemeSwitcher() {
  const { themeId, setThemeId, currentTheme, themes } = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  // Close on outside click
  useEffect(() => {
    function handleClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    if (open) document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [open]);

  // Close on Escape
  useEffect(() => {
    function handleKey(e) {
      if (e.key === 'Escape') setOpen(false);
    }
    if (open) document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [open]);

  return (
    <div className="theme-switcher" ref={ref}>
      <button
        className="theme-toggle-btn"
        onClick={() => setOpen(!open)}
        aria-label="Switch theme"
        title="Switch theme"
        id="theme-toggle-btn"
      >
        <span className="theme-toggle-icon">🎨</span>
        <span className="theme-toggle-label">{currentTheme.name}</span>
        <span className={`theme-toggle-chevron ${open ? 'open' : ''}`}>▾</span>
      </button>

      <div className={`theme-dropdown ${open ? 'show' : ''}`}>
        <div className="theme-dropdown-header">
          <span className="theme-dropdown-title">🎨 Choose Theme</span>
        </div>
        <div className="theme-options">
          {themes.map((theme) => (
            <button
              key={theme.id}
              className={`theme-option ${themeId === theme.id ? 'active' : ''}`}
              onClick={() => {
                setThemeId(theme.id);
                setOpen(false);
              }}
              id={`theme-option-${theme.id}`}
            >
              <div className="theme-option-preview">
                {theme.preview.map((color, i) => (
                  <span
                    key={i}
                    className="theme-color-dot"
                    style={{ background: color }}
                  />
                ))}
              </div>
              <div className="theme-option-info">
                <span className="theme-option-name">
                  <span className="theme-option-icon">{theme.icon}</span>
                  {theme.name}
                </span>
                <span className="theme-option-desc">{theme.description}</span>
              </div>
              {themeId === theme.id && (
                <span className="theme-check">✓</span>
              )}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
