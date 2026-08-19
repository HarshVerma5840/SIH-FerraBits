import { useState, useEffect } from 'react';

/**
 * useLocalStorage — drop-in replacement for useState that persists to localStorage.
 * All keys are namespaced under 'sbomguard:' to avoid collisions.
 *
 * @param {string} key        Storage key (without namespace prefix)
 * @param {*}      defaultVal Default value if nothing is stored yet
 */
export function useLocalStorage(key, defaultVal) {
  const storageKey = `sbomguard:${key}`;

  const [value, setValue] = useState(() => {
    try {
      const stored = localStorage.getItem(storageKey);
      return stored !== null ? JSON.parse(stored) : defaultVal;
    } catch {
      return defaultVal;
    }
  });

  useEffect(() => {
    try {
      if (value === undefined || value === null) {
        localStorage.removeItem(storageKey);
      } else {
        localStorage.setItem(storageKey, JSON.stringify(value));
      }
    } catch {
      // Quota exceeded or private browsing — silently degrade
    }
  }, [storageKey, value]);

  return [value, setValue];
}
