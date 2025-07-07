import { useEffect } from 'react';
import useLocalStorage from './useLocalStorage';
import type { ThemeType } from '../types';


function useTheme() {
  const [theme, setTheme] = useLocalStorage<ThemeType>('cyberpost-theme', 'cyber-green');
  const [darkMode, setDarkMode] = useLocalStorage<boolean>('cyberpost-dark-mode', true);
  

  useEffect(() => {

    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    

    document.documentElement.dataset.theme = theme;
    

    return () => {
      document.documentElement.classList.remove('dark');
      delete document.documentElement.dataset.theme;
    };
  }, [theme, darkMode]);
  

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };
  
  return {
    theme,
    setTheme,
    darkMode,
    setDarkMode,
    toggleDarkMode,
  };
}

export default useTheme;
