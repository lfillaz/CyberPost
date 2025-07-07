import React, { useState } from 'react';
import useTheme from '../hooks/useTheme';
import useLocalStorage from '../hooks/useLocalStorage';
import { AppSettings, HttpMethod, BodyType } from '../types';

export const Settings: React.FC = () => {
  const { theme, setTheme, darkMode, toggleDarkMode } = useTheme();
  
  const [settings, setSettings] = useLocalStorage<AppSettings>('cyberpost-settings', {
    theme: 'cyber-green',
    autoSave: true,
    defaultRequestMethod: 'GET' as HttpMethod,
    defaultBodyType: 'json' as BodyType,
    darkMode: true
  });

  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [resetSuccess, setResetSuccess] = useState(false);

  const handleThemeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newTheme = e.target.value as AppSettings['theme'];
    setTheme(newTheme);
    setSettings({ ...settings, theme: newTheme });
  };

  const handleAutoSaveChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSettings({ ...settings, autoSave: e.target.checked });
  };

  const handleMethodChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setSettings({ ...settings, defaultRequestMethod: e.target.value as HttpMethod });
  };

  const handleBodyTypeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setSettings({ ...settings, defaultBodyType: e.target.value as BodyType });
  };

  const handleDarkModeChange = () => {
    const newDarkMode = !darkMode;
    toggleDarkMode();
    setSettings({ ...settings, darkMode: newDarkMode });
  };

  const resetAllData = async () => {
    try {
      // Clear IndexedDB
      const databases = await window.indexedDB.databases();
      databases.forEach(db => {
        if (db.name) window.indexedDB.deleteDatabase(db.name);
      });
      
      // Clear LocalStorage (only app-specific items)
      Object.keys(localStorage).forEach(key => {
        if (key.startsWith('cyberpost-')) {
          localStorage.removeItem(key);
        }
      });
      
      setResetSuccess(true);
      setTimeout(() => {
        setResetSuccess(false);
        setShowResetConfirm(false);
        window.location.reload();
      }, 2000);
    } catch (error) {
      console.error('Error resetting data:', error);
    }
  };

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-6 text-cyber-green">Settings</h1>
      
      <div className="space-y-6">
        {/* Appearance Settings */}
        <section className="card p-4">
          <h2 className="text-lg font-medium mb-4">Appearance</h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm mb-2">Theme</label>
              <select 
                value={theme} 
                onChange={handleThemeChange}
                className="input w-full"
              >
                <option value="cyber-green">Cyber Green</option>
                <option value="cyber-cyan">Cyber Cyan</option>
                <option value="cyber-red">Cyber Red</option>
              </select>
            </div>
            
            <div>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={darkMode}
                  onChange={handleDarkModeChange}
                  className="form-checkbox"
                />
                <span>Dark Mode</span>
              </label>
            </div>
          </div>
        </section>
        
        {/* Request Settings */}
        <section className="card p-4">
          <h2 className="text-lg font-medium mb-4">Request Defaults</h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm mb-2">Default HTTP Method</label>
              <select 
                value={settings.defaultRequestMethod} 
                onChange={handleMethodChange}
                className="input w-full"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
                <option value="OPTIONS">OPTIONS</option>
                <option value="HEAD">HEAD</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm mb-2">Default Body Type</label>
              <select 
                value={settings.defaultBodyType} 
                onChange={handleBodyTypeChange}
                className="input w-full"
              >
                <option value="raw">Raw</option>
                <option value="json">JSON</option>
                <option value="form-data">Form Data</option>
                <option value="x-www-form-urlencoded">x-www-form-urlencoded</option>
              </select>
            </div>
            
            <div>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={settings.autoSave}
                  onChange={handleAutoSaveChange}
                  className="form-checkbox"
                />
                <span>Auto-save requests</span>
              </label>
              <p className="text-xs text-gray-400 mt-1">
                Automatically save requests after sending
              </p>
            </div>
          </div>
        </section>
        
        {/* Data Management */}
        <section className="card p-4">
          <h2 className="text-lg font-medium mb-4">Data Management</h2>
          
          <div className="space-y-4">
            {!showResetConfirm ? (
              <button 
                onClick={() => setShowResetConfirm(true)}
                className="btn-danger"
              >
                Reset All Data
              </button>
            ) : (
              <div className="space-y-2">
                <p className="text-sm text-gray-300">
                  Are you sure? This will delete all saved requests and settings.
                </p>
                <div className="flex space-x-2">
                  <button 
                    onClick={resetAllData}
                    className="btn-danger"
                  >
                    Yes, Reset Everything
                  </button>
                  <button 
                    onClick={() => setShowResetConfirm(false)}
                    className="btn-secondary"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
            
            {resetSuccess && (
              <div className="text-cyber-green text-sm mt-2">
                All data has been reset successfully!
              </div>
            )}
            
            <div className="mt-6 pt-4 border-t border-gray-700">
              <h3 className="text-sm font-medium mb-2">Export/Import</h3>
              <div className="flex space-x-2">
                <button className="btn-secondary text-sm">
                  Export All Data
                </button>
                <label className="btn-secondary text-sm cursor-pointer">
                  Import Data
                  <input 
                    type="file" 
                    accept=".json"
                    className="hidden"
                  />
                </label>
              </div>
            </div>
          </div>
        </section>
        
        {/* About */}
        <section className="card p-4">
          <h2 className="text-lg font-medium mb-2">About CyberPost Lab</h2>
          <p className="text-sm text-gray-300">
            Version 1.0.0
          </p>
          <p className="text-sm text-gray-400 mt-2">
            A fully offline, browser-based HTTP request testing tool for cybersecurity researchers.
          </p>
          <p className="text-xs text-gray-500 mt-4">
            All data is stored locally in your browser.
          </p>
        </section>
      </div>
    </div>
  );
};
