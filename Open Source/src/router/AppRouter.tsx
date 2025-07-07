import React from 'react';
import { HashRouter, Route, Routes } from 'react-router-dom';
import { MainPage } from '../pages/MainPage';
import { Settings } from '../pages/Settings';

/**
 * Router component to handle application routing
 * Using HashRouter for browser extension compatibility
 */
export const AppRouter: React.FC = () => {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<MainPage />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </HashRouter>
  );
};
