import React from 'react';
import { AppRouter } from './router/AppRouter';

/**
 * Root App Component
 * Uses AppRouter to handle navigation between pages
 */
const App: React.FC = () => {
  return <AppRouter />;
};

export default App;
