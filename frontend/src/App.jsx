import React, { useState } from 'react';
import Sidebar from './components/layout/Sidebar';
import Navbar from './components/layout/Navbar';
import Dashboard from './pages/Dashboard';
import MessageScanner from './pages/MessageScanner';
import UrlScanner from './pages/UrlScanner';
import ScanHistory from './pages/ScanHistory';

export default function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [selectedScanId, setSelectedScanId] = useState(null);

  const handleSelectScan = (id) => {
    setSelectedScanId(id);
    setCurrentView('history');
  };

  return (
    <div className="flex h-screen bg-navy-950 text-slate-100 overflow-hidden font-sans">
      {/* Navigation Sidebar */}
      <Sidebar
        currentView={currentView}
        onSelectView={(view) => {
          setSelectedScanId(null);
          setCurrentView(view);
        }}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Navbar />

        <main className="flex-1 overflow-y-auto p-6 md:p-8">
          <div className="max-w-6xl mx-auto">
            {currentView === 'dashboard' && (
              <Dashboard
                onNavigateToScanner={(view) => setCurrentView(view)}
                onSelectScan={handleSelectScan}
              />
            )}

            {currentView === 'message-scanner' && (
              <MessageScanner />
            )}

            {currentView === 'url-scanner' && (
              <UrlScanner />
            )}

            {currentView === 'history' && (
              <ScanHistory initialSelectedId={selectedScanId} />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

