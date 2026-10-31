import React, { useEffect, useState } from 'react';
import { Activity, Menu, Shield } from 'lucide-react';
import { api } from '../../services/api';

export default function Navbar({ onToggleMobileMenu }) {
  const [backendStatus, setBackendStatus] = useState('checking'); // 'connected', 'offline', 'checking'

  const verifyHealth = async () => {
    try {
      const data = await api.checkHealth();
      if (data && data.status === 'healthy') {
        setBackendStatus('connected');
      } else {
        setBackendStatus('offline');
      }
    } catch {
      setBackendStatus('offline');
    }
  };

  useEffect(() => {
    verifyHealth();
    const interval = setInterval(verifyHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 border-b border-slate-800/80 bg-navy-900/60 backdrop-blur-md px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleMobileMenu}
          className="md:hidden p-2 rounded-lg bg-slate-800/80 text-slate-300 hover:text-white border border-slate-700"
          title="Toggle Navigation"
        >
          <Menu className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wider font-semibold px-2.5 py-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-blue-400 animate-pulse" />
            <span className="hidden sm:inline">Detection Engine Active</span>
            <span className="sm:hidden">Engine Active</span>
          </span>
          <span className="hidden lg:inline-block text-xs font-mono text-slate-400 bg-slate-800/60 px-2 py-0.5 rounded border border-slate-700/50">
            India & Global Threat Shield
          </span>
        </div>
      </div>

      <div className="flex items-center gap-3 sm:gap-4">
        {/* Backend health status badge */}
        <div className="flex items-center gap-2 text-xs font-mono px-3 py-1 rounded-full bg-slate-900/80 border border-slate-800">
          {backendStatus === 'connected' ? (
            <>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              <span className="text-emerald-400 font-medium">API Connected</span>
            </>
          ) : backendStatus === 'checking' ? (
            <>
              <span className="w-2 h-2 rounded-full bg-amber-400"></span>
              <span className="text-amber-300">Checking...</span>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-rose-500"></span>
              <span className="text-rose-400">API Offline</span>
            </>
          )}
        </div>

        <div className="flex items-center gap-2 border-l border-slate-800 pl-3 sm:pl-4 text-xs text-slate-400">
          <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-blue-600 to-violet-600 flex items-center justify-center text-white font-bold text-xs shadow-glow-blue shrink-0">
            SS
          </div>
          <span className="hidden md:inline font-medium text-slate-200">Security Analyst</span>
        </div>
      </div>
    </header>
  );
}
