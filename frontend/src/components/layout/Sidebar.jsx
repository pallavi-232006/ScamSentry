import React from 'react';
import { ShieldAlert, LayoutDashboard, MessageSquareText, Link2, History, AlertTriangle, Cpu, X } from 'lucide-react';

export default function Sidebar({ currentView, onSelectView, isOpen, onClose }) {
  const navItems = [
    { id: 'dashboard', label: 'Security Dashboard', icon: LayoutDashboard },
    { id: 'message-scanner', label: 'Message Scanner', icon: MessageSquareText },
    { id: 'url-scanner', label: 'URL Threat Inspector', icon: Link2 },
    { id: 'history', label: 'Scan History', icon: History },
  ];

  const handleNav = (id) => {
    onSelectView(id);
    if (onClose) onClose();
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div 
          onClick={onClose}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 md:hidden"
        />
      )}

      <aside className={`fixed md:static inset-y-0 left-0 z-50 w-64 bg-navy-900 border-r border-slate-800 flex flex-col justify-between shrink-0 select-none transition-transform duration-200 ease-in-out ${
        isOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
      }`}>
        <div>
          {/* Brand Header */}
          <div className="p-6 border-b border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 via-indigo-600 to-violet-600 flex items-center justify-center text-white shadow-glow-blue">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="font-extrabold text-lg tracking-tight text-white">SCAM<span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400">SENTRY</span></span>
                </div>
                <p className="text-[10px] text-slate-400 font-medium tracking-tight">Cyber Threat Guardian</p>
              </div>
            </div>

            <button 
              onClick={onClose}
              className="md:hidden p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="px-6 pt-3">
            <div className="px-2.5 py-1.5 rounded bg-slate-950/60 border border-slate-800/60 text-[11px] text-slate-400 font-mono flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-blue-400" />
              <span>Multi-Vector AI Engine</span>
            </div>
          </div>

          {/* Navigation items */}
          <nav className="p-4 space-y-1.5">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 px-3 pb-2 pt-1">
              Analysis Suite
            </div>
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNav(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-gradient-to-r from-blue-600/20 to-violet-600/10 text-white border border-blue-500/30 shadow-sm'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                  {isActive && (
                    <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-glow-cyan"></span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Footer Info */}
        <div className="p-4 m-4 rounded-xl bg-slate-950/80 border border-slate-800/80 text-xs text-slate-400">
          <div className="flex items-center gap-2 mb-1.5 text-slate-300 font-medium">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span>Air-Gapped Protocol</span>
          </div>
          <p className="text-[11px] leading-relaxed text-slate-400">
            URLs are analyzed offline. Target links are never visited, resolved, or executed.
          </p>
        </div>
      </aside>
    </>
  );
}
