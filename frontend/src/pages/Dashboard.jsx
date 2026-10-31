import React, { useEffect, useState } from 'react';
import { 
  ShieldCheck, AlertTriangle, ShieldAlert, FileText, ArrowUpRight, 
  RefreshCw, TrendingUp, Sparkles, CheckCircle2, Activity,
  Layers, Lock, Eye, ArrowRight
} from 'lucide-react';
import { 
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, 
  PieChart, Pie, Cell, AreaChart, Area, CartesianGrid 
} from 'recharts';
import { api } from '../services/api';

const LEVEL_COLORS = {
  LOW: '#10b981',      // Emerald
  MEDIUM: '#f59e0b',   // Amber
  HIGH: '#f97316',     // Orange
  CRITICAL: '#ef4444', // Red
};

export default function Dashboard({ onNavigateToScanner, onSelectScan }) {
  const [stats, setStats] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, historyData] = await Promise.all([
        api.getStats(),
        api.getHistory(6),
      ]);
      setStats(statsData);
      setRecentScans(historyData || []);
    } catch (err) {
      console.error("Dashboard fetch error:", err);
      setError("Unable to connect to security telemetry service. Please check API status.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Top Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-navy-900 via-navy-850 to-indigo-950/80 border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="relative z-10">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold uppercase tracking-wider mb-2">
            <Sparkles className="w-3.5 h-3.5" /> Threat Intelligence Core Active
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
            Detect the Scam. Understand the Threat. Stay Protected.
          </h1>
          <p className="text-slate-400 text-xs sm:text-sm mt-1 max-w-2xl leading-relaxed">
            Real-time hybrid heuristic & machine learning inspection for SMS, WhatsApp, emails, and deceptive URL vectors across Indian and global threats.
          </p>
        </div>

        <div className="flex items-center gap-3 relative z-10">
          <button
            onClick={() => onNavigateToScanner('message-scanner')}
            className="px-4 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-medium text-xs sm:text-sm transition-all shadow-glow-blue flex items-center gap-2 shrink-0"
          >
            <span>Scan Message</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
          <button
            onClick={() => onNavigateToScanner('url-scanner')}
            className="px-4 py-2.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-200 font-medium text-xs sm:text-sm transition-all flex items-center gap-2 shrink-0"
          >
            <span>Inspect URL</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
          <button
            onClick={fetchData}
            title="Refresh metrics"
            className="p-2.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 transition-all shrink-0"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button onClick={fetchData} className="underline hover:text-rose-200">Retry</button>
        </div>
      )}

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scans */}
        <div className="p-5 rounded-xl bg-navy-900/80 border border-slate-800/80 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Scans</p>
            <h3 className="text-2xl font-bold text-white mt-1">
              {stats ? stats.total_scans : 0}
            </h3>
            <p className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
              <TrendingUp className="w-3 h-3 text-blue-400" /> Monitored events
            </p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shadow-glow-blue">
            <FileText className="w-6 h-6" />
          </div>
        </div>

        {/* Safe Scans */}
        <div className="p-5 rounded-xl bg-navy-900/80 border border-slate-800/80 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Safe Communications</p>
            <h3 className="text-2xl font-bold text-emerald-400 mt-1">
              {stats ? stats.safe_scans : 0}
            </h3>
            <p className="text-[11px] text-emerald-400/80 mt-1">Benign baseline confirmed</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
        </div>

        {/* Suspicious Scans */}
        <div className="p-5 rounded-xl bg-navy-900/80 border border-slate-800/80 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Suspicious Anomalies</p>
            <h3 className="text-2xl font-bold text-amber-400 mt-1">
              {stats ? (stats.suspicious_scans || 0) : 0}
            </h3>
            <p className="text-[11px] text-amber-400/80 mt-1">Medium risk elevation</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <AlertTriangle className="w-6 h-6" />
          </div>
        </div>

        {/* High Risk Detections */}
        <div className="p-5 rounded-xl bg-navy-900/80 border border-slate-800/80 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">High Risk / Critical</p>
            <h3 className="text-2xl font-bold text-rose-400 mt-1">
              {stats ? stats.high_risk_detections : 0}
            </h3>
            <p className="text-[11px] text-rose-400/80 mt-1">Direct intervention advised</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Visual Analytics Grid: 3 Recharts Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Chart 1: Threat Severity Distribution (Bar Chart) */}
        <div className="p-6 rounded-2xl bg-navy-900/80 border border-slate-800/80 flex flex-col justify-between">
          <div className="mb-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              Threat Severity Distribution
            </h2>
            <p className="text-xs text-slate-400">Classification across Low, Medium, High & Critical</p>
          </div>

          <div className="h-56 w-full">
            {stats && stats.threat_level_distribution && stats.threat_level_distribution.some(d => d.count > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.threat_level_distribution} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <XAxis dataKey="level" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0a0f1d', borderColor: '#1e293b', borderRadius: '8px', color: '#fff', fontSize: '11px' }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {stats.threat_level_distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={LEVEL_COLORS[entry.level] || '#3b82f6'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-xs text-slate-500">
                <ShieldCheck className="w-8 h-8 text-slate-600 mb-1" />
                <span>No threat telemetry recorded yet</span>
              </div>
            )}
          </div>
        </div>

        {/* Chart 2: Scan Activity Over Time (Area Chart) */}
        <div className="p-6 rounded-2xl bg-navy-900/80 border border-slate-800/80 flex flex-col justify-between">
          <div className="mb-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Telemetry Timeline
            </h2>
            <p className="text-xs text-slate-400">Daily scan volume and threat detections</p>
          </div>

          <div className="h-56 w-full">
            {stats && stats.activity_over_time && stats.activity_over_time.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.activity_over_time} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0}/>
                    </linearGradient>
                    <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="date" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} allowDecimals={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0a0f1d', borderColor: '#1e293b', borderRadius: '8px', color: '#fff', fontSize: '11px' }}
                  />
                  <Area type="monotone" dataKey="scans" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#scanGradient)" name="Total Scans" />
                  <Area type="monotone" dataKey="high_risk" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#threatGradient)" name="High Risk" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                Activity timeline awaiting events
              </div>
            )}
          </div>
        </div>

        {/* Chart 3: Common Threat Vectors (Horizontal Distribution) */}
        <div className="p-6 rounded-2xl bg-navy-900/80 border border-slate-800/80 flex flex-col justify-between">
          <div className="mb-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-violet-400" />
              Prevalent Attack Vectors
            </h2>
            <p className="text-xs text-slate-400">Distribution across scam categories</p>
          </div>

          <div className="h-56 flex flex-col justify-center space-y-3">
            {stats && stats.category_distribution && stats.category_distribution.length > 0 ? (
              stats.category_distribution.slice(0, 5).map((cat, i) => (
                <div key={i} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-300 font-medium truncate max-w-[180px]">{cat.category}</span>
                    <span className="text-slate-400 font-mono text-[11px]">{cat.count} scan(s)</span>
                  </div>
                  <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                    <div 
                      className="bg-gradient-to-r from-blue-500 via-indigo-500 to-violet-500 h-full rounded-full transition-all duration-500"
                      style={{ width: `${Math.min(100, (cat.count / Math.max(1, stats.total_scans)) * 100)}%` }}
                    ></div>
                  </div>
                </div>
              ))
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                No threat categories recorded
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="rounded-2xl bg-navy-900/80 border border-slate-800/80 overflow-hidden shadow-xl">
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white">Latest Security Inspection Reports</h2>
            <p className="text-xs text-slate-400">Recent SQLite scan audit logs</p>
          </div>
          <button 
            onClick={() => onNavigateToScanner('history')}
            className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1 transition-colors"
          >
            <span>View All History</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Vector</th>
                <th className="py-3 px-4">Target Summary</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Threat Level</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {recentScans.length > 0 ? (
                recentScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-4 font-mono uppercase text-slate-400 text-[11px]">
                      {scan.scan_type}
                    </td>
                    <td className="py-3.5 px-4 font-medium max-w-xs truncate text-white">
                      {scan.target_summary}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 text-[11px]">
                      {scan.category}
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold">
                      <span className={
                        scan.risk_score >= 75 ? 'text-rose-400' :
                        scan.risk_score >= 50 ? 'text-orange-400' :
                        scan.risk_score >= 25 ? 'text-amber-400' : 'text-emerald-400'
                      }>
                        {scan.risk_score} / 100
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        scan.threat_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                        scan.threat_level === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                        scan.threat_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                        'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      }`}>
                        {scan.threat_level}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => onSelectScan(scan.id)}
                        className="px-2.5 py-1 rounded bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 font-medium transition-all text-xs"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No scan activity recorded yet. Run a message or URL inspection to generate telemetry.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
