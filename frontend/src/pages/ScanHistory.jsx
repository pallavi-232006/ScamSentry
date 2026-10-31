import React, { useEffect, useState } from 'react';
import { 
  History, Trash2, Eye, ShieldAlert, ShieldCheck, 
  AlertTriangle, RefreshCw, X, ArrowLeft 
} from 'lucide-react';
import { api } from '../services/api';

export default function ScanHistory({ initialSelectedId, onBack }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getHistory(50);
      setHistory(data);
    } catch (err) {
      console.error("Failed to load history:", err);
    } finally {
      setLoading(false);
    }
  };

  const loadScanDetail = async (id) => {
    setLoadingDetail(true);
    try {
      const detail = await api.getScanDetail(id);
      setSelectedScan(detail);
    } catch (err) {
      console.error("Failed to load scan detail:", err);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm("Remove this scan record from database?")) return;

    try {
      await api.deleteScan(id);
      setHistory((prev) => prev.filter((item) => item.id !== id));
      if (selectedScan?.id === id) {
        setSelectedScan(null);
      }
    } catch (err) {
      console.error("Failed to delete record:", err);
    }
  };

  useEffect(() => {
    fetchHistory();
    if (initialSelectedId) {
      loadScanDetail(initialSelectedId);
    }
  }, [initialSelectedId]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <History className="w-6 h-6 text-blue-400" />
            Audit & Scan History
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Persisted SQLite logs of all heuristic & ML security inspections.
          </p>
        </div>

        <button
          onClick={fetchHistory}
          className="p-2.5 rounded-lg bg-navy-900 border border-slate-800 text-slate-300 hover:text-white transition-all flex items-center gap-2 text-xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Main Table */}
      <div className="rounded-2xl bg-navy-900/90 border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">ID</th>
                <th className="py-3 px-4">Vector</th>
                <th className="py-3 px-4">Target Summary</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Threat Level</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {history.length > 0 ? (
                history.map((item) => (
                  <tr 
                    key={item.id} 
                    onClick={() => loadScanDetail(item.id)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3.5 px-4 font-mono text-slate-500">#{item.id}</td>
                    <td className="py-3.5 px-4 font-mono uppercase text-slate-400">{item.scan_type}</td>
                    <td className="py-3.5 px-4 font-medium text-white max-w-xs truncate">{item.target_summary}</td>
                    <td className="py-3.5 px-4 text-slate-300">{item.category}</td>
                    <td className="py-3.5 px-4 font-mono font-bold">
                      <span className={
                        item.risk_score >= 80 ? 'text-rose-400' :
                        item.risk_score >= 50 ? 'text-amber-400' : 'text-emerald-400'
                      }>
                        {item.risk_score}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        item.threat_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                        item.threat_level === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                        item.threat_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                        'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      }`}>
                        {item.threat_level}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px] font-mono">
                      {new Date(item.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-2">
                      <button
                        onClick={(e) => { e.stopPropagation(); loadScanDetail(item.id); }}
                        title="View Report"
                        className="p-1.5 rounded bg-blue-600/10 text-blue-400 hover:bg-blue-600/20 transition-all"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={(e) => handleDelete(item.id, e)}
                        title="Delete Record"
                        className="p-1.5 rounded bg-rose-600/10 text-rose-400 hover:bg-rose-600/20 transition-all"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    {loading ? 'Loading records...' : 'No scan history recorded in SQLite database.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Modal / Drawer */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-navy-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-3">
                <span className={`px-2.5 py-1 rounded text-xs font-bold font-mono uppercase ${
                  selectedScan.threat_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                  selectedScan.threat_level === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                  selectedScan.threat_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                  'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                }`}>
                  {selectedScan.threat_level} ({selectedScan.risk_score}/100)
                </span>
                <span className="text-xs text-slate-400 font-mono">Scan #{selectedScan.id}</span>
              </div>
              <button
                onClick={() => setSelectedScan(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-all"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-5 text-xs">
              <div>
                <label className="text-slate-400 font-semibold uppercase tracking-wider block mb-1">
                  Raw Scanned Target
                </label>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-slate-200 break-all select-all">
                  {selectedScan.metadata?.raw_content || selectedScan.target_summary}
                </div>
              </div>

              <div>
                <label className="text-slate-400 font-semibold uppercase tracking-wider block mb-2">
                  Detected Threat Indicators ({selectedScan.indicators?.length || 0})
                </label>
                <div className="space-y-2">
                  {selectedScan.indicators && selectedScan.indicators.length > 0 ? (
                    selectedScan.indicators.map((ind, i) => (
                      <div key={i} className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80">
                        <div className="flex justify-between font-medium text-white mb-1">
                          <span>{ind.name}</span>
                          <span className="text-blue-400 font-mono">+{ind.score_impact} pts</span>
                        </div>
                        <p className="text-slate-400 text-[11px]">{ind.description}</p>
                      </div>
                    ))
                  ) : (
                    <p className="text-slate-500">No indicators triggered.</p>
                  )}
                </div>
              </div>

              <div>
                <label className="text-slate-400 font-semibold uppercase tracking-wider block mb-2">
                  Recommended Action Plan
                </label>
                <ul className="space-y-1.5 text-slate-300">
                  {selectedScan.recommendations.map((rec, i) => (
                    <li key={i} className="p-2.5 rounded-lg bg-blue-500/5 border border-blue-500/20 text-blue-200">
                      • {rec}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex justify-end">
              <button
                onClick={() => setSelectedScan(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-medium transition-all"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
