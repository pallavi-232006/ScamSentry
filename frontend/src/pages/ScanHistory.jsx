import React, { useEffect, useState } from 'react';
import { 
  History, Trash2, Eye, ShieldAlert, ShieldCheck, 
  AlertTriangle, RefreshCw, X, ArrowLeft, Search, Filter,
  Layers, Copy, Check, AlertOctagon
} from 'lucide-react';
import { api } from '../services/api';

export default function ScanHistory({ initialSelectedId, onBack }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [copied, setCopied] = useState(false);

  // Filters state
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('all');
  const [selectedLevel, setSelectedLevel] = useState('all');
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [notification, setNotification] = useState(null);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getHistory({
        limit: 100,
        scan_type: selectedType,
        threat_level: selectedLevel,
        search: searchTerm,
      });
      setHistory(data || []);
    } catch (err) {
      console.error("Failed to load history:", err);
      showNotification("Failed to fetch history logs", "error");
    } finally {
      setLoading(false);
    }
  };

  const showNotification = (msg, type = "success") => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 3000);
  };

  const loadScanDetail = async (id) => {
    setLoadingDetail(true);
    try {
      const detail = await api.getScanDetail(id);
      setSelectedScan(detail);
    } catch (err) {
      console.error("Failed to load scan detail:", err);
      showNotification("Failed to load scan detail", "error");
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm(`Permanently remove scan #${id} from the database?`)) return;

    try {
      await api.deleteScan(id);
      setHistory((prev) => prev.filter((item) => item.id !== id));
      if (selectedScan?.id === id) {
        setSelectedScan(null);
      }
      showNotification(`Scan #${id} deleted successfully`);
    } catch (err) {
      console.error("Failed to delete record:", err);
      showNotification("Failed to delete scan record", "error");
    }
  };

  const handleClearAll = async () => {
    try {
      await api.clearAllHistory();
      setHistory([]);
      setSelectedScan(null);
      setShowClearConfirm(false);
      showNotification("All scan history records cleared successfully");
    } catch (err) {
      console.error("Failed to clear history:", err);
      showNotification("Failed to clear history", "error");
    }
  };

  const handleCopyReport = () => {
    if (!selectedScan) return;
    const txt = `[ScamSentry Threat Inspection #${selectedScan.id}]
Target: ${selectedScan.metadata?.raw_content || selectedScan.target_summary}
Score: ${selectedScan.risk_score}/100 (${selectedScan.threat_level})
Category: ${selectedScan.category}
Recommendations: ${selectedScan.recommendations?.join(' ')}`;
    navigator.clipboard.writeText(txt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  useEffect(() => {
    fetchHistory();
  }, [selectedType, selectedLevel]);

  // Debounced search
  useEffect(() => {
    const handler = setTimeout(() => {
      fetchHistory();
    }, 300);
    return () => clearTimeout(handler);
  }, [searchTerm]);

  useEffect(() => {
    if (initialSelectedId) {
      loadScanDetail(initialSelectedId);
    }
  }, [initialSelectedId]);

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Toast Notification */}
      {notification && (
        <div className={`p-3 rounded-xl border text-xs flex items-center justify-between shadow-lg transition-all ${
          notification.type === 'error'
            ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
            : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
        }`}>
          <span>{notification.msg}</span>
          <button onClick={() => setNotification(null)} className="ml-2">✕</button>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <History className="w-6 h-6 text-blue-400" />
            Audit & Scan History
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Persisted SQLite logs of all heuristic & ML security inspections. Search, inspect, or manage records.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          {history.length > 0 && (
            <button
              onClick={() => setShowClearConfirm(true)}
              className="px-3 py-2 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 hover:text-white transition-all flex items-center gap-1.5 text-xs font-medium"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
              <span>Clear History</span>
            </button>
          )}

          <button
            onClick={fetchHistory}
            className="p-2.5 rounded-lg bg-navy-900 border border-slate-800 text-slate-300 hover:text-white transition-all flex items-center gap-2 text-xs"
            title="Refresh logs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>

      {/* Search and Filters Bar */}
      <div className="p-4 rounded-xl bg-navy-900/80 border border-slate-800 flex flex-col md:flex-row items-center gap-3 justify-between">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search keywords, categories, or URLs..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto justify-end">
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Vector:</span>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Vectors</option>
              <option value="message">Messages</option>
              <option value="url">URLs</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Severity:</span>
            <select
              value={selectedLevel}
              onChange={(e) => setSelectedLevel(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Tiers</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>
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
                    <td className="py-3.5 px-4 font-mono uppercase text-slate-400 text-[11px]">{item.scan_type}</td>
                    <td className="py-3.5 px-4 font-medium text-white max-w-xs truncate">{item.target_summary}</td>
                    <td className="py-3.5 px-4 text-slate-300 text-[11px]">{item.category}</td>
                    <td className="py-3.5 px-4 font-mono font-bold">
                      <span className={
                        item.risk_score >= 75 ? 'text-rose-400' :
                        item.risk_score >= 50 ? 'text-orange-400' :
                        item.risk_score >= 25 ? 'text-amber-400' : 'text-emerald-400'
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
                      {new Date(item.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })}
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
                  <td colSpan={8} className="py-12 text-center text-slate-500">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <Layers className="w-8 h-8 text-slate-600 mb-1" />
                      <span className="text-slate-400 font-medium">No matching security records found</span>
                      <span className="text-[11px] text-slate-600 max-w-sm">
                        {searchTerm ? "Try broadening your search term or resetting active filters." : "Scanned messages and inspected URLs will automatically be logged here."}
                      </span>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Confirmation Modal for Clear History */}
      {showClearConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="w-full max-w-md bg-navy-900 border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
                <AlertOctagon className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Clear All Scan Records?</h3>
                <p className="text-xs text-slate-400">This action will permanently delete all persisted logs from SQLite.</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 bg-slate-950 p-3 rounded-xl border border-slate-800">
              Are you sure you want to delete all historical telemetry? This action cannot be reversed.
            </p>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setShowClearConfirm(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleClearAll}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-medium transition-colors"
              >
                Yes, Delete All Records
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Detail Modal / Drawer */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
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
                <span className="text-xs text-slate-400 font-mono">Record #{selectedScan.id}</span>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                  {selectedScan.scan_type}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyReport}
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors text-xs flex items-center gap-1"
                  title="Copy details"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => setSelectedScan(null)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-all"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-5 text-xs">
              <div>
                <label className="text-slate-400 font-semibold uppercase tracking-wider block mb-1">
                  Full Analyzed Payload
                </label>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-slate-200 break-all select-all leading-relaxed max-h-48 overflow-y-auto">
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
                        <p className="text-slate-400 text-[11px] leading-relaxed">{ind.description}</p>
                      </div>
                    ))
                  ) : (
                    <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <span>Zero threat indicators triggered. Baseline benign scan.</span>
                    </div>
                  )}
                </div>
              </div>

              <div>
                <label className="text-slate-400 font-semibold uppercase tracking-wider block mb-2">
                  Safety Guidance & Prescribed Actions
                </label>
                <ul className="space-y-1.5 text-slate-300">
                  {selectedScan.recommendations && selectedScan.recommendations.length > 0 ? (
                    selectedScan.recommendations.map((rec, i) => (
                      <li key={i} className="p-2.5 rounded-lg bg-blue-500/5 border border-blue-500/20 text-blue-200 flex items-start gap-2">
                        <span className="text-blue-400">•</span>
                        <span>{rec}</span>
                      </li>
                    ))
                  ) : (
                    <p className="text-slate-500">No special action required.</p>
                  )}
                </ul>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
              <span className="text-[11px] text-slate-500 font-mono">
                Logged at: {new Date(selectedScan.created_at).toLocaleString()}
              </span>
              <button
                onClick={() => setSelectedScan(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-medium transition-all"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
