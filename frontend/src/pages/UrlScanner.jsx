import React, { useState } from 'react';
import { 
  Link2, Sparkles, Send, RefreshCw, AlertTriangle, 
  CheckCircle2, Info, ChevronRight, Globe, Lock, ShieldCheck 
} from 'lucide-react';
import { api } from '../services/api';

const SAMPLE_URLS = [
  {
    title: "Numeric IP + Port Relay (Critical)",
    url: "http://192.168.1.100:8080/paypal/login.php?cmd=verify",
  },
  {
    title: "PayPal Phishing Subdomain (High)",
    url: "https://paypal.account-verification-notice.xyz/signin",
  },
  {
    title: "URL Shortener Masking (Warning)",
    url: "https://bit.ly/bank-tax-refund-claim",
  },
  {
    title: "Legitimate Trusted Domain (Safe)",
    url: "https://www.apple.com/support/system-status",
  },
];

export default function UrlScanner({ onScanComplete }) {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    e?.preventDefault();
    if (!url.trim()) return;

    setIsScanning(true);
    setError(null);

    try {
      const result = await api.scanUrl(url);
      setScanResult(result);
      if (onScanComplete) onScanComplete(result);
    } catch (err) {
      setError(err.message || 'Failed to inspect URL');
    } finally {
      setIsScanning(false);
    }
  };

  const loadPreset = (preset) => {
    setUrl(preset.url);
    setScanResult(null);
    setError(null);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Link2 className="w-6 h-6 text-blue-400" />
          URL Threat Inspector
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Zero-execution structural deception analysis. Inspect lookalikes, IP hosts, and abnormal ports safely.
        </p>
      </div>

      {/* Preset selector pills */}
      <div className="space-y-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-blue-400" /> Test Common Phishing URL Patterns:
        </span>
        <div className="flex flex-wrap gap-2">
          {SAMPLE_URLS.map((preset, idx) => (
            <button
              key={idx}
              onClick={() => loadPreset(preset)}
              className="text-xs px-3 py-1.5 rounded-lg bg-navy-900 border border-slate-800 text-slate-300 hover:text-white hover:border-blue-500/50 hover:bg-slate-800/60 transition-all text-left"
            >
              {preset.title}
            </button>
          ))}
        </div>
      </div>

      {/* URL Input Form */}
      <div className="p-6 rounded-2xl bg-navy-900/90 border border-slate-800 shadow-xl space-y-4">
        <form onSubmit={handleScan} className="space-y-4">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-300 block">
            Target URL Address
          </label>

          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500">
              <Globe className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="e.g. http://192.168.1.1:8080/secure or https://bank-login.xyz"
              className="w-full bg-slate-950/90 border border-slate-800 rounded-xl pl-11 pr-4 py-3 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500/80 focus:ring-1 focus:ring-blue-500/40 font-mono"
            />
          </div>

          <div className="flex items-center justify-between pt-1">
            <span className="text-xs text-slate-500 flex items-center gap-1.5">
              <Lock className="w-3 h-3 text-emerald-400" />
              Air-Gapped: Never connects to remote servers
            </span>
            <div className="flex items-center gap-3">
              {url && (
                <button
                  type="button"
                  onClick={() => { setUrl(''); setScanResult(null); }}
                  className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1.5"
                >
                  Clear
                </button>
              )}
              <button
                type="submit"
                disabled={isScanning || !url.trim()}
                className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-medium text-sm transition-all shadow-glow-blue disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Analyzing Structure...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4" />
                    <span>Inspect URL Safety</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </form>

        {error && (
          <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Structural Threat Report */}
      {scanResult && (
        <div className="space-y-6 pt-2 animate-in fade-in duration-300">
          <div className="p-6 rounded-2xl bg-navy-900 border border-slate-800 shadow-xl space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  URL Inspection Report #{scanResult.id}
                </span>
                <h2 className="text-lg font-bold text-white mt-1 font-mono break-all">
                  {scanResult.target_summary}
                </h2>
              </div>

              {/* Threat Score Badge */}
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <div className="text-xs text-slate-400 uppercase font-semibold">Risk Score</div>
                  <div className={`text-2xl font-black font-mono ${
                    scanResult.risk_score >= 80 ? 'text-rose-400' :
                    scanResult.risk_score >= 50 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {scanResult.risk_score} <span className="text-xs text-slate-500">/ 100</span>
                  </div>
                </div>

                <div className={`px-4 py-2 rounded-xl text-center font-bold tracking-wider uppercase text-sm border ${
                  scanResult.threat_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                  scanResult.threat_level === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' :
                  scanResult.threat_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                  'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                }`}>
                  {scanResult.threat_level}
                </div>
              </div>
            </div>

            {/* Extracted Structural Metadata */}
            {scanResult.metadata && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 text-xs">
                <div>
                  <span className="text-slate-500 block uppercase font-mono text-[10px]">Hostname</span>
                  <span className="font-mono text-slate-200 truncate block">
                    {scanResult.metadata.hostname || 'None'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase font-mono text-[10px]">Protocol / Scheme</span>
                  <span className="font-mono text-slate-200">
                    {scanResult.metadata.scheme || 'http'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase font-mono text-[10px]">Port</span>
                  <span className="font-mono text-slate-200">
                    {scanResult.metadata.port || 'Default (80/443)'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase font-mono text-[10px]">Path Length</span>
                  <span className="font-mono text-slate-200">
                    {scanResult.metadata.path_length || 0} chars
                  </span>
                </div>
              </div>
            )}

            {/* Detected Indicators Breakdown */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                Structural Deception Indicators ({scanResult.indicators?.length || 0})
              </h3>
              
              {scanResult.indicators && scanResult.indicators.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {scanResult.indicators.map((ind, i) => (
                    <div 
                      key={i} 
                      className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-semibold text-white">{ind.name}</span>
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-blue-400 border border-slate-700">
                          +{ind.score_impact} pts
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 leading-relaxed">
                        {ind.description}
                      </div>
                      <div className="text-[10px] font-mono uppercase text-slate-500 pt-1">
                        Category: {ind.category}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 shrink-0" />
                  <span>No deceptive domain techniques, abnormal ports, or IP hostnames detected.</span>
                </div>
              )}
            </div>

            {/* Recommendations */}
            <div className="p-4 rounded-xl bg-blue-500/5 border border-blue-500/20 space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400 flex items-center gap-1.5">
                <Info className="w-4 h-4" /> Safety Guidance
              </h3>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {scanResult.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <ChevronRight className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
