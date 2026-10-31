import React, { useState } from 'react';
import { 
  ShieldAlert, Sparkles, Send, RefreshCw, AlertTriangle, 
  CheckCircle2, Info, ChevronRight, HelpCircle 
} from 'lucide-react';
import { api } from '../services/api';

const SAMPLE_PRESETS = [
  {
    title: "Bank Account Urgency (Critical)",
    type: "sms",
    text: "URGENT from Chase Bank: Your debit card has been suspended due to 3 failed PIN attempts. To reactivate your account immediately, verify your identity and enter your OTP at https://chase-reactivate-login.xyz",
  },
  {
    title: "WhatsApp 6-Digit Verification Code",
    type: "whatsapp",
    text: "Hey! I accidentally sent my 6-digit WhatsApp code to your phone by mistake. Can you please forward it back to me quickly? I need it urgently!",
  },
  {
    title: "Lottery / Prize Claim (High Risk)",
    type: "email",
    text: "Congratulations! You have been selected as the grand winner of the 2026 International Crypto Sweepstakes for $250,000. Send your bank account routing number and social security number to claim immediately.",
  },
  {
    title: "Benign Work Email (Low Risk)",
    type: "email",
    text: "Hi team, please find the updated project timeline for the Q4 sprint attached. Let's discuss any blockers during our standup at 10 AM tomorrow.",
  },
];

export default function MessageScanner({ onScanComplete }) {
  const [message, setMessage] = useState('');
  const [sourceType, setSourceType] = useState('auto');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    e?.preventDefault();
    if (!message.trim()) return;

    setIsScanning(true);
    setError(null);

    try {
      const result = await api.scanMessage(message, sourceType);
      setScanResult(result);
      if (onScanComplete) onScanComplete(result);
    } catch (err) {
      setError(err.message || 'Failed to scan message');
    } finally {
      setIsScanning(false);
    }
  };

  const loadPreset = (preset) => {
    setMessage(preset.text);
    setSourceType(preset.type);
    setScanResult(null);
    setError(null);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-blue-400" />
          Message Threat Scanner
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Deep heuristic and NLP analysis for SMS, WhatsApp chats, and phishing emails.
        </p>
      </div>

      {/* Preset selector pills */}
      <div className="space-y-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-blue-400" /> Try Curated Sample Attack Scenarios:
        </span>
        <div className="flex flex-wrap gap-2">
          {SAMPLE_PRESETS.map((preset, idx) => (
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

      {/* Main Analysis Input Form */}
      <div className="p-6 rounded-2xl bg-navy-900/90 border border-slate-800 shadow-xl space-y-4">
        <form onSubmit={handleScan} className="space-y-4">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Paste Message Content
            </label>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Source:</span>
              <select
                value={sourceType}
                onChange={(e) => setSourceType(e.target.value)}
                className="text-xs bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-300 focus:outline-none focus:border-blue-500"
              >
                <option value="auto">Auto-Detect</option>
                <option value="sms">SMS Text</option>
                <option value="whatsapp">WhatsApp</option>
                <option value="email">Email Body</option>
              </select>
            </div>
          </div>

          <textarea
            rows={5}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Paste raw SMS message, WhatsApp text, or suspicious email content here..."
            className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-4 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500/80 focus:ring-1 focus:ring-blue-500/40 transition-all font-sans"
          />

          <div className="flex items-center justify-between pt-2">
            <span className="text-xs text-slate-500 font-mono">
              {message.length} characters
            </span>
            <div className="flex items-center gap-3">
              {message && (
                <button
                  type="button"
                  onClick={() => { setMessage(''); setScanResult(null); }}
                  className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1.5"
                >
                  Clear
                </button>
              )}
              <button
                type="submit"
                disabled={isScanning || !message.trim()}
                className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-medium text-sm transition-all shadow-glow-blue disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Analyzing Indicators...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4" />
                    <span>Run Threat Scan</span>
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

      {/* Threat Report Display */}
      {scanResult && (
        <div className="space-y-6 pt-2 animate-in fade-in duration-300">
          <div className="p-6 rounded-2xl bg-navy-900 border border-slate-800 shadow-xl space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Scan Evaluation ID: #{scanResult.id}
                </span>
                <h2 className="text-xl font-bold text-white mt-1">
                  Threat Analysis Report
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
                  scanResult.threat_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-glow-rose' :
                  scanResult.threat_level === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' :
                  scanResult.threat_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                  'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                }`}>
                  {scanResult.threat_level}
                </div>
              </div>
            </div>

            {/* Suspicious Phrases Extracted */}
            {scanResult.suspicious_phrases && scanResult.suspicious_phrases.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Suspicious Triggers & Keyphrases Identified
                </h3>
                <div className="flex flex-wrap gap-2">
                  {scanResult.suspicious_phrases.map((phrase, i) => (
                    <span 
                      key={i} 
                      className="px-2.5 py-1 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono"
                    >
                      "{phrase}"
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Detected Indicators Breakdown */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                Detected Threat Indicators ({scanResult.indicators?.length || 0})
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
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>No malicious indicators or high-pressure triggers detected in this text.</span>
                </div>
              )}
            </div>

            {/* Actionable Safety Advice */}
            <div className="p-4 rounded-xl bg-blue-500/5 border border-blue-500/20 space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400 flex items-center gap-1.5">
                <Info className="w-4 h-4" /> Recommended Safety Actions
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
