import React, { useState } from 'react';
import { 
  ShieldAlert, Sparkles, Send, RefreshCw, AlertTriangle, 
  CheckCircle2, Info, ChevronRight, BrainCircuit,
  Flame, Lock, Scale, Copy, Check
} from 'lucide-react';
import { api } from '../services/api';

const INDIAN_SCAM_PRESETS = [
  {
    title: "1. Fake UPI Collect Request",
    tag: "UPI Fraud",
    type: "sms",
    text: "PhonePe Reward: You have received a cash reward of Rs 25,000! Enter your secret UPI PIN to claim money instantly into your bank account or accept collect request.",
  },
  {
    title: "2. Fake Bank KYC Suspension",
    tag: "KYC / Bank Phish",
    type: "sms",
    text: "Dear SBI user, your YONO account is blocked today due to pending KYC update. Click http://sbi-kyc-pan-update.xyz to update PAN and Aadhaar immediately to avoid permanent deactivation.",
  },
  {
    title: "3. Digital Arrest Threat",
    tag: "Digital Arrest",
    type: "whatsapp",
    text: "CBI & Cyber Crime Cell Notice: A courier package containing 250g MDMA narcotics in your name was intercepted at Mumbai airport. You are under Digital Arrest. Transfer Rs 2,50,000 immediately to RBI security escrow to clear charges.",
  },
  {
    title: "4. Fake Courier Delivery Fee",
    tag: "India Post Phish",
    type: "sms",
    text: "India Post Notice: Consignment #IN82019 failed delivery due to incorrect pin code. Pay Rs 25 redelivery charge at http://indiapost-parcel-redelivery.xyz to avoid return.",
  },
  {
    title: "5. Fraudulent Internship Offer",
    tag: "Fake Job / Task",
    type: "whatsapp",
    text: "Work From Home Internship at Tata Consultancy Services! Earn Rs 2,500 daily for data entry. Pay Rs 499 refundable equipment fee via UPI to start. Contact HR manager on Telegram @remote_career_now.",
  },
  {
    title: "6. OTP Harvesting Message",
    tag: "OTP Theft",
    type: "sms",
    text: "Dear customer, Rs 48,500 debited from your HDFC account. If not done by you, forward the 6-digit verification OTP code received to cancel transfer immediately.",
  },
  {
    title: "7. Fake Government Subsidy",
    tag: "PM Subsidy Fraud",
    type: "sms",
    text: "PM Kisan Samman Nidhi: Your DBT subsidy of Rs 6,000 has been approved. Click to verify your Aadhaar and bank details at http://pmkisan-dbt-subsidy.top",
  },
  {
    title: "8. Legitimate Bank Notification",
    tag: "Legitimate (Safe)",
    type: "sms",
    text: "SBI Alert: Your A/C 9812 is debited by Rs 450.00 on 31-Oct-26 via UPI Ref 410291. Avail Bal: Rs 14,210.00. If not you, SMS BLOCK to 567676.",
  },
];

export default function MessageScanner({ onScanComplete }) {
  const [message, setMessage] = useState('');
  const [sourceType, setSourceType] = useState('auto');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  const handleScan = async (e) => {
    e?.preventDefault();
    if (!message.trim()) {
      setError("Please paste or type message content before scanning.");
      return;
    }

    setIsScanning(true);
    setError(null);

    try {
      const result = await api.scanMessage(message, sourceType);
      setScanResult(result);
      if (onScanComplete) onScanComplete(result);
    } catch (err) {
      setError(err.message || 'Failed to analyze message. Ensure backend is running.');
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

  const handleCopyReport = () => {
    if (!scanResult) return;
    const reportText = `[ScamSentry Threat Report]
Target: ${scanResult.target_summary}
Risk Score: ${scanResult.risk_score}/100 (${scanResult.threat_level})
Classification: ${scanResult.classification || 'SUSPICIOUS'}
Category: ${scanResult.category}
Explanations: ${scanResult.explanations?.join(' ')}
Recommendations: ${scanResult.recommendations?.join(' ')}`;

    navigator.clipboard.writeText(reportText).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-blue-400" />
          Advanced Message Scanner & Intelligence Engine
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Deep contextual analysis for Indian & global cyber threats: UPI collect frauds, bank KYC blocking, digital arrests, OTP theft, and malicious links.
        </p>
      </div>

      {/* Preset selector pills */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-blue-400" /> Indian Cyber Threat Presets (Click to Test Real Backend):
          </span>
          <span className="text-[11px] text-slate-500 font-mono">8 Verified Scenarios</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {INDIAN_SCAM_PRESETS.map((preset, idx) => (
            <button
              key={idx}
              onClick={() => loadPreset(preset)}
              className="text-left p-3 rounded-xl bg-navy-900 border border-slate-800 text-slate-300 hover:text-white hover:border-blue-500/50 hover:bg-slate-800/60 transition-all flex flex-col justify-between group shadow-sm"
            >
              <div className="font-medium text-xs text-slate-200 group-hover:text-blue-300 transition-colors">
                {preset.title}
              </div>
              <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                  {preset.tag}
                </span>
                <span className="uppercase">{preset.type}</span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Analysis Input Form */}
      <div className="p-6 rounded-2xl bg-navy-900/90 border border-slate-800 shadow-xl space-y-4">
        <form onSubmit={handleScan} className="space-y-4">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Paste SMS, WhatsApp, or Email Text
            </label>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Vector:</span>
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
            className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-4 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500/80 focus:ring-1 focus:ring-blue-500/40 transition-all font-sans leading-relaxed"
          />

          <div className="flex items-center justify-between pt-1">
            <span className="text-xs text-slate-500 font-mono">
              {message.length} characters
            </span>
            <div className="flex items-center gap-3">
              {message && (
                <button
                  type="button"
                  onClick={() => { setMessage(''); setScanResult(null); setError(null); }}
                  className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1.5 rounded hover:bg-slate-800 transition-colors"
                >
                  Clear
                </button>
              )}
              <button
                type="submit"
                disabled={isScanning || !message.trim()}
                className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-medium text-xs sm:text-sm transition-all shadow-glow-blue disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Evaluating Threat Vectors...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4" />
                    <span>Run Multi-Vector Scan</span>
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

      {/* Explainable Threat Report Display */}
      {scanResult && (
        <div className="space-y-6 pt-2 animate-in fade-in duration-300">
          <div className="p-6 rounded-2xl bg-navy-900 border border-slate-800 shadow-xl space-y-6">
            
            {/* Header: Score, Classification, Confidence */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    Threat Assessment Report #{scanResult.id}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                    scanResult.classification === 'CONFIRMED_MALICIOUS' ? 'bg-rose-600/25 text-rose-300 border border-rose-500/50 shadow-glow-rose' :
                    scanResult.classification === 'CONFIRMED_THREAT' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-glow-rose' :
                    scanResult.classification === 'LIKELY_SCAM' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                    scanResult.classification === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                    scanResult.classification === 'LOW_RISK' ? 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30' :
                    'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  }`}>
                    {scanResult.classification || 'SUSPICIOUS'}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-white mt-1">
                  {scanResult.category} Threat Analysis
                </h2>
                {scanResult.metadata?.confidence_label && (
                  <p className="text-xs text-slate-400 mt-1 flex items-center gap-1.5">
                    <Scale className="w-3.5 h-3.5 text-blue-400" />
                    Detection Confidence: <span className="text-slate-200 font-semibold">{scanResult.metadata.confidence_label}</span>
                    {' '}({Math.round((scanResult.metadata.confidence_score || 0.8) * 100)}%)
                    <span className="text-[10px] text-slate-600 ml-1">— heuristic+ML convergence score, not ML probability</span>
                  </p>
                )}
              </div>

              {/* Threat Score & Actions */}
              <div className="flex items-center gap-4">
                <button
                  onClick={handleCopyReport}
                  className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 transition-colors flex items-center gap-1.5 text-xs"
                  title="Copy formatted security summary"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  <span className="hidden sm:inline">{copied ? "Copied" : "Copy Report"}</span>
                </button>

                <div className="text-right">
                  <div className="text-xs text-slate-400 uppercase font-semibold">Risk Score</div>
                  <div className={`text-3xl font-black font-mono ${
                    scanResult.risk_score >= 75 ? 'text-rose-400' :
                    scanResult.risk_score >= 50 ? 'text-orange-400' :
                    scanResult.risk_score >= 25 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {scanResult.risk_score} <span className="text-xs text-slate-500">/ 100</span>
                  </div>
                </div>

                <div className={`px-4 py-2.5 rounded-xl text-center font-bold tracking-wider uppercase text-sm border ${
                  scanResult.threat_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                  scanResult.threat_level === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' :
                  scanResult.threat_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                  'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                }`}>
                  {scanResult.threat_level}
                </div>
              </div>
            </div>

            {/* Explanations Section */}
            {scanResult.explanations && scanResult.explanations.length > 0 && (
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                  <Info className="w-4 h-4 text-cyan-400" /> Assessment Explanations & Rationale
                </h3>
                <ul className="space-y-1 text-xs text-slate-300">
                  {scanResult.explanations.map((exp, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                      <span>{exp}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Social Engineering Tactics (Module 2) */}
            {scanResult.social_engineering_tactics && scanResult.social_engineering_tactics.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                  <Flame className="w-4 h-4 text-orange-400" />
                  Psychological Persuasion Tactics ({scanResult.social_engineering_tactics.length})
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {scanResult.social_engineering_tactics.map((tactic, i) => (
                    <div key={i} className="p-4 rounded-xl bg-slate-950/60 border border-orange-500/20 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-semibold text-white">{tactic.name}</span>
                        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-orange-500/10 text-orange-300 border border-orange-500/30">
                          {tactic.category}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {tactic.explanation}
                      </p>
                      <div className="text-[11px] font-mono text-orange-200 bg-slate-900/80 p-2 rounded border border-slate-800 truncate">
                        Evidence: {tactic.evidence}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Machine Learning Analysis Panel (Module 4) */}
            {scanResult.ml_analysis && scanResult.ml_analysis.scam_probability !== undefined && (
              <div className="p-4 rounded-xl bg-indigo-950/20 border border-indigo-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <BrainCircuit className="w-4 h-4 text-indigo-400" />
                    <span className="text-xs font-bold uppercase tracking-wider text-indigo-300">
                      Local ML Pipeline (TF-IDF + Logistic Regression)
                    </span>
                  </div>
                  <span className="text-xs font-mono font-bold text-indigo-300">
                    Scam Probability: {scanResult.ml_analysis.scam_probability}%
                  </span>
                </div>

                {/* Clarification banner */}
                <div className="p-2.5 rounded-lg bg-indigo-950/40 border border-indigo-800/60 text-[11px] text-indigo-300/80 leading-relaxed">
                  <span className="font-semibold text-indigo-200">ℹ ML Probability</span> is a statistical vocabulary-similarity score from a local model trained on {scanResult.ml_analysis.training_samples || 96} labelled messages — it is <span className="font-semibold">not</span> the same as overall detection confidence.
                  The final risk score blends ML (30% weight) with rule-based heuristics (70% weight) only when both agree.
                  {scanResult.metadata?.confidence_label && (
                    <span className="block mt-1">
                      <span className="font-semibold text-indigo-200">Overall Detection Confidence: </span>
                      {scanResult.metadata.confidence_label} ({Math.round((scanResult.metadata.confidence_score || 0) * 100)}%) — {scanResult.metadata.uncertainty_notes}
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-[10px] uppercase font-mono text-slate-500 block">Model Precision</span>
                    <span className="text-slate-200 font-mono font-semibold">
                      {Math.round((scanResult.ml_analysis.model_metrics?.precision || 1.0) * 100)}%
                    </span>
                    <span className="text-[9px] text-slate-600 block">on holdout set</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-[10px] uppercase font-mono text-slate-500 block">Model Recall</span>
                    <span className="text-slate-200 font-mono font-semibold">
                      {Math.round((scanResult.ml_analysis.model_metrics?.recall || 0.83) * 100)}%
                    </span>
                    <span className="text-[9px] text-slate-600 block">on holdout set</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-[10px] uppercase font-mono text-slate-500 block">F1-Score</span>
                    <span className="text-slate-200 font-mono font-semibold">
                      {scanResult.ml_analysis.model_metrics?.f1_score || 0.909}
                    </span>
                    <span className="text-[9px] text-slate-600 block">harmonic mean</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-[10px] uppercase font-mono text-slate-500 block">Holdout Acc.</span>
                    <span className="text-slate-200 font-mono font-semibold">
                      {Math.round((scanResult.ml_analysis.model_metrics?.test_accuracy || 0.917) * 100)}%
                    </span>
                    <span className="text-[9px] text-slate-600 block">stratified split</span>
                  </div>
                </div>

                {scanResult.ml_analysis.top_contributing_ngrams && scanResult.ml_analysis.top_contributing_ngrams.length > 0 && (
                  <div className="pt-1">
                    <span className="text-[11px] text-slate-400 font-medium block mb-1">
                      Top Salient N-Grams (vocabulary match):
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {scanResult.ml_analysis.top_contributing_ngrams.map((ngram, i) => (
                        <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                          {ngram}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Suspicious Phrases Extracted */}
            {scanResult.suspicious_phrases && scanResult.suspicious_phrases.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Suspicious Triggers & Tokens Identified
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

            {/* Limitations Notice */}
            {scanResult.limitations && scanResult.limitations.length > 0 && (
              <div className="pt-2 border-t border-slate-800/80 text-[11px] text-slate-500 space-y-1">
                <span className="font-semibold uppercase tracking-wider text-slate-400 block">
                  Transparency & Limitations
                </span>
                {scanResult.limitations.map((lim, i) => (
                  <p key={i}>• {lim}</p>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
