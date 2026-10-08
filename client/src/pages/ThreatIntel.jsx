import React, { useState, useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Crosshair,
  Search,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Globe,
  Database,
  Terminal,
  Play,
  RotateCcw,
  Copy,
  Download,
  History,
  Check,
  ExternalLink,
  Code2,
  Clock,
  Sparkles,
  Layers,
  FileSpreadsheet,
  FileCode2,
  Info,
  Bot,
  Send,
  ArrowRight,
  RefreshCw,
  ChevronRight,
  HelpCircle,
  Table,
  Eye,
  BookOpen,
  Trash2,
  ArrowUpRight
} from 'lucide-react';
import { iocsApi } from '../services/api';
import StatusBadge from '../components/StatusBadge';
import Spinner from '../components/Spinner';

const SQL_TEMPLATES = [
  {
    label: 'Sample 10 Indicators',
    query: 'SELECT * FROM indicators LIMIT 10;'
  },
  {
    label: 'Total Indicator Count',
    query: 'SELECT COUNT(*) AS total_indicators FROM indicators;'
  },
  {
    label: 'Group by Type',
    query: 'SELECT indicator_type, COUNT(*) AS total FROM indicators GROUP BY indicator_type;'
  },
  {
    label: 'Malicious Only',
    query: "SELECT * FROM indicators WHERE reputation = 'malicious';"
  },
  {
    label: 'Distinct Types',
    query: 'SELECT DISTINCT indicator_type FROM indicators;'
  },
  {
    label: 'Latest Observed (20)',
    query: 'SELECT * FROM indicators ORDER BY last_seen DESC LIMIT 20;'
  },
  {
    label: 'Top Event Source IPs',
    query: 'SELECT source_ip, COUNT(*) AS total_events FROM events WHERE source_ip IS NOT NULL AND source_ip != "" GROUP BY source_ip ORDER BY total_events DESC LIMIT 10;'
  },
  {
    label: 'Critical Alerts',
    query: "SELECT alert_id, title, severity, status, source_ip, host, count FROM alerts WHERE severity = 'critical' ORDER BY count DESC LIMIT 10;"
  },
  {
    label: 'High-Score Threat Feeds',
    query: 'SELECT * FROM threat_intel WHERE score > 70 LIMIT 10;'
  }
];

const SUGGESTED_AI_PROMPTS = [
  { label: 'Top Event Source IPs', prompt: 'Which IP address generated the highest number of events?' },
  { label: 'Failed Logins by User', prompt: 'Which user has the highest number of failed login attempts?' },
  { label: 'Total Security Events', prompt: 'How many total security events are recorded?' },
  { label: 'Malicious IP Addresses', prompt: 'Show all malicious IP addresses.' },
  { label: 'Top 10 Source IPs', prompt: 'List the top 10 source IP addresses.' },
  { label: 'Unique Users Count', prompt: 'How many unique users are present?' },
  { label: 'Suspicious Auth Events', prompt: 'Show suspicious authentication events.' },
  { label: 'Repeated Failed Logins', prompt: 'Which IP addresses are associated with multiple failed logins?' },
  { label: 'Critical Severity Alerts', prompt: 'Show all critical severity alerts.' },
  { label: 'Earliest Forensic Event', prompt: 'What is the earliest event in the dataset?' },
  { label: 'Latest 20 Events', prompt: 'Show the latest 20 security events.' },
  { label: 'Top Alerting Hosts', prompt: 'Which hosts generated the most security alerts?' }
];

export default function ThreatIntel() {
  const [activeTab, setActiveTab] = useState('ai'); // 'ai' | 'sql' | 'lookup'
  const [search, setSearch] = useState('');

  // --- Rapid Indicator Lookup State ---
  const [lookupType, setLookupType] = useState('auto');
  const [lookupQuery, setLookupQuery] = useState('194.26.29.112');
  const [lookupResult, setLookupResult] = useState(null);
  const [isLookingUp, setIsLookingUp] = useState(false);

  // --- SQL Query Engine State ---
  const [sqlQuery, setSqlQuery] = useState('SELECT * FROM indicators LIMIT 10;');
  const [sqlResult, setSqlResult] = useState(null);
  const [isExecutingSql, setIsExecutingSql] = useState(false);
  const [sqlError, setSqlError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [queryInsertedNotice, setQueryInsertedNotice] = useState(false);
  const [queryHistory, setQueryHistory] = useState(() => {
    try {
      const saved = localStorage.getItem('aegis_sql_history');
      return saved ? JSON.parse(saved) : [
        'SELECT * FROM indicators LIMIT 10;',
        'SELECT source_ip, COUNT(*) AS total_events FROM events WHERE source_ip IS NOT NULL AND source_ip != "" GROUP BY source_ip ORDER BY total_events DESC LIMIT 10;',
        "SELECT alert_id, title, severity, status, source_ip, host, count FROM alerts WHERE severity = 'critical' ORDER BY count DESC LIMIT 10;"
      ];
    } catch (e) {
      return [];
    }
  });

  // --- AI Query Assistant State ---
  const [aiQuestion, setAiQuestion] = useState('');
  const [aiDataset, setAiDataset] = useState('all');
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);
  const [aiError, setAiError] = useState(null);
  const [copiedAiSqlId, setCopiedAiSqlId] = useState(null);
  const [executingAiMsgId, setExecutingAiMsgId] = useState(null);
  const [showSchemaModal, setShowSchemaModal] = useState(false);
  const [schemaMetadata, setSchemaMetadata] = useState(null);
  const [selectedSchemaTable, setSelectedSchemaTable] = useState('events');
  const chatBottomRef = useRef(null);

  const [conversation, setConversation] = useState([
    {
      id: 'greeting-1',
      role: 'assistant',
      text: 'Greetings Analyst. I am your SOC AI Natural Language to SQL Assistant. Ask any question about enterprise telemetry, attack vectors, or threat intelligence in English. I will translate it into an optimized, read-only SQL query calibrated to our verified schema.',
      isGreeting: true,
      timestamp: new Date().toISOString()
    }
  ]);

  // Load Schema Metadata on mount
  useEffect(() => {
    iocsApi.getAiSchema()
      .then(res => setSchemaMetadata(res.data))
      .catch(err => console.warn('Failed to prefetch schema metadata:', err));
  }, []);

  // Auto-scroll chat to bottom when conversation updates
  useEffect(() => {
    if (activeTab === 'ai') {
      chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [conversation, isGeneratingAi, activeTab]);

  // Global indicator list query
  const { data: iocs = [], isLoading } = useQuery({
    queryKey: ['threatIntelList', search],
    queryFn: async () => {
      const res = await iocsApi.getIOCs({ search: search || undefined });
      return res.data;
    }
  });

  // Handle single indicator lookup
  const handleLookup = async (e) => {
    if (e) e.preventDefault();
    if (!lookupQuery.trim()) return;

    setIsLookingUp(true);
    setLookupResult(null);

    try {
      const res = await iocsApi.lookup({
        type: lookupType === 'auto' ? undefined : lookupType,
        value: lookupQuery.trim()
      });
      setLookupResult(res.data);
    } catch (err) {
      setLookupResult({
        error: err.response?.data?.message || 'Indicator lookup failed to complete.',
        indicator: lookupQuery.trim(),
        verdict: 'no intelligence available'
      });
    } finally {
      setIsLookingUp(false);
    }
  };

  // Handle SQL execution
  const handleExecuteSql = async (overrideQuery = null) => {
    const targetQuery = typeof overrideQuery === 'string' ? overrideQuery : sqlQuery;
    if (!targetQuery.trim()) return;

    setIsExecutingSql(true);
    setSqlError(null);

    try {
      const res = await iocsApi.executeSql(targetQuery.trim());
      setSqlResult(res.data);

      // Save to query history
      setQueryHistory((prev) => {
        const filtered = prev.filter((q) => q !== targetQuery.trim());
        const updated = [targetQuery.trim(), ...filtered].slice(0, 10);
        try {
          localStorage.setItem('aegis_sql_history', JSON.stringify(updated));
        } catch (e) {}
        return updated;
      });
      return res.data;
    } catch (err) {
      const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'SQL execution failed';
      setSqlError(msg);
      setSqlResult(null);
      throw new Error(msg);
    } finally {
      setIsExecutingSql(false);
    }
  };

  // Keyboard shortcut Ctrl+Enter to execute SQL
  const handleKeyDown = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      handleExecuteSql();
    }
  };

  const handleCopyQuery = () => {
    navigator.clipboard.writeText(sqlQuery);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // --- AI ASSISTANT HANDLERS ---
  const handleSendAiQuestion = async (customPrompt = null) => {
    const questionText = (typeof customPrompt === 'string' ? customPrompt : aiQuestion).trim();
    if (!questionText || isGeneratingAi) return;

    const userMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      text: questionText,
      timestamp: new Date().toISOString()
    };

    setConversation(prev => [...prev, userMessage]);
    setAiQuestion('');
    setIsGeneratingAi(true);
    setAiError(null);

    // Extract conversation turns for contextual follow-ups
    const conversationHistory = conversation
      .filter(m => m.sql)
      .map(m => ({ question: m.question, sql: m.sql }));

    try {
      const res = await iocsApi.generateAiQuery({
        question: questionText,
        conversationHistory,
        dataset: aiDataset
      });

      const assistantMessage = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        question: questionText,
        sql: res.data.sql,
        explanation: res.data.explanation,
        targetTable: res.data.targetTable,
        confidence: res.data.confidence,
        suggestedFollowUps: res.data.suggestedFollowUps || [],
        timestamp: res.data.timestamp || new Date().toISOString(),
        executionResult: null
      };

      setConversation(prev => [...prev, assistantMessage]);
    } catch (err) {
      const errorMsg = err.response?.data?.error || err.response?.data?.message || err.message || 'AI query generation failed.';
      setAiError(errorMsg);
      setConversation(prev => [
        ...prev,
        {
          id: `error-${Date.now()}`,
          role: 'assistant',
          isError: true,
          text: `Query Generation Notice: ${errorMsg}`,
          timestamp: new Date().toISOString()
        }
      ]);
    } finally {
      setIsGeneratingAi(false);
    }
  };

  // Insert generated query into existing SQL console
  const handleInsertQuery = (sql) => {
    setSqlQuery(sql);
    setSqlError(null);
    setActiveTab('sql');
    setQueryInsertedNotice(true);
    setTimeout(() => setQueryInsertedNotice(false), 3000);
  };

  // Run query directly from AI assistant and attach live results to message
  const handleRunAiQuery = async (messageId, sql) => {
    setExecutingAiMsgId(messageId);
    try {
      const result = await handleExecuteSql(sql);
      setConversation(prev =>
        prev.map(msg => msg.id === messageId ? { ...msg, executionResult: result } : msg)
      );
    } catch (err) {
      setConversation(prev =>
        prev.map(msg => msg.id === messageId ? { ...msg, executionError: err.message } : msg)
      );
    } finally {
      setExecutingAiMsgId(null);
    }
  };

  const handleCopyAiSql = (sql, id) => {
    navigator.clipboard.writeText(sql);
    setCopiedAiSqlId(id);
    setTimeout(() => setCopiedAiSqlId(null), 2000);
  };

  const exportAsCSV = (dataToExport = null) => {
    const target = dataToExport || sqlResult;
    if (!target?.results || target.results.length === 0) return;
    const cols = target.columns || Object.keys(target.results[0]);
    const csvRows = [cols.join(',')];

    for (const row of target.results) {
      const vals = cols.map((c) => {
        const val = row[c] === null || row[c] === undefined ? '' : String(row[c]);
        return `"${val.replace(/"/g, '""')}"`;
      });
      csvRows.push(vals.join(','));
    }

    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis_query_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportAsJSON = (dataToExport = null) => {
    const target = dataToExport || sqlResult;
    if (!target?.results || target.results.length === 0) return;
    const blob = new Blob([JSON.stringify(target.results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis_query_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="p-5 bg-[#0f1422] border border-slate-800 rounded-2xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Crosshair className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wide">
              Threat Intelligence & Rapid Indicator Reputation Engine
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Deterministic correlation across Global Threat Intelligence Feeds and Enterprise Forensic Telemetry.
          </p>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <span className="text-slate-400">
            Total Indicators: <strong className="text-cyan-400 font-bold">{iocs.length}</strong>
          </span>
          <span className="px-2.5 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-400 text-[11px] font-bold flex items-center gap-1.5">
            <Sparkles className="w-3 h-3 text-cyan-400" /> AI Query Assistant Active
          </span>
        </div>
      </div>

      {/* Main Module Wrapper with 3-Mode Tabs */}
      <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
        {/* Module Sub-Header & Navigation */}
        <div className="p-4 bg-[#0e1320] border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setActiveTab('ai')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all ${
                activeTab === 'ai'
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-black shadow-[0_0_15px_rgba(6,182,212,0.4)]'
                  : 'bg-[#080b12] text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Bot className="w-4 h-4" /> AI Natural Language Query Assistant
              <span className="px-1.5 py-0.2 bg-black/40 text-cyan-200 rounded text-[9px] uppercase font-bold tracking-wider">
                NL → SQL
              </span>
            </button>

            <button
              onClick={() => setActiveTab('sql')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all ${
                activeTab === 'sql'
                  ? 'bg-cyan-500 text-black shadow-[0_0_15px_rgba(6,182,212,0.4)]'
                  : 'bg-[#080b12] text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Database className="w-4 h-4" /> SQL Telemetry Query Console
              {queryInsertedNotice && (
                <span className="animate-pulse px-1.5 py-0.5 rounded bg-emerald-400 text-black text-[10px] font-bold">
                  Query Inserted!
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('lookup')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all ${
                activeTab === 'lookup'
                  ? 'bg-cyan-500 text-black shadow-[0_0_15px_rgba(6,182,212,0.4)]'
                  : 'bg-[#080b12] text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Globe className="w-4 h-4" /> Single Indicator Reputation Lookup
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowSchemaModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#090e18] hover:bg-[#121a2c] border border-slate-800 text-cyan-400 text-[11px] font-mono transition-colors"
              title="Inspect verified database tables, columns, and types"
            >
              <BookOpen className="w-3.5 h-3.5" /> Schema Explorer
            </button>
          </div>
        </div>

        {/* --- TAB 1: AI NATURAL LANGUAGE TO SQL QUERY ASSISTANT --- */}
        {activeTab === 'ai' && (
          <div className="p-5 space-y-4 font-mono text-xs">
            {/* Top Bar: Dataset Selection & Status */}
            <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-[#070a12] border border-slate-800 rounded-xl">
              <div className="flex items-center gap-2 text-slate-400 text-xs">
                <span className="text-slate-500 font-bold uppercase text-[10px] tracking-wider">Target Dataset:</span>
                <select
                  value={aiDataset}
                  onChange={(e) => setAiDataset(e.target.value)}
                  className="bg-[#0e1320] border border-slate-800 rounded-lg px-2.5 py-1 text-cyan-300 text-xs focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="all">Auto-Detect Schema (All Tables)</option>
                  <option value="events">Security Telemetry (events - 71k+ records)</option>
                  <option value="alerts">Security Alerts (alerts - 60+ rules)</option>
                  <option value="indicators">Extracted IOCs (indicators)</option>
                  <option value="threat_intel">Threat Intelligence Feeds (threat_intel)</option>
                  <option value="cases">Forensic Cases (cases)</option>
                </select>
              </div>

              <div className="flex items-center gap-3 text-[11px]">
                <span className="flex items-center gap-1 text-emerald-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> Read-Only Engine
                </span>
                <button
                  type="button"
                  onClick={() => setConversation([
                    {
                      id: `greeting-${Date.now()}`,
                      role: 'assistant',
                      text: 'Conversation reset. Ask any natural language security question to generate schema-aware SQL queries.',
                      isGreeting: true,
                      timestamp: new Date().toISOString()
                    }
                  ])}
                  className="flex items-center gap-1 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  <Trash2 className="w-3 h-3" /> Clear Chat
                </button>
              </div>
            </div>

            {/* Quick Suggested SOC Questions Bar */}
            <div className="space-y-1.5">
              <span className="text-[11px] text-slate-400 flex items-center gap-1.5 font-bold uppercase tracking-wider">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" /> Analyst Quick Prompts:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {SUGGESTED_AI_PROMPTS.map((item, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleSendAiQuestion(item.prompt)}
                    disabled={isGeneratingAi}
                    className="px-2.5 py-1 rounded-lg bg-[#0e1320] hover:bg-[#161d30] hover:border-cyan-500/50 border border-slate-800 text-slate-300 text-[11px] transition-all disabled:opacity-50"
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Conversation Window */}
            <div className="min-h-[380px] max-h-[560px] overflow-y-auto space-y-4 p-4 rounded-xl border border-slate-800 bg-[#060910] shadow-inner">
              {conversation.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  {msg.role === 'assistant' && (
                    <div className="w-7 h-7 rounded-lg bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center flex-shrink-0 text-cyan-400 mt-1">
                      <Bot className="w-4 h-4" />
                    </div>
                  )}

                  <div
                    className={`max-w-[85%] rounded-2xl p-4 space-y-3 ${
                      msg.role === 'user'
                        ? 'bg-gradient-to-r from-blue-950/80 to-cyan-950/80 border border-cyan-800/60 text-cyan-100 rounded-tr-none'
                        : msg.isError
                        ? 'bg-rose-950/60 border border-rose-800 text-rose-300'
                        : 'bg-[#0d121f] border border-slate-800 text-slate-200 rounded-tl-none shadow-lg'
                    }`}
                  >
                    {/* Message Header */}
                    <div className="flex items-center justify-between gap-3 text-[10px] text-slate-400 pb-1 border-b border-slate-800/60">
                      <span className="font-bold tracking-wider uppercase text-cyan-400">
                        {msg.role === 'user' ? 'SOC Analyst' : 'AEGIS Query Assistant'}
                      </span>
                      <span>{new Date(msg.timestamp).toLocaleTimeString()}</span>
                    </div>

                    {/* Text / Question */}
                    {msg.text && (
                      <p className="text-xs leading-relaxed text-slate-300 whitespace-pre-wrap">{msg.text}</p>
                    )}

                    {/* AI Generated SQL Block */}
                    {msg.sql && (
                      <div className="space-y-3 pt-1">
                        {/* Explanation */}
                        {msg.explanation && (
                          <div className="p-2.5 rounded-lg bg-[#070a12] border border-cyan-900/40 text-cyan-200/90 text-xs flex items-start gap-2">
                            <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                            <div>
                              <strong className="block text-cyan-300 text-[11px] uppercase font-bold mb-0.5">
                                Query Rationale:
                              </strong>
                              <span>{msg.explanation}</span>
                            </div>
                          </div>
                        )}

                        {/* SQL Syntax Card */}
                        <div className="relative rounded-xl border border-slate-800 bg-[#04060a] overflow-hidden">
                          <div className="px-3 py-1.5 bg-[#0a0f1d] border-b border-slate-800/80 flex items-center justify-between text-[11px]">
                            <div className="flex items-center gap-2 text-slate-400">
                              <Code2 className="w-3.5 h-3.5 text-cyan-400" />
                              <span className="font-bold text-slate-300">Generated SQL</span>
                              <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 text-[10px]">
                                Target: {msg.targetTable}
                              </span>
                              {msg.confidence && (
                                <span className="px-1.5 py-0.2 rounded bg-emerald-950/80 text-emerald-300 text-[10px] border border-emerald-800/60">
                                  {msg.confidence}% Confidence
                                </span>
                              )}
                            </div>

                            <button
                              type="button"
                              onClick={() => handleCopyAiSql(msg.sql, msg.id)}
                              className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-colors"
                            >
                              {copiedAiSqlId === msg.id ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-400" /> Copied
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" /> Copy
                                </>
                              )}
                            </button>
                          </div>

                          <pre className="p-3 text-cyan-300 font-mono text-xs overflow-x-auto leading-relaxed select-all">
                            <code>{msg.sql}</code>
                          </pre>
                        </div>

                        {/* Action Buttons Toolbar: Insert Query, Run Query, Regenerate */}
                        <div className="flex flex-wrap items-center gap-2 pt-1">
                          <button
                            type="button"
                            onClick={() => handleRunAiQuery(msg.id, msg.sql)}
                            disabled={executingAiMsgId === msg.id}
                            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-bold transition-all shadow-[0_0_12px_rgba(6,182,212,0.3)] disabled:opacity-50"
                          >
                            {executingAiMsgId === msg.id ? (
                              <>
                                <Spinner size="sm" /> Executing on DB...
                              </>
                            ) : (
                              <>
                                <Play className="w-3.5 h-3.5 fill-black" /> Run Query
                              </>
                            )}
                          </button>

                          <button
                            type="button"
                            onClick={() => handleInsertQuery(msg.sql)}
                            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-[#090e18] hover:bg-[#12192b] border border-slate-700 text-slate-200 hover:text-cyan-300 transition-colors"
                            title="Copy query into SQL Query Console editor without executing"
                          >
                            <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Insert Query into Console
                          </button>

                          <button
                            type="button"
                            onClick={() => handleSendAiQuestion(msg.question)}
                            disabled={isGeneratingAi}
                            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-[#090e18] hover:bg-[#12192b] border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
                            title="Regenerate query for this question"
                          >
                            <RefreshCw className="w-3.5 h-3.5" /> Regenerate
                          </button>
                        </div>

                        {/* Live Query Execution Results Table (Embedded inside message) */}
                        {msg.executionResult && (
                          <div className="mt-3 border border-slate-800 rounded-xl overflow-hidden bg-[#05070d] shadow-lg animate-in fade-in duration-300">
                            <div className="px-3.5 py-2 bg-[#090d18] border-b border-slate-800 flex items-center justify-between text-xs">
                              <div className="flex items-center gap-2">
                                <span className="px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-800/80 text-emerald-300 font-bold text-[11px] flex items-center gap-1">
                                  <CheckCircle2 className="w-3 h-3" /> {msg.executionResult.totalRecords} Records Found
                                </span>
                                <span className="text-slate-400 text-[11px] flex items-center gap-1">
                                  <Clock className="w-3 h-3 text-slate-500" /> {msg.executionResult.executionTimeMs}ms
                                </span>
                              </div>

                              <div className="flex items-center gap-1.5">
                                <button
                                  type="button"
                                  onClick={() => exportAsCSV(msg.executionResult)}
                                  className="flex items-center gap-1 px-2 py-1 rounded bg-[#0e1320] hover:bg-[#161d30] border border-slate-800 text-slate-300 text-[10px] transition-colors"
                                >
                                  <FileSpreadsheet className="w-3 h-3 text-emerald-400" /> CSV
                                </button>
                                <button
                                  type="button"
                                  onClick={() => exportAsJSON(msg.executionResult)}
                                  className="flex items-center gap-1 px-2 py-1 rounded bg-[#0e1320] hover:bg-[#161d30] border border-slate-800 text-slate-300 text-[10px] transition-colors"
                                >
                                  <FileCode2 className="w-3 h-3 text-cyan-400" /> JSON
                                </button>
                              </div>
                            </div>

                            <div className="overflow-x-auto max-h-[260px]">
                              <table className="w-full text-left text-xs font-mono text-slate-300">
                                <thead className="bg-[#0b0f19] border-b border-slate-800 sticky top-0 uppercase tracking-wider text-slate-400 text-[10px]">
                                  <tr>
                                    {msg.executionResult.columns.map((col, idx) => (
                                      <th key={idx} className="px-3 py-2 font-semibold">
                                        {col}
                                      </th>
                                    ))}
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/60">
                                  {msg.executionResult.results.length === 0 ? (
                                    <tr>
                                      <td colSpan={msg.executionResult.columns.length} className="py-6 text-center text-slate-500">
                                        0 records returned for this query.
                                      </td>
                                    </tr>
                                  ) : (
                                    msg.executionResult.results.map((row, rowIdx) => (
                                      <tr key={rowIdx} className="hover:bg-[#0f1422] transition-colors">
                                        {msg.executionResult.columns.map((col, colIdx) => {
                                          const val = row[col];
                                          return (
                                            <td key={colIdx} className="px-3 py-2 text-[11px]">
                                              {col.toLowerCase().includes('reputation') || col.toLowerCase().includes('verdict') ? (
                                                <StatusBadge status={String(val)} />
                                              ) : col.toLowerCase().includes('type') ? (
                                                <span className="uppercase font-bold text-cyan-400">{String(val)}</span>
                                              ) : typeof val === 'object' && val !== null ? (
                                                JSON.stringify(val)
                                              ) : (
                                                String(val ?? '—')
                                              )}
                                            </td>
                                          );
                                        })}
                                      </tr>
                                    ))
                                  )}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        )}

                        {/* Execution Error Notice */}
                        {msg.executionError && (
                          <div className="p-3 rounded-lg bg-rose-950/70 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                            <span>Execution Error: {msg.executionError}</span>
                          </div>
                        )}

                        {/* Suggested Follow-Up Prompts */}
                        {msg.suggestedFollowUps && msg.suggestedFollowUps.length > 0 && (
                          <div className="pt-2 border-t border-slate-800/60 space-y-1.5">
                            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider flex items-center gap-1">
                              <ChevronRight className="w-3 h-3 text-cyan-400" /> Suggested Contextual Follow-ups:
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {msg.suggestedFollowUps.map((promptText, idx) => (
                                <button
                                  key={idx}
                                  type="button"
                                  onClick={() => handleSendAiQuestion(promptText)}
                                  disabled={isGeneratingAi}
                                  className="px-2.5 py-1 rounded-lg bg-[#070b14] hover:bg-[#101726] border border-cyan-900/40 hover:border-cyan-500/60 text-cyan-300 text-[11px] transition-all"
                                >
                                  {promptText} →
                                </button>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              ))}

              {/* Generating indicator */}
              {isGeneratingAi && (
                <div className="flex gap-3 justify-start animate-in fade-in duration-200">
                  <div className="w-7 h-7 rounded-lg bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center flex-shrink-0 text-cyan-400 mt-1">
                    <Bot className="w-4 h-4" />
                  </div>
                  <div className="p-4 rounded-2xl bg-[#0d121f] border border-slate-800 text-slate-200 rounded-tl-none flex items-center gap-3">
                    <Spinner size="sm" />
                    <span className="text-xs text-cyan-300">
                      Analyzing question against database schema and compiling SQL query...
                    </span>
                  </div>
                </div>
              )}

              <div ref={chatBottomRef} />
            </div>

            {/* AI Error Display */}
            {aiError && (
              <div className="p-3 rounded-xl bg-rose-950/70 border border-rose-800 text-rose-300 flex items-start gap-2.5 text-xs">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 text-rose-400 mt-0.5" />
                <div>
                  <strong className="block font-bold">Query Assistant Error:</strong>
                  <span>{aiError}</span>
                </div>
              </div>
            )}

            {/* Input Bar */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendAiQuestion();
              }}
              className="flex gap-2 pt-1"
            >
              <div className="flex-1 relative">
                <input
                  type="text"
                  placeholder="Ask a question in English (e.g. Which IP address generated the highest number of events?)..."
                  value={aiQuestion}
                  onChange={(e) => setAiQuestion(e.target.value)}
                  disabled={isGeneratingAi}
                  className="w-full bg-[#070a10] border border-slate-800 rounded-xl pl-4 pr-10 py-3 text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none text-xs font-mono"
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-slate-600 font-mono hidden sm:inline">
                  Press Enter
                </span>
              </div>

              <button
                type="submit"
                disabled={isGeneratingAi || !aiQuestion.trim()}
                className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-bold disabled:opacity-50 transition-all flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.3)]"
              >
                {isGeneratingAi ? (
                  <Spinner size="sm" />
                ) : (
                  <>
                    <Send className="w-4 h-4" /> Send
                  </>
                )}
              </button>
            </form>
          </div>
        )}

        {/* --- TAB 2: SQL TELEMETRY QUERY CONSOLE --- */}
        {activeTab === 'sql' && (
          <div className="p-5 space-y-4 font-mono text-xs">
            {/* Template Selector Bar */}
            <div className="space-y-1.5">
              <span className="text-[11px] text-slate-400 flex items-center gap-1.5 font-bold uppercase tracking-wider">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" /> Pre-built SQL Query Templates:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {SQL_TEMPLATES.map((tpl, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      setSqlQuery(tpl.query);
                      setSqlError(null);
                    }}
                    className="px-2.5 py-1 rounded-lg bg-[#0e1320] hover:bg-[#161d30] border border-slate-800 text-slate-300 text-[11px] transition-colors"
                  >
                    {tpl.label}
                  </button>
                ))}
              </div>
            </div>

            {/* SQL Editor Area */}
            <div className="relative rounded-xl border border-slate-800 bg-[#070a10] overflow-hidden focus-within:border-cyan-500 shadow-inner">
              <div className="px-4 py-2 bg-[#0d121f] border-b border-slate-800/80 flex items-center justify-between">
                <div className="flex items-center gap-2 text-slate-400 text-[11px]">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="font-bold">SQL Query Console</span>
                  <span className="text-slate-600">//</span>
                  <span className="text-slate-500">Ctrl + Enter to Execute</span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleCopyQuery}
                    className="flex items-center gap-1 px-2.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-colors"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? 'Copied' : 'Copy SQL'}
                  </button>

                  <button
                    type="button"
                    onClick={() => setSqlQuery('')}
                    className="flex items-center gap-1 px-2.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-colors"
                  >
                    <RotateCcw className="w-3 h-3" /> Clear
                  </button>
                </div>
              </div>

              <textarea
                rows={5}
                value={sqlQuery}
                onChange={(e) => setSqlQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Write SELECT query (e.g. SELECT * FROM events WHERE status = 'failed' LIMIT 10;)"
                className="w-full bg-[#070a10] text-cyan-300 p-4 font-mono text-xs focus:outline-none resize-y leading-relaxed select-all"
                spellCheck={false}
              />
            </div>

            {/* Controls & Export Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleExecuteSql()}
                  disabled={isExecutingSql || !sqlQuery.trim()}
                  className="px-6 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-bold disabled:opacity-50 transition-all flex items-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.4)]"
                >
                  {isExecutingSql ? (
                    <>
                      <Spinner size="sm" /> Executing SQL...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-black" /> Execute Query
                    </>
                  )}
                </button>

                {sqlResult && (
                  <div className="flex items-center gap-2 text-xs">
                    <span className="px-2.5 py-1 rounded-lg bg-emerald-950/60 border border-emerald-800/80 text-emerald-300 font-bold flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5" /> {sqlResult.totalRecords} records
                    </span>
                    <span className="px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300 flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-400" /> {sqlResult.executionTimeMs}ms
                    </span>
                  </div>
                )}
              </div>

              {sqlResult?.results?.length > 0 && (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => exportAsCSV()}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0e1320] hover:bg-[#161d30] border border-slate-800 text-slate-300 text-xs transition-colors"
                  >
                    <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" /> Export CSV
                  </button>
                  <button
                    type="button"
                    onClick={() => exportAsJSON()}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0e1320] hover:bg-[#161d30] border border-slate-800 text-slate-300 text-xs transition-colors"
                  >
                    <FileCode2 className="w-3.5 h-3.5 text-cyan-400" /> Export JSON
                  </button>
                </div>
              )}
            </div>

            {/* Error Display */}
            {sqlError && (
              <div className="p-3.5 rounded-xl bg-rose-950/70 border border-rose-800 text-rose-300 flex items-start gap-2.5 text-xs">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 text-rose-400 mt-0.5" />
                <div>
                  <strong className="block font-bold">SQL Execution Error:</strong>
                  <span>{sqlError}</span>
                </div>
              </div>
            )}

            {/* Query Results Table */}
            {sqlResult && (
              <div className="border border-slate-800 rounded-xl overflow-hidden bg-[#070a10] shadow-lg">
                <div className="px-4 py-2.5 bg-[#0d121f] border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
                  <span>Query Results ({sqlResult.totalRecords} Rows)</span>
                  <span className="text-[11px] text-slate-500 font-mono">Read-Only Telemetry View</span>
                </div>

                <div className="overflow-x-auto max-h-[380px]">
                  <table className="w-full text-left text-xs font-mono text-slate-300">
                    <thead className="bg-[#0b0f19] border-b border-slate-800 sticky top-0 uppercase tracking-wider text-slate-400 text-[11px]">
                      <tr>
                        {sqlResult.columns.map((col, idx) => (
                          <th key={idx} className="px-4 py-2.5 font-semibold">
                            {col}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {sqlResult.results.length === 0 ? (
                        <tr>
                          <td colSpan={sqlResult.columns.length} className="py-8 text-center text-slate-500">
                            0 records matched query criteria.
                          </td>
                        </tr>
                      ) : (
                        sqlResult.results.map((row, rowIdx) => (
                          <tr key={rowIdx} className="hover:bg-[#121829] transition-colors">
                            {sqlResult.columns.map((col, colIdx) => {
                              const val = row[col];
                              return (
                                <td key={colIdx} className="px-4 py-2.5">
                                  {col.toLowerCase().includes('reputation') || col.toLowerCase().includes('verdict') ? (
                                    <StatusBadge status={String(val)} />
                                  ) : col.toLowerCase().includes('type') ? (
                                    <span className="uppercase font-bold text-cyan-400">{String(val)}</span>
                                  ) : typeof val === 'object' && val !== null ? (
                                    JSON.stringify(val)
                                  ) : (
                                    String(val ?? '—')
                                  )}
                                </td>
                              );
                            })}
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Query History */}
            {queryHistory.length > 0 && (
              <div className="pt-2 border-t border-slate-800/60">
                <div className="flex items-center gap-1.5 text-[11px] text-slate-500 font-bold uppercase mb-2">
                  <History className="w-3.5 h-3.5" /> Recent Query History:
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {queryHistory.map((hQuery, i) => (
                    <button
                      key={i}
                      type="button"
                      onClick={() => setSqlQuery(hQuery)}
                      className="px-2.5 py-1 rounded bg-[#090d16] hover:bg-[#12192b] border border-slate-800/80 text-slate-400 hover:text-cyan-300 text-[11px] transition-colors truncate max-w-xs"
                      title={hQuery}
                    >
                      {hQuery}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* --- TAB 3: RAPID INDICATOR REPUTATION LOOKUP --- */}
        {activeTab === 'lookup' && (
          <div className="p-5 space-y-5 font-mono text-xs">
            <form onSubmit={handleLookup} className="space-y-3">
              <div className="flex flex-col sm:flex-row gap-2">
                <select
                  value={lookupType}
                  onChange={(e) => setLookupType(e.target.value)}
                  className="bg-[#070a10] border border-slate-800 rounded-xl px-3 py-2.5 text-slate-200 focus:border-cyan-500 focus:outline-none text-xs font-mono"
                >
                  <option value="auto">Auto-Detect Type</option>
                  <option value="ip">IPv4 / IPv6 Address</option>
                  <option value="domain">Domain Name</option>
                  <option value="url">URL Address</option>
                  <option value="hash">File Hash (MD5 / SHA256)</option>
                  <option value="email">Email Address</option>
                </select>

                <div className="flex-1 relative">
                  <input
                    type="text"
                    placeholder="Enter Indicator (e.g. 194.26.29.112, evil-c2-tunnel.ru, or SHA256)..."
                    value={lookupQuery}
                    onChange={(e) => setLookupQuery(e.target.value)}
                    className="w-full bg-[#070a10] border border-slate-800 rounded-xl px-4 py-2.5 text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none text-xs font-mono"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isLookingUp}
                  className="px-6 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-bold disabled:opacity-50 transition-all flex items-center justify-center gap-2 shadow-[0_0_12px_rgba(6,182,212,0.3)]"
                >
                  {isLookingUp ? (
                    <>
                      <Spinner size="sm" /> Querying Feeds...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4" /> Query Reputation
                    </>
                  )}
                </button>
              </div>

              {/* Quick sample chips */}
              <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-slate-400">
                <span className="text-slate-500">Quick Test IOCs:</span>
                {[
                  { label: 'C2 IP (194.26.29.112)', val: '194.26.29.112' },
                  { label: 'C2 Domain (evil-c2-tunnel.ru)', val: 'evil-c2-tunnel.ru' },
                  { label: 'Mimikatz SHA256', val: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' },
                  { label: 'Phishing Domain', val: 'auth-secure-verify.com' }
                ].map((chip, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      setLookupQuery(chip.val);
                      setLookupType('auto');
                    }}
                    className="px-2 py-0.5 rounded bg-[#131929] hover:bg-[#1a233a] text-cyan-300 border border-slate-800/80 transition-colors"
                  >
                    {chip.label}
                  </button>
                ))}
              </div>
            </form>

            {/* Rich Lookup Result Card */}
            {lookupResult && (
              <div className="mt-4 p-5 bg-[#070a10] rounded-xl border border-slate-800 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
                  <div className="flex items-center gap-3">
                    <span className="text-slate-400 uppercase font-bold text-[11px]">Indicator:</span>
                    <code className="text-sm font-bold text-cyan-300 bg-[#0e1320] px-2.5 py-1 rounded border border-slate-800 select-all">
                      {lookupResult.indicator || lookupResult.query?.value}
                    </code>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] uppercase font-bold">
                      Type: {lookupResult.type || 'Unknown'}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 text-[11px]">Verdict:</span>
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-bold uppercase border flex items-center gap-1.5 ${
                        lookupResult.verdict === 'malicious'
                          ? 'bg-rose-950/80 text-rose-300 border-rose-700/80 shadow-[0_0_10px_rgba(244,63,94,0.3)]'
                          : lookupResult.verdict === 'suspicious'
                          ? 'bg-amber-950/80 text-amber-300 border-amber-700/80 shadow-[0_0_10px_rgba(245,158,11,0.3)]'
                          : lookupResult.verdict === 'benign' || lookupResult.verdict === 'good'
                          ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/80 shadow-[0_0_10px_rgba(16,185,129,0.3)]'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}
                    >
                      {lookupResult.verdict === 'malicious' ? (
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                      ) : lookupResult.verdict === 'suspicious' ? (
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      ) : lookupResult.verdict === 'benign' ? (
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Info className="w-3.5 h-3.5 text-slate-400" />
                      )}
                      {lookupResult.verdict}
                    </span>
                  </div>
                </div>

                {/* Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 bg-[#0d121f] rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Confidence Score</span>
                    <div className="flex items-center gap-2">
                      <span className="text-base font-bold text-slate-100">{lookupResult.confidence || 0}%</span>
                      <div className="flex-1 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${
                            (lookupResult.confidence || 0) > 75
                              ? 'bg-rose-500'
                              : (lookupResult.confidence || 0) > 40
                              ? 'bg-amber-500'
                              : 'bg-emerald-500'
                          }`}
                          style={{ width: `${lookupResult.confidence || 0}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="p-3 bg-[#0d121f] rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Threat Intel Source</span>
                    <span className="text-xs font-bold text-slate-200">
                      {lookupResult.source || lookupResult.threatIntel?.source || 'No Feed Records'}
                    </span>
                  </div>

                  <div className="p-3 bg-[#0d121f] rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Occurrences</span>
                    <span className="text-xs font-bold text-slate-200">{lookupResult.occurrences || 0} Telemetry Hits</span>
                  </div>

                  <div className="p-3 bg-[#0d121f] rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Last Observed</span>
                    <span className="text-xs font-bold text-slate-200">
                      {lookupResult.lastSeen ? new Date(lookupResult.lastSeen).toLocaleDateString() : 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Threat Tags */}
                {lookupResult.tags && lookupResult.tags.length > 0 && (
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1.5">Adversary Threat Tags:</span>
                    <div className="flex flex-wrap gap-1.5">
                      {lookupResult.tags.map((t, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/60 text-rose-300 text-[10px]">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Correlated Incidents & Alerts */}
                {((lookupResult.associatedAlerts && lookupResult.associatedAlerts.length > 0) ||
                  (lookupResult.relatedCases && lookupResult.relatedCases.length > 0)) && (
                  <div className="pt-2 border-t border-slate-800/80 space-y-2">
                    <span className="text-[10px] text-slate-400 uppercase font-bold block">Correlated Alerts & Cases:</span>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {lookupResult.associatedAlerts?.map((alt, i) => (
                        <div key={i} className="p-2.5 rounded bg-[#0b0f19] border border-slate-800 flex items-center justify-between text-[11px]">
                          <div>
                            <span className="text-rose-400 font-bold mr-1.5">{alt.alertId}</span>
                            <span className="text-slate-300">{alt.title}</span>
                          </div>
                          <StatusBadge status={alt.severity} />
                        </div>
                      ))}
                      {lookupResult.relatedCases?.map((cs, i) => (
                        <div key={i} className="p-2.5 rounded bg-[#0b0f19] border border-slate-800 flex items-center justify-between text-[11px]">
                          <div>
                            <span className="text-cyan-400 font-bold mr-1.5">{cs.caseId}</span>
                            <span className="text-slate-300">{cs.title}</span>
                          </div>
                          <StatusBadge status={cs.status} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Database Schema Explorer Modal */}
      {showSchemaModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-[#0b0f19] border border-slate-700 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden font-mono text-xs">
            <div className="p-4 bg-[#0e1424] border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-cyan-400" />
                <div>
                  <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
                    SOC Telemetry Database Schema Explorer
                  </h3>
                  <span className="text-[11px] text-slate-400">
                    Live verified collections, columns, data types, and supported operations
                  </span>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setShowSchemaModal(false)}
                className="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
              >
                Close ✕
              </button>
            </div>

            <div className="p-4 flex-1 overflow-y-auto space-y-4">
              {/* Table Tabs */}
              {schemaMetadata?.tables && (
                <div>
                  <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
                    {Object.keys(schemaMetadata.tables).map((tblKey) => (
                      <button
                        key={tblKey}
                        type="button"
                        onClick={() => setSelectedSchemaTable(tblKey)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                          selectedSchemaTable === tblKey
                            ? 'bg-cyan-500 text-black shadow-[0_0_10px_rgba(6,182,212,0.4)]'
                            : 'bg-[#0e1322] text-slate-400 hover:text-slate-200 border border-slate-800'
                        }`}
                      >
                        {tblKey}
                      </button>
                    ))}
                  </div>

                  {/* Active Table Details */}
                  {schemaMetadata.tables[selectedSchemaTable] && (
                    <div className="mt-4 space-y-3">
                      <div className="p-3 bg-[#070a12] border border-slate-800 rounded-xl">
                        <div className="flex items-center justify-between text-xs mb-1">
                          <span className="font-bold text-cyan-300 uppercase">
                            Collection: {schemaMetadata.tables[selectedSchemaTable].tableName}
                          </span>
                          <span className="text-slate-500">
                            Primary Key: {schemaMetadata.tables[selectedSchemaTable].primaryKey}
                          </span>
                        </div>
                        <p className="text-slate-400 text-xs">
                          {schemaMetadata.tables[selectedSchemaTable].description}
                        </p>
                      </div>

                      <div className="border border-slate-800 rounded-xl overflow-hidden bg-[#070a10]">
                        <table className="w-full text-left text-xs text-slate-300">
                          <thead className="bg-[#0e1322] border-b border-slate-800 uppercase tracking-wider text-slate-400 text-[10px]">
                            <tr>
                              <th className="px-4 py-2.5 font-bold">Column Name</th>
                              <th className="px-4 py-2.5 font-bold">Data Type</th>
                              <th className="px-4 py-2.5 font-bold">Role</th>
                              <th className="px-4 py-2.5 font-bold">Description</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60">
                            {schemaMetadata.tables[selectedSchemaTable].fields.map((f, idx) => (
                              <tr key={idx} className="hover:bg-[#12192b] transition-colors">
                                <td className="px-4 py-2.5 font-bold text-cyan-400 select-all">{f.name}</td>
                                <td className="px-4 py-2.5 text-slate-400 font-mono">{f.type}</td>
                                <td className="px-4 py-2.5">
                                  {f.role ? (
                                    <span className="px-2 py-0.5 rounded bg-purple-950/70 border border-purple-800/70 text-purple-300 text-[10px] uppercase font-bold">
                                      {f.role}
                                    </span>
                                  ) : (
                                    <span className="text-slate-600">—</span>
                                  )}
                                </td>
                                <td className="px-4 py-2.5 text-slate-300">{f.description}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Supported SQL Operations Callout */}
              <div className="p-3 bg-[#0a0f1d] border border-slate-800 rounded-xl space-y-1.5">
                <span className="text-[11px] font-bold uppercase text-slate-300 block">
                  Supported Query Engine Capabilities:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-[11px] text-slate-400">
                  <span>✓ SELECT & DISTINCT Projections</span>
                  <span>✓ WHERE with AND, OR, IN, LIKE wildcards</span>
                  <span>✓ GROUP BY with COUNT, AVG, SUM, MIN, MAX</span>
                  <span>✓ HAVING aggregation filter conditions</span>
                  <span>✓ ORDER BY (ASC / DESC) sorting</span>
                  <span>✓ LIMIT pagination (up to 500 rows)</span>
                  <span>✓ ISO & Date literals (YYYY-MM-DD)</span>
                  <span>✓ Strict server-side read-only enforcement</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Global Threat Indicators Table */}
      <div className="bg-[#0f1422] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              Enterprise Indicator Registry
            </h3>
            <span className="text-[11px] text-slate-500 font-mono">
              Live normalized indicators extracted from endpoint & network telemetry
            </span>
          </div>

          <div className="relative w-72">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Filter threat indicators..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-[#070a10] border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono text-slate-300">
            <thead className="bg-[#0b0f19] border-b border-slate-800 uppercase tracking-wider text-slate-400 text-[11px]">
              <tr>
                <th className="px-4 py-3 font-semibold">Type</th>
                <th className="px-4 py-3 font-semibold">Indicator Value</th>
                <th className="px-4 py-3 font-semibold">Reputation</th>
                <th className="px-4 py-3 font-semibold">Confidence</th>
                <th className="px-4 py-3 font-semibold">Occurrences</th>
                <th className="px-4 py-3 font-semibold">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center">
                    <Spinner size="md" />
                  </td>
                </tr>
              ) : iocs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No threat indicators found.
                  </td>
                </tr>
              ) : (
                iocs.map((ioc) => (
                  <tr key={ioc._id} className="hover:bg-[#141b2d] transition-colors">
                    <td className="px-4 py-3 uppercase font-bold text-cyan-400">{ioc.type}</td>
                    <td className="px-4 py-3 font-semibold text-slate-200 select-all">{ioc.value}</td>
                    <td className="px-4 py-3">
                      <StatusBadge status={ioc.reputation} />
                    </td>
                    <td className="px-4 py-3 font-bold text-slate-200">{ioc.confidence}%</td>
                    <td className="px-4 py-3 text-slate-400">{ioc.count} hits</td>
                    <td className="px-4 py-3 text-slate-500 capitalize">{ioc.source}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
