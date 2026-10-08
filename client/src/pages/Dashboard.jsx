import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertTriangle,
  FolderLock,
  Server,
  Users,
  Crosshair,
  ArrowRight,
  TrendingUp,
  Radio,
  FileText,
  UploadCloud,
  RotateCcw,
  CheckCircle2,
  Trash2,
  HardDrive,
  FileCheck,
  Filter
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar
} from 'recharts';

import { dashboardApi, logsApi } from '../services/api';
import StatCard from '../components/StatCard';
import ChartCard from '../components/ChartCard';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import Spinner from '../components/Spinner';
import Modal from '../components/Modal';
import LogUploader from '../components/LogUploader';

export default function Dashboard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [selectedFile, setSelectedFile] = useState(() => {
    return localStorage.getItem('aegis_active_log_file') || '';
  });
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showResetModal, setShowResetModal] = useState(false);
  const [isResetting, setIsResetting] = useState(false);

  // Fetch list of all uploaded log files
  const { data: uploadedFiles = [], refetch: refetchFiles } = useQuery({
    queryKey: ['uploadedFiles'],
    queryFn: async () => {
      const res = await logsApi.getFiles();
      return res.data;
    }
  });

  // Automatically select the first file or keep selectedFile synced
  useEffect(() => {
    if (uploadedFiles.length > 0) {
      if (!selectedFile || !uploadedFiles.some(f => f.fileName === selectedFile)) {
        const first = uploadedFiles[0].fileName;
        setSelectedFile(first);
        localStorage.setItem('aegis_active_log_file', first);
      }
    } else {
      if (selectedFile) {
        setSelectedFile('');
        localStorage.removeItem('aegis_active_log_file');
      }
    }
  }, [uploadedFiles, selectedFile]);

  // Query dashboard summary strictly for selectedFile
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['dashboardSummary', selectedFile],
    queryFn: async () => {
      const res = await dashboardApi.getSummary(selectedFile ? { rawFile: selectedFile } : {});
      return res.data;
    },
    refetchInterval: 15000
  });

  const totals = data?.totals || {
    events: 0,
    alerts: 0,
    activeAlerts: 0,
    criticalAlerts: 0,
    openCases: 0,
    endpoints: 0,
    compromisedEndpoints: 0,
    accounts: 0,
    compromisedAccounts: 0,
    iocs: 0,
    maliciousIOCs: 0
  };

  const alertsBySeverity = data?.alertsBySeverity || [];
  const eventsBySource = data?.eventsBySource || [];
  const eventsOverTime = data?.eventsOverTime || [];
  const topSourceIPs = data?.topSourceIPs || [];
  const topTargetedAccounts = data?.topTargetedAccounts || [];
  const topAffectedEndpoints = data?.topAffectedEndpoints || [];
  const recentAlerts = data?.recentAlerts || [];
  const isEmpty = Boolean(data?.isEmpty || totals.events === 0 || !data?.activeFile);

  const handleFileChange = (fileName) => {
    setSelectedFile(fileName);
    if (fileName) {
      localStorage.setItem('aegis_active_log_file', fileName);
    } else {
      localStorage.removeItem('aegis_active_log_file');
    }
  };

  const handleUploadSuccess = (summary) => {
    setShowUploadModal(false);
    queryClient.invalidateQueries({ queryKey: ['uploadedFiles'] });
    queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
    queryClient.invalidateQueries({ queryKey: ['recentLogsEvents'] });
    queryClient.invalidateQueries({ queryKey: ['activeAlertsCount'] });
    if (summary?.fileName) {
      setSelectedFile(summary.fileName);
      localStorage.setItem('aegis_active_log_file', summary.fileName);
    }
    refetchFiles();
    refetch();
  };

  const handleResetAll = async () => {
    setIsResetting(true);
    try {
      await logsApi.resetAll();
      setSelectedFile('');
      localStorage.removeItem('aegis_active_log_file');
      queryClient.invalidateQueries({ queryKey: ['uploadedFiles'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
      queryClient.invalidateQueries({ queryKey: ['recentLogsEvents'] });
      queryClient.invalidateQueries({ queryKey: ['activeAlertsCount'] });
      await refetchFiles();
      await refetch();
      setShowResetModal(false);
    } catch (err) {
      alert('Failed to reset telemetry: ' + (err.response?.data?.message || err.message));
    } finally {
      setIsResetting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh]">
        <Spinner size="lg" />
        <p className="mt-3 text-xs font-mono text-slate-400 animate-pulse">
          Synthesizing Security Intelligence Telemetry...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Active File Telemetry Selector & Control Bar */}
      <div className="bg-[#0f1422] border border-slate-800 rounded-2xl p-4 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <HardDrive className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">
                Inspected Log File Telemetry
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-semibold">
                Single-File Inspector
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2 mt-1">
              <select
                id="dashboard-file-select"
                value={selectedFile || data?.activeFile || ''}
                onChange={(e) => handleFileChange(e.target.value)}
                className="bg-[#0b0f19] border border-cyan-500/40 text-cyan-300 font-mono text-xs rounded-xl px-3 py-1.5 focus:ring-1 focus:ring-cyan-400 outline-none cursor-pointer max-w-[280px] sm:max-w-md truncate"
              >
                {uploadedFiles.length === 0 ? (
                  <option value="">No Log Files Uploaded (System Reset/Empty)</option>
                ) : (
                  uploadedFiles.map((f) => (
                    <option key={f._id} value={f.fileName}>
                      📄 {f.fileName} — {f.eventsCount?.toLocaleString()} logs
                    </option>
                  ))
                )}
              </select>

              {data?.activeFile && totals.events > 0 && (
                <span className="hidden lg:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-950/60 border border-cyan-800/80 text-cyan-300 font-mono text-xs">
                  <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                  Showing: <strong className="text-white">{data.activeFile}</strong> ({totals.events.toLocaleString()} events)
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowUploadModal(true)}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all"
            title="Upload a new log file to inspect its logs and alerts"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload Log File</span>
          </button>

          <button
            onClick={() => setShowResetModal(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-rose-950/30 hover:bg-rose-900/40 text-rose-400 border border-rose-800/50 font-mono text-xs transition-all"
            title="Reset alerts and all telemetry back to 0"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Reset All</span>
          </button>
        </div>
      </div>

      {/* Top Threat Posture Ticker */}
      {isEmpty ? (
        <div className="p-4 bg-gradient-to-r from-emerald-950/40 via-[#0f1422] to-[#0f1422] border border-emerald-900/50 rounded-2xl flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/20 text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.3)]">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-black uppercase tracking-wider text-emerald-400">
                  SYSTEM IDLE // ALL TELEMETRY RESET
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold">
                  0 INCIDENTS
                </span>
              </div>
              <p className="text-sm font-mono text-slate-300 mt-0.5">
                {selectedFile
                  ? `Selected file "${selectedFile}" contains 0 logs. All alerts and telemetry are fully reset.`
                  : 'No log file loaded. Upload a log file to view its events, evaluate detection rules, and populate dashboard telemetry.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowUploadModal(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold shadow-[0_0_12px_rgba(6,182,212,0.4)] transition-all"
            >
              <UploadCloud className="w-4 h-4" /> Upload Log File
            </button>
          </div>
        </div>
      ) : totals.criticalAlerts > 0 || totals.alerts > 0 ? (
        <div className="p-4 bg-gradient-to-r from-rose-950/40 via-[#0f1422] to-[#0f1422] border border-rose-900/50 rounded-2xl flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 animate-pulse shadow-[0_0_12px_rgba(244,63,94,0.3)]">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-black uppercase tracking-wider text-rose-400">
                  ACTIVE THREAT INCIDENT // {data.activeFile}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700 font-bold">
                  {totals.criticalAlerts > 0 ? 'CRITICAL RISK' : 'ELEVATED RISK'}
                </span>
              </div>
              <p className="text-sm font-mono text-slate-200 mt-0.5">
                Intrusion telemetry active for file <strong className="text-cyan-400">{data.activeFile}</strong>: {totals.alerts} alert(s) across {totals.compromisedEndpoints || 0} endpoint(s) and {totals.compromisedAccounts || 0} identity/identities.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/cases')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-bold shadow-[0_0_12px_rgba(244,63,94,0.4)] transition-all"
            >
              Investigate Cases <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      ) : (
        <div className="p-4 bg-gradient-to-r from-emerald-950/40 via-[#0f1422] to-[#0f1422] border border-emerald-900/50 rounded-2xl flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/20 text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.3)]">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-black uppercase tracking-wider text-emerald-400">
                  TELEMETRY NORMAL // {data.activeFile}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold">
                  ALL CLEAR
                </span>
              </div>
              <p className="text-sm font-mono text-slate-200 mt-0.5">
                File <strong className="text-cyan-400">{data.activeFile}</strong> analyzed with {totals.events.toLocaleString()} events. 0 security rule violations detected.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/events')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold shadow-[0_0_12px_rgba(16,185,129,0.4)] transition-all"
            >
              Explore Events <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Row 1: KPI StatCards - Strictly showing the selected file's logs and metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Events"
          value={isEmpty ? '0' : totals.events?.toLocaleString()}
          subtitle={data?.activeFile ? `In ${data.activeFile}` : 'No file selected'}
          icon={Activity}
          color="cyan"
          trend={isEmpty ? '0 events' : `Selected file only`}
        />
        <StatCard
          title="Critical Alerts"
          value={isEmpty ? '0' : totals.criticalAlerts}
          subtitle={isEmpty ? '0 active in triage' : `${totals.alerts || 0} total in file (${totals.activeAlerts || 0} active)`}
          icon={AlertTriangle}
          color="rose"
          trend={isEmpty ? '0 new' : `${totals.criticalAlerts} critical`}
        />
        <StatCard
          title="Active Cases"
          value={isEmpty ? '0' : totals.openCases}
          subtitle={isEmpty ? 'All clear' : 'Forensic investigations'}
          icon={FolderLock}
          color="amber"
          trend={isEmpty ? 'Idle' : 'Active'}
        />
        <StatCard
          title="Compromised Assets"
          value={isEmpty ? '0 / 0' : `${totals.compromisedEndpoints || 0} / ${totals.endpoints || 0}`}
          subtitle={isEmpty ? 'Clean perimeter' : `${totals.compromisedAccounts || 0} compromised identities`}
          icon={Server}
          color="purple"
          trend={isEmpty ? 'Normal' : 'Profiled'}
        />
      </div>

      {/* Row 2: Charts (Events over time AreaChart + Alerts by Severity PieChart) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Events Timeline Area Chart (2 cols) */}
        <div className="lg:col-span-2">
          <ChartCard
            title={`Telemetry Volume (24h) — ${data?.activeFile || 'No File Selected'}`}
            subtitle={isEmpty ? 'No telemetry events recorded for active file' : 'Ingested events bucketized chronologically'}
            icon={TrendingUp}
          >
            <div className="h-72 w-full flex items-center justify-center">
              {isEmpty || eventsOverTime.length === 0 ? (
                <div className="text-center py-10">
                  <Activity className="w-10 h-10 text-slate-600 mx-auto mb-2 opacity-50" />
                  <p className="text-xs font-mono text-slate-500">No telemetry events recorded for active file.</p>
                  <button
                    onClick={() => setShowUploadModal(true)}
                    className="mt-3 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-mono transition-all"
                  >
                    Upload Log File to View Timeline
                  </button>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={eventsOverTime} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                        <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0}/>
                      </linearGradient>
                      <linearGradient id="securityGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.5}/>
                        <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1f293d" vertical={false} />
                    <XAxis dataKey="time" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                    <YAxis stroke="#64748b" fontSize={11} fontFamily="monospace" />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f1422', borderColor: '#1f293d', borderRadius: '8px', fontFamily: 'monospace', fontSize: '12px' }}
                      labelStyle={{ color: '#06b6d4', fontWeight: 'bold' }}
                    />
                    <Area type="monotone" dataKey="events" name="File Events" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#eventGradient)" />
                    <Area type="monotone" dataKey="security" name="Security Incidents" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#securityGradient)" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </ChartCard>
        </div>

        {/* Severity Distribution Pie Chart (1 col) */}
        <div>
          <ChartCard
            title="Alerts by Severity"
            subtitle={isEmpty || totals.alerts === 0 ? 'No alerts in active file' : 'Triage classification breakdown'}
            icon={Radio}
          >
            <div className="h-72 w-full flex items-center justify-center">
              {isEmpty || totals.alerts === 0 ? (
                <div className="text-center py-10">
                  <ShieldCheck className="w-10 h-10 text-emerald-500/50 mx-auto mb-2" />
                  <p className="text-xs font-mono text-slate-400">0 Alerts in selected file</p>
                  <p className="text-[11px] font-mono text-slate-500 mt-1">Detection pipeline clear</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={alertsBySeverity}
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={85}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {alertsBySeverity.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f1422', borderColor: '#1f293d', borderRadius: '8px', fontFamily: 'monospace', fontSize: '12px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="grid grid-cols-2 gap-2 mt-2 pt-2 border-t border-slate-800 text-xs font-mono">
              {alertsBySeverity.map((s) => (
                <div key={s.name} className="flex items-center justify-between px-2 py-1 rounded bg-[#0b0f19]">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: s.color }} />
                    <span className="text-slate-300">{s.name}</span>
                  </div>
                  <strong className="text-white">{isEmpty ? 0 : s.value}</strong>
                </div>
              ))}
            </div>
          </ChartCard>
        </div>
      </div>

      {/* Row 3: Threat Analytics Intelligence (Top Source IPs, Targeted Accounts, Affected Endpoints) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Top Source IPs */}
        <div className="bg-[#0f1422] border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              Top Adversary Source IPs
            </h4>
            <span className="text-[10px] font-mono text-cyan-400">File Feed</span>
          </div>

          <div className="space-y-2.5 font-mono text-xs">
            {isEmpty || topSourceIPs.length === 0 ? (
              <p className="text-slate-500 py-6 text-center">No external source IPs in active file</p>
            ) : (
              topSourceIPs.map((ipObj) => (
                <div key={ipObj.ip} className="p-2 rounded-lg bg-[#0b0f19] border border-slate-800/80 flex items-center justify-between">
                  <div>
                    <span className="font-bold text-rose-300 block">{ipObj.ip}</span>
                    <span className="text-[10px] text-slate-500">{ipObj.failedCount} failed auth attempts</span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px] font-bold">
                    {ipObj.count} hits
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Targeted Accounts */}
        <div className="bg-[#0f1422] border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              Targeted Account Identities
            </h4>
            <span className="text-[10px] font-mono text-amber-400">Identity Risk</span>
          </div>

          <div className="space-y-2.5 font-mono text-xs">
            {isEmpty || topTargetedAccounts.length === 0 ? (
              <p className="text-slate-500 py-6 text-center">No targeted accounts in active file</p>
            ) : (
              topTargetedAccounts.map((acc) => (
                <div key={acc.username} className="p-2 rounded-lg bg-[#0b0f19] border border-slate-800/80 flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-1.5">
                      <span className="font-bold text-slate-200">{acc.username}</span>
                      <span className="text-[10px] px-1 rounded bg-slate-800 text-slate-400">{acc.privilege}</span>
                    </div>
                    <span className="text-[10px] text-slate-500">{acc.failedLogins || 0} failed logins</span>
                  </div>
                  <div className="text-right">
                    <span className={`text-[11px] font-bold block ${acc.riskScore > 50 ? 'text-rose-400' : 'text-emerald-400'}`}>
                      Risk: {acc.riskScore}/100
                    </span>
                    <span className="text-[10px] capitalize text-slate-500">{acc.status}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Affected Endpoints */}
        <div className="bg-[#0f1422] border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              Host Asset Rankings
            </h4>
            <span className="text-[10px] font-mono text-purple-400">Endpoint Telemetry</span>
          </div>

          <div className="space-y-2.5 font-mono text-xs">
            {isEmpty || topAffectedEndpoints.length === 0 ? (
              <p className="text-slate-500 py-6 text-center">No affected host assets in active file</p>
            ) : (
              topAffectedEndpoints.map((ep) => (
                <div key={ep.hostname} className="p-2 rounded-lg bg-[#0b0f19] border border-slate-800/80 flex items-center justify-between">
                  <div>
                    <span className="font-bold text-slate-200 block">{ep.hostname}</span>
                    <span className="text-[10px] text-slate-500">{ep.os || 'Windows Host'}</span>
                  </div>
                  <div className="text-right">
                    <span className={`text-[11px] font-bold block ${ep.riskScore > 50 ? 'text-rose-400' : 'text-emerald-400'}`}>
                      Risk: {ep.riskScore}/100
                    </span>
                    <span className="text-[10px] capitalize text-slate-500">{ep.status}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Row 4: Recent Alerts Triage List */}
      <div className="bg-[#0f1422] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold font-mono tracking-wide text-slate-200 uppercase">
              Recent Alerts Feed ({data?.activeFile ? data.activeFile : 'No File'})
            </h3>
          </div>
          <button
            onClick={() => navigate('/alerts')}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            View All Alerts ({totals.alerts || 0}) <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="divide-y divide-slate-800/60 font-mono text-xs">
          {isEmpty || recentAlerts.length === 0 ? (
            <div className="py-10 text-center">
              <CheckCircle2 className="w-8 h-8 text-emerald-500/50 mx-auto mb-2" />
              <p className="text-slate-400">No alerts generated for this log file.</p>
              <p className="text-[11px] text-slate-500 mt-1">
                {selectedFile ? 'All detection rules evaluated clean with 0 incident anomalies.' : 'Upload a log file to trigger automated detection analysis.'}
              </p>
            </div>
          ) : (
            recentAlerts.map((alert) => (
              <div key={alert._id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-[#141b2d] px-2 rounded-lg transition-colors">
                <div className="flex items-start sm:items-center gap-3">
                  <SeverityBadge severity={alert.severity} />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-100">{alert.title}</span>
                      <span className="text-[11px] text-slate-500">[{alert.alertId}]</span>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] text-slate-400 mt-0.5">
                      {alert.host && <span>Host: <strong className="text-slate-300">{alert.host}</strong></span>}
                      {alert.sourceIP && <span>IP: <strong className="text-slate-300">{alert.sourceIP}</strong></span>}
                      {alert.mitreTechniqueId && <span className="text-purple-400">MITRE {alert.mitreTechniqueId}</span>}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 self-end sm:self-center">
                  <StatusBadge status={alert.status} />
                  <button
                    onClick={() => {
                      if (alert.caseId) navigate(`/cases/${alert.caseId._id || alert.caseId}`);
                      else navigate('/alerts');
                    }}
                    className="px-3 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 hover:text-cyan-300 text-slate-300 text-xs transition-colors flex items-center gap-1"
                  >
                    Investigate <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Reset Confirmation Modal */}
      <Modal
        isOpen={showResetModal}
        onClose={() => setShowResetModal(false)}
        title="Reset All Telemetry & Alerts"
        maxWidth="max-w-md"
      >
        <div className="space-y-4">
          <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs font-mono">
            <strong>Warning:</strong> This will purge all uploaded log files, normalized events, alerts, and cases. All dashboard metrics will reset completely to 0.
          </div>
          <p className="text-xs text-slate-300 font-mono">
            Are you sure you want to completely clear and reset the SOC telemetry dashboard?
          </p>
          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              onClick={() => setShowResetModal(false)}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleResetAll}
              disabled={isResetting}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-bold transition-all shadow-[0_0_12px_rgba(244,63,94,0.4)]"
            >
              {isResetting ? <Spinner size="sm" /> : <Trash2 className="w-4 h-4" />}
              <span>Yes, Reset Everything</span>
            </button>
          </div>
        </div>
      </Modal>

      {/* Upload Modal */}
      <Modal
        isOpen={showUploadModal}
        onClose={() => setShowUploadModal(false)}
        title="Upload & Ingest Security Log File"
        maxWidth="max-w-2xl"
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-400 font-mono">
            Select or drop a log file (.csv, .json, .log, .txt). The dashboard will immediately inspect only this file's logs and alert detections.
          </p>
          <LogUploader onUploadSuccess={handleUploadSuccess} />
        </div>
      </Modal>
    </div>
  );
}
