import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { FileCode, Filter, RefreshCw, X, Clock, Calendar, RotateCcw, CalendarDays, UploadCloud } from 'lucide-react';
import EventTable from '../components/EventTable';
import { eventsApi } from '../services/api';

const TIME_PRESETS = [
  { id: 'all', label: 'All Time' },
  { id: '15m', label: 'Last 15m' },
  { id: '1h', label: 'Last 1h' },
  { id: '6h', label: 'Last 6h' },
  { id: '24h', label: 'Last 24h' },
  { id: '7d', label: 'Last 7d' },
  { id: '30d', label: 'Last 30d' },
  { id: 'custom', label: 'Custom Range' }
];

const formatForInput = (d) => {
  if (!d) return '';
  const date = new Date(d);
  if (isNaN(date.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
};

export default function Events() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialRawFile = searchParams.get('rawFile') || '';

  const [source, setSource] = useState('');
  const [eventType, setEventType] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [host, setHost] = useState('');
  const [username, setUsername] = useState('');
  const [sourceIP, setSourceIP] = useState('');
  const [rawFile, setRawFile] = useState(initialRawFile);
  const [timePreset, setTimePreset] = useState('all');
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');
  const [page, setPage] = useState(1);

  // Sync if URL query param changes
  useEffect(() => {
    const f = searchParams.get('rawFile');
    if (f !== null && f !== rawFile) {
      setRawFile(f);
    }
  }, [searchParams]);

  // Compute time bounds for query
  const getTimeBounds = () => {
    if (timePreset === 'custom') {
      const from = customStart && !isNaN(new Date(customStart).getTime()) ? new Date(customStart).toISOString() : undefined;
      const to = customEnd && !isNaN(new Date(customEnd).getTime()) ? new Date(customEnd).toISOString() : undefined;
      return { dateFrom: from, dateTo: to };
    }
    if (timePreset === 'all') {
      return { dateFrom: undefined, dateTo: undefined };
    }
    const now = new Date();
    const minutesMap = {
      '15m': 15,
      '1h': 60,
      '6h': 360,
      '24h': 1440,
      '7d': 7 * 1440,
      '30d': 30 * 1440
    };
    const mins = minutesMap[timePreset];
    if (mins) {
      return {
        dateFrom: new Date(now.getTime() - mins * 60 * 1000).toISOString(),
        dateTo: undefined
      };
    }
    return { dateFrom: undefined, dateTo: undefined };
  };

  const { dateFrom, dateTo } = getTimeBounds();

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['eventsExplorer', { source, eventType, severity, status, host, username, sourceIP, rawFile, timePreset, customStart, customEnd, page }],
    queryFn: async () => {
      const bounds = getTimeBounds();
      const res = await eventsApi.getEvents({
        source: source || undefined,
        eventType: eventType || undefined,
        severity: severity || undefined,
        status: status || undefined,
        host: host || undefined,
        username: username || undefined,
        sourceIP: sourceIP || undefined,
        rawFile: rawFile || undefined,
        dateFrom: bounds.dateFrom,
        dateTo: bounds.dateTo,
        page,
        limit: 250
      });
      return res.data;
    }
  });

  const clearFilters = () => {
    setSource('');
    setEventType('');
    setSeverity('');
    setStatus('');
    setHost('');
    setUsername('');
    setSourceIP('');
    setRawFile('');
    setTimePreset('all');
    setCustomStart('');
    setCustomEnd('');
    setSearchParams({});
    setPage(1);
  };

  const handlePresetSelect = (id) => {
    setTimePreset(id);
    if (id === 'custom' && !customStart && !customEnd) {
      const now = new Date();
      const past24h = new Date(now.getTime() - 24 * 3600 * 1000);
      setCustomStart(formatForInput(past24h));
      setCustomEnd(formatForInput(now));
    }
    setPage(1);
  };

  const applyCustomQuickRange = (hoursAgo) => {
    const now = new Date();
    const start = new Date(now.getTime() - hoursAgo * 3600 * 1000);
    setCustomStart(formatForInput(start));
    setCustomEnd(formatForInput(now));
    setTimePreset('custom');
    setPage(1);
  };

  const applyTodayRange = () => {
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0);
    setCustomStart(formatForInput(start));
    setCustomEnd(formatForInput(now));
    setTimePreset('custom');
    setPage(1);
  };

  const hasFilters = Boolean(
    source || eventType || severity || status || host || username || sourceIP || rawFile ||
    timePreset !== 'all' || customStart || customEnd
  );

  const getActiveTimeRangeText = () => {
    if (timePreset === 'all') return 'Full historic retention (unbounded)';
    if (timePreset === '15m') return 'Past 15 minutes';
    if (timePreset === '1h') return 'Past 1 hour';
    if (timePreset === '6h') return 'Past 6 hours';
    if (timePreset === '24h') return 'Past 24 hours';
    if (timePreset === '7d') return 'Past 7 days';
    if (timePreset === '30d') return 'Past 30 days';
    if (timePreset === 'custom') {
      if (customStart && customEnd) return `${customStart.replace('T', ' ')} → ${customEnd.replace('T', ' ')}`;
      if (customStart) return `From ${customStart.replace('T', ' ')} onward`;
      if (customEnd) return `Up to ${customEnd.replace('T', ' ')}`;
      return 'Custom range (unspecified)';
    }
    return '';
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="p-4 bg-[#0f1422] border border-slate-800 rounded-2xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wide">
              Common Event Model (CEM) Telemetry Explorer
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Normalized enterprise event stream with field filtering, MITRE technique tagging, and raw payload inspect.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => navigate('/logs')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-300 font-mono text-xs transition-colors"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            Upload & Archive Logs
          </button>

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh Stream
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 bg-[#0b0f19] border border-slate-800 rounded-xl space-y-4 font-mono text-xs">
        {/* Top Header of Filters */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-slate-400 font-bold uppercase tracking-wider">
            <Filter className="w-4 h-4 text-cyan-400" /> Advanced Telemetry Filters
          </div>

          <div className="flex items-center gap-3">
            {data?.pagination && (
              <span className="px-2 py-0.5 rounded-md bg-cyan-950/60 border border-cyan-800/80 text-cyan-400 text-[11px] font-bold">
                {data.pagination.total} {data.pagination.total === 1 ? 'event' : 'events'} matched
              </span>
            )}

            {hasFilters && (
              <button
                onClick={clearFilters}
                className="text-xs text-rose-400 hover:text-rose-300 flex items-center gap-1 transition-colors"
              >
                <X className="w-3.5 h-3.5" /> Clear Filters
              </button>
            )}
          </div>
        </div>

        {/* Time Range Filter Section */}
        <div className="p-3 bg-[#070a10]/80 border border-slate-800/90 rounded-lg space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-slate-300">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-[11px] uppercase tracking-wide font-semibold text-slate-300">
                Time Range Filter
              </span>
              <span className="text-[10px] text-slate-500">|</span>
              <span className="text-[11px] text-cyan-400/90">
                {getActiveTimeRangeText()}
              </span>
            </div>

            {timePreset !== 'all' && (
              <button
                onClick={() => handlePresetSelect('all')}
                className="text-[10px] text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors"
              >
                <RotateCcw className="w-3 h-3" /> Reset Time Range
              </button>
            )}
          </div>

          {/* Preset Buttons */}
          <div className="flex flex-wrap items-center gap-1.5">
            {TIME_PRESETS.map((p) => {
              const isActive = timePreset === p.id;
              return (
                <button
                  key={p.id}
                  onClick={() => handlePresetSelect(p.id)}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all flex items-center gap-1 border ${
                    isActive
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/60 shadow-sm shadow-cyan-500/20 font-bold'
                      : 'bg-[#0b0f19] text-slate-400 border-slate-800 hover:border-slate-700 hover:text-slate-200'
                  }`}
                >
                  {p.id === 'custom' && <Calendar className="w-3 h-3" />}
                  {p.label}
                </button>
              );
            })}
          </div>

          {/* Custom Date Range Picker Accordion/Panel */}
          {timePreset === 'custom' && (
            <div className="pt-2 border-t border-slate-800/60 flex flex-wrap items-end gap-3 bg-[#0a0e17] p-2.5 rounded-md border border-slate-800/80">
              <div className="flex-1 min-w-[200px]">
                <label className="block text-[10px] uppercase text-slate-400 mb-1 flex items-center gap-1">
                  <CalendarDays className="w-3 h-3 text-cyan-400" /> Start Time (From)
                </label>
                <input
                  type="datetime-local"
                  value={customStart}
                  onChange={(e) => {
                    setCustomStart(e.target.value);
                    setPage(1);
                  }}
                  className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-200 focus:border-cyan-500 focus:outline-none text-xs [color-scheme:dark]"
                />
              </div>

              <div className="flex-1 min-w-[200px]">
                <label className="block text-[10px] uppercase text-slate-400 mb-1 flex items-center gap-1">
                  <CalendarDays className="w-3 h-3 text-cyan-400" /> End Time (To)
                </label>
                <input
                  type="datetime-local"
                  value={customEnd}
                  onChange={(e) => {
                    setCustomEnd(e.target.value);
                    setPage(1);
                  }}
                  className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-200 focus:border-cyan-500 focus:outline-none text-xs [color-scheme:dark]"
                />
              </div>

              {/* Quick shortcuts for custom range */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <button
                  type="button"
                  onClick={() => setCustomEnd(formatForInput(new Date()))}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-colors"
                  title="Set end timestamp to current local time"
                >
                  Set End to Now
                </button>
                <button
                  type="button"
                  onClick={() => applyCustomQuickRange(2)}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-colors"
                >
                  Past 2h
                </button>
                <button
                  type="button"
                  onClick={() => applyCustomQuickRange(12)}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-colors"
                >
                  Past 12h
                </button>
                <button
                  type="button"
                  onClick={applyTodayRange}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-colors"
                >
                  Today
                </button>
                {(customStart || customEnd) && (
                  <button
                    type="button"
                    onClick={() => { setCustomStart(''); setCustomEnd(''); }}
                    className="px-2 py-1 rounded bg-rose-950/60 border border-rose-800/60 hover:bg-rose-900/60 text-rose-300 text-[10px] transition-colors"
                  >
                    Clear Inputs
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Field Filters Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 lg:grid-cols-9 gap-2.5 pt-1">
          {/* Time Range Dropdown selector in grid */}
          <div>
            <label className="block text-[10px] uppercase text-slate-500 mb-1 flex items-center gap-1">
              <Clock className="w-2.5 h-2.5 text-cyan-400" /> Time Range
            </label>
            <select
              value={timePreset}
              onChange={(e) => handlePresetSelect(e.target.value)}
              className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="all">All Time</option>
              <option value="15m">Last 15 Minutes</option>
              <option value="1h">Last 1 Hour</option>
              <option value="6h">Last 6 Hours</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="custom">Custom Range...</option>
            </select>
          </div>

          {/* Source filter */}
          <div>
            <label className="block text-[10px] uppercase text-slate-500 mb-1">Source</label>
            <select
              value={source}
              onChange={(e) => { setSource(e.target.value); setPage(1); }}
              className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="">All Sources</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="edr">EDR</option>
              <option value="network">Network</option>
              <option value="dns">DNS</option>
              <option value="firewall">Firewall</option>
              <option value="application">Application</option>
            </select>
          </div>

          {/* EventType filter */}
          <div>
            <label className="block text-[10px] uppercase text-slate-500 mb-1">Type</label>
            <select
              value={eventType}
              onChange={(e) => { setEventType(e.target.value); setPage(1); }}
              className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="">All Types</option>
              <option value="authentication">Authentication</option>
              <option value="process">Process</option>
              <option value="file">File</option>
              <option value="network">Network</option>
              <option value="dns">DNS</option>
              <option value="registry">Registry</option>
              <option value="other">Other</option>
            </select>
          </div>

          {/* Severity filter */}
          <div>
            <label className="block text-[10px] uppercase text-slate-500 mb-1">Severity</label>
            <select
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
              className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Status filter */}
          <div>
            <label className="block text-[10px] uppercase text-slate-500 mb-1">Status</label>
            <select
              value={status}
              onChange={(e) => { setStatus(e.target.value); setPage(1); }}
              className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="">All Statuses</option>
              <option value="success">Success</option>
              <option value="failed">Failed</option>
              <option value="in_allowed_list">In Allowed List</option>
            </select>
          </div>

          {/* Host input */}
          <div>
            <label className="block text-[10px] uppercase text-slate-500 mb-1">Host</label>
            <input
              type="text"
              placeholder="e.g. DC01"
              value={host}
              onChange={(e) => { setHost(e.target.value); setPage(1); }}
              className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          {/* Username input */}
          <div>
            <label className="block text-[10px] uppercase text-slate-500 mb-1">User</label>
            <input
              type="text"
              placeholder="e.g. jsmith"
              value={username}
              onChange={(e) => { setUsername(e.target.value); setPage(1); }}
              className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          {/* Source IP input */}
          <div>
            <label className="block text-[10px] uppercase text-slate-500 mb-1">Source IP</label>
            <input
              type="text"
              placeholder="e.g. 194.26"
              value={sourceIP}
              onChange={(e) => { setSourceIP(e.target.value); setPage(1); }}
              className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          {/* Source Log File input */}
          <div>
            <label className="block text-[10px] uppercase text-slate-500 mb-1">Source File</label>
            <input
              type="text"
              placeholder="e.g. intrusion.csv"
              value={rawFile}
              onChange={(e) => { setRawFile(e.target.value); setPage(1); }}
              className="w-full bg-[#070a10] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* Events Table */}
      <EventTable events={data?.events || []} isLoading={isLoading} />
    </div>
  );
}

