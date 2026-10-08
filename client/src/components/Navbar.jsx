import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Bell,
  LogOut,
  User,
  Shield,
  Search,
  Activity,
  ChevronDown,
  UploadCloud
} from 'lucide-react';
import { useAuthStore } from '../stores/authStore';
import { useUiStore } from '../stores/uiStore';
import { useQuery } from '@tanstack/react-query';
import { alertsApi } from '../services/api';

export default function Navbar() {
  const { user, logout } = useAuthStore();
  const { sidebarCollapsed } = useUiStore();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  // Fetch critical alerts count for notification bell
  const { data: alerts = [] } = useQuery({
    queryKey: ['activeAlertsCount'],
    queryFn: async () => {
      const res = await alertsApi.getAlerts({ status: 'new' });
      return res.data;
    },
    refetchInterval: 15000
  });

  const criticalCount = alerts.filter(a => a.severity === 'critical').length;
  const newCount = alerts.length;

  const getPageTitle = () => {
    const p = location.pathname;
    if (p === '/') return 'SOC Command Center';
    if (p === '/logs') return 'Log Ingestion & Normalization';
    if (p === '/events') return 'Common Event Model Telemetry';
    if (p === '/rules') return 'Detection Engine Rules';
    if (p === '/alerts') return 'Alerts & Triage Queue';
    if (p.startsWith('/cases/')) return 'Forensic Investigation Workspace';
    if (p === '/cases') return 'Investigative Cases';
    if (p === '/threat-intel') return 'Threat Intelligence Feeds';
    if (p === '/endpoints') return 'Endpoint Asset Inventory';
    if (p === '/accounts') return 'Identity & Access Profiling';
    if (p === '/reports') return 'Incident Forensic Reports';
    return 'SOC Platform';
  };

  return (
    <header
      className={`fixed top-0 right-0 h-16 bg-[#080b12]/90 backdrop-blur-md border-b border-slate-800/80 z-30 transition-all duration-300 flex items-center justify-between px-6 ${
        sidebarCollapsed ? 'left-20' : 'left-64'
      }`}
    >
      {/* Breadcrumb & Page Title */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]" />
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
            AEGIS FORENSIC
          </span>
          <span className="text-slate-600">/</span>
          <h1 className="text-sm font-bold font-mono text-white tracking-tight">
            {getPageTitle()}
          </h1>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* System Health Badge */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/50 border border-emerald-800/60 text-[11px] font-mono text-emerald-300">
          <Activity className="w-3.5 h-3.5 animate-pulse" />
          <span>DEFCON 4 // ACTIVE</span>
        </div>

        {/* Quick Upload Logs Link */}
        <button
          onClick={() => navigate('/logs')}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-mono text-xs transition-all shadow-[0_0_10px_rgba(6,182,212,0.1)]"
          title="Upload & Ingest Security Logs"
        >
          <UploadCloud className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Upload Logs</span>
        </button>

        {/* Notifications Bell */}
        <button
          onClick={() => navigate('/alerts')}
          className="relative p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          title="Alerts Triage Queue"
        >
          <Bell className="w-5 h-5" />
          {newCount > 0 && (
            <span className={`absolute top-1 right-1 flex items-center justify-center min-w-[18px] h-[18px] text-[10px] font-mono font-bold rounded-full px-1 ${
              criticalCount > 0
                ? 'bg-rose-600 text-white shadow-[0_0_8px_rgba(244,63,94,0.6)] animate-bounce'
                : 'bg-cyan-500 text-black'
            }`}>
              {newCount}
            </span>
          )}
        </button>

        {/* User Dropdown */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2.5 p-1.5 rounded-xl hover:bg-slate-800/80 transition-colors"
          >
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center font-mono font-bold text-xs text-black">
              {user?.username?.substring(0, 2).toUpperCase() || 'SO'}
            </div>
            <div className="hidden md:flex flex-col text-left">
              <span className="text-xs font-bold text-slate-200">
                {user?.fullName || user?.username}
              </span>
              <span className="text-[10px] font-mono text-slate-400 uppercase">
                {user?.role}
              </span>
            </div>
            <ChevronDown className="w-4 h-4 text-slate-400" />
          </button>

          {dropdownOpen && (
            <div
              className="absolute right-0 mt-2 w-56 bg-[#0f1422] border border-slate-700 rounded-xl shadow-2xl py-2 z-50 text-xs font-mono"
              onClick={() => setDropdownOpen(false)}
            >
              <div className="px-4 py-2 border-b border-slate-800">
                <p className="font-bold text-slate-200 truncate">{user?.fullName}</p>
                <p className="text-[11px] text-slate-400 truncate">{user?.email}</p>
                <div className="mt-1 inline-block px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 text-[10px] uppercase font-bold">
                  {user?.role} Role
                </div>
              </div>

              <div className="py-1">
                <button
                  onClick={() => navigate('/cases')}
                  className="w-full text-left px-4 py-2 text-slate-300 hover:bg-slate-800 hover:text-white flex items-center gap-2"
                >
                  <Shield className="w-4 h-4 text-cyan-400" /> My Cases
                </button>
              </div>

              <div className="border-t border-slate-800 pt-1">
                <button
                  onClick={logout}
                  className="w-full text-left px-4 py-2 text-rose-400 hover:bg-rose-950/40 flex items-center gap-2"
                >
                  <LogOut className="w-4 h-4" /> Terminate Session
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
