import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  LayoutDashboard,
  UploadCloud,
  FileCode,
  Sliders,
  Bell,
  Briefcase,
  Crosshair,
  Server,
  Users,
  FileText,
  ChevronLeft,
  ChevronRight,
  Terminal
} from 'lucide-react';
import { useUiStore } from '../stores/uiStore';
import { useAuthStore } from '../stores/authStore';

export default function Sidebar() {
  const { sidebarCollapsed, toggleSidebar } = useUiStore();
  const { user } = useAuthStore();

  const navItems = [
    { label: 'Dashboard', path: '/', icon: LayoutDashboard },
    { label: 'Upload & Log Files', path: '/logs', icon: UploadCloud },
    { label: 'Event Telemetry', path: '/events', icon: FileCode },
    { label: 'Detection Rules', path: '/rules', icon: Sliders },
    { label: 'Alerts Queue', path: '/alerts', icon: Bell },
    { label: 'Forensic Cases', path: '/cases', icon: Briefcase },
    { label: 'Threat Intel', path: '/threat-intel', icon: Crosshair },
    { label: 'Endpoints', path: '/endpoints', icon: Server },
    { label: 'Accounts', path: '/accounts', icon: Users },
    { label: 'Reports', path: '/reports', icon: FileText }
  ];

  return (
    <aside
      className={`fixed left-0 top-0 h-screen z-40 bg-[#080b12] border-r border-slate-800/80 transition-all duration-300 flex flex-col justify-between select-none ${
        sidebarCollapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Top Branding */}
      <div>
        <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800/80">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-700 flex items-center justify-center flex-shrink-0 shadow-[0_0_12px_rgba(6,182,212,0.4)]">
              <ShieldAlert className="w-5 h-5 text-black" />
            </div>
            {!sidebarCollapsed && (
              <div className="flex flex-col">
                <span className="font-mono font-extrabold text-sm tracking-wider text-white">
                  AEGIS<span className="text-cyan-400">//</span>SOC
                </span>
                <span className="text-[10px] font-mono tracking-widest text-slate-500 uppercase">
                  Forensic v1.0
                </span>
              </div>
            )}
          </div>

          <button
            onClick={toggleSidebar}
            className="hidden md:flex p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            {sidebarCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation List */}
        <nav className="p-3 space-y-1 overflow-y-auto max-h-[calc(100vh-140px)]">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-mono font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.15)] font-bold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`
                }
                title={sidebarCollapsed ? item.label : undefined}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                {!sidebarCollapsed && <span>{item.label}</span>}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* User Info Footer */}
      <div className="p-3 border-t border-slate-800/80 bg-[#06080e]">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center font-mono font-bold text-xs text-cyan-400 flex-shrink-0">
            {user?.username?.substring(0, 2).toUpperCase() || 'AN'}
          </div>

          {!sidebarCollapsed && (
            <div className="overflow-hidden flex-1">
              <div className="text-xs font-bold text-slate-200 truncate">
                {user?.fullName || user?.username}
              </div>
              <div className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider">
                Role: {user?.role || 'analyst'}
              </div>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}
