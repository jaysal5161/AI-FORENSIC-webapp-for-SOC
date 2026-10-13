import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Lock, User, Terminal, ArrowRight, AlertCircle } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';
import Spinner from '../components/Spinner';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { login, isLoading, error } = useAuthStore();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const res = await login(username, password);
    if (res.success) {
      navigate('/');
    }
  };

  return (
    <div className="min-h-screen bg-[#070a10] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background Matrix/Cyber glow elements */}
      <div className="absolute -top-40 -left-40 w-96 h-96 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 rounded-full bg-blue-600/10 blur-3xl pointer-events-none" />

      <div className="w-full max-w-md relative z-10">
        {/* Branding */}
        <div className="text-center mb-8">
          <div className="inline-flex p-3 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-700 shadow-[0_0_20px_rgba(6,182,212,0.4)] mb-3">
            <ShieldAlert className="w-10 h-10 text-black" />
          </div>
          <h2 className="text-2xl font-black font-mono tracking-wider text-white">
            AEGIS <span className="text-cyan-400">//</span> SOC
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1 uppercase tracking-widest">
            Forensic Investigation & Incident Command Center
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-[#0f1422] border border-slate-800/90 rounded-2xl p-7 shadow-2xl backdrop-blur-xl">
          <div className="flex items-center gap-2 pb-4 mb-5 border-b border-slate-800">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Analyst Access Authentication
            </span>
          </div>

          {error && (
            <div className="mb-5 p-3.5 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-300 flex items-center gap-2.5 text-xs font-mono">
              <AlertCircle className="w-4 h-4 flex-shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                Username / Agent ID
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 bg-[#080b12] border border-slate-800 rounded-lg text-sm text-slate-200 placeholder-slate-600 font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                  placeholder="Enter username"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                Password / Secure Token
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 bg-[#080b12] border border-slate-800 rounded-lg text-sm text-slate-200 placeholder-slate-600 font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-2 py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-black text-xs font-bold font-mono uppercase tracking-wider flex items-center justify-center gap-2 hover:brightness-110 shadow-[0_0_15px_rgba(6,182,212,0.35)] disabled:opacity-50 transition-all cursor-pointer"
            >
              {isLoading ? <Spinner size="sm" /> : <ArrowRight className="w-4 h-4" />}
              {isLoading ? 'Authorizing...' : 'Initialize Session'}
            </button>
          </form>
        </div>

        {/* Security Notice */}
        <p className="mt-6 text-center text-[10px] font-mono text-slate-500 uppercase tracking-wider">
          UNAUTHORIZED ACCESS STRICTLY PROHIBITED &bull; ALL ACTIONS AUDITED
        </p>
      </div>
    </div>
  );
}
