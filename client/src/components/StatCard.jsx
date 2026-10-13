import React from 'react';

export default function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'cyan',
  trend,
  className = ''
}) {
  const colorMap = {
    cyan: {
      border: 'border-cyan-500/30 hover:border-cyan-500/60',
      iconBg: 'bg-cyan-500/10 text-cyan-400',
      glow: 'shadow-[0_0_15px_rgba(6,182,212,0.15)]'
    },
    rose: {
      border: 'border-rose-500/30 hover:border-rose-500/60',
      iconBg: 'bg-rose-500/10 text-rose-400',
      glow: 'shadow-[0_0_15px_rgba(244,63,94,0.15)]'
    },
    amber: {
      border: 'border-amber-500/30 hover:border-amber-500/60',
      iconBg: 'bg-amber-500/10 text-amber-400',
      glow: 'shadow-[0_0_15px_rgba(245,158,11,0.15)]'
    },
    emerald: {
      border: 'border-emerald-500/30 hover:border-emerald-500/60',
      iconBg: 'bg-emerald-500/10 text-emerald-400',
      glow: 'shadow-[0_0_15px_rgba(16,185,129,0.15)]'
    },
    purple: {
      border: 'border-purple-500/30 hover:border-purple-500/60',
      iconBg: 'bg-purple-500/10 text-purple-400',
      glow: 'shadow-[0_0_15px_rgba(168,85,247,0.15)]'
    }
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div className={`bg-[#0f1422] border rounded-xl p-5 transition-all duration-200 select-none cursor-default ${scheme.border} ${scheme.glow} ${className}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono select-none cursor-default">
          {title}
        </span>
        {Icon && (
          <div className={`p-2.5 rounded-lg ${scheme.iconBg}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>

      <div className="mt-4 flex items-baseline justify-between select-none cursor-default">
        <span className="text-2xl sm:text-3xl font-bold font-mono tracking-tight text-white select-none cursor-default">
          {value !== undefined && value !== null ? value : '-'}
        </span>
        {trend && (
          <span className={`text-xs font-mono font-medium select-none cursor-default ${trend.startsWith('+') ? 'text-rose-400' : 'text-emerald-400'}`}>
            {trend}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="mt-2 text-xs text-slate-400 truncate select-none cursor-default">
          {subtitle}
        </p>
      )}
    </div>
  );
}
