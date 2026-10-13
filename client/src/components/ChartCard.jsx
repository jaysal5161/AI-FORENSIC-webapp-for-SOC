import React from 'react';

export default function ChartCard({
  title,
  subtitle,
  icon: Icon,
  children,
  action,
  className = ''
}) {
  return (
    <div className={`bg-[#0f1422] border border-slate-800 rounded-xl p-5 shadow-lg ${className}`}>
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-4 select-none cursor-default">
        <div className="flex items-center gap-2.5">
          {Icon && (
            <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400">
              <Icon className="w-4 h-4" />
            </div>
          )}
          <div>
            <h4 className="text-sm font-bold font-mono tracking-wide text-slate-200 uppercase select-none cursor-default">
              {title}
            </h4>
            {subtitle && (
              <p className="text-xs text-slate-400 select-none cursor-default">{subtitle}</p>
            )}
          </div>
        </div>
        {action && <div>{action}</div>}
      </div>
      <div>
        {children}
      </div>
    </div>
  );
}
