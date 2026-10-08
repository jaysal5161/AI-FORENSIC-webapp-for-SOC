import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Sliders,
  Plus,
  Play,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  Edit2,
  Search,
  Filter,
  Check,
  X,
  Shield,
  Clock,
  Layers,
  Sparkles
} from 'lucide-react';
import { rulesApi } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import Modal from '../components/Modal';
import Spinner from '../components/Spinner';
import { useAuthStore } from '../stores/authStore';

const DEFAULT_FORM_DATA = {
  name: '',
  description: '',
  severity: 'high',
  enabled: true,
  eventType: 'authentication',
  action: 'login',
  status: 'failed',
  source: '',
  threshold: 3,
  windowSeconds: 300,
  patternType: 'threshold',
  mitreTechniqueId: 'T1110',
  tags: 'BruteForce, Auth'
};

export default function Rules() {
  const queryClient = useQueryClient();
  const { isAnalyst } = useAuthStore();
  const canManage = isAnalyst();

  // Modals & States
  const [modalOpen, setModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState('create'); // 'create' | 'edit'
  const [editingRuleId, setEditingRuleId] = useState(null);
  const [formData, setFormData] = useState(DEFAULT_FORM_DATA);
  const [formError, setFormError] = useState(null);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all'); // 'all' | 'allowed' | 'disallowed'
  const [severityFilter, setSeverityFilter] = useState('all');

  // Execution & Notifications
  const [executing, setExecuting] = useState(false);
  const [engineResult, setEngineResult] = useState(null);
  const [actionNotice, setActionNotice] = useState(null);

  const { data: rules = [], isLoading } = useQuery({
    queryKey: ['detectionRules'],
    queryFn: async () => {
      const res = await rulesApi.getRules();
      return res.data;
    }
  });

  const showNotice = (message, type = 'success') => {
    setActionNotice({ message, type });
    setTimeout(() => {
      setActionNotice(null);
    }, 4500);
  };

  // Toggle Rule Status (Allow / Disallow)
  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }) => rulesApi.updateRule(id, { enabled }),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['detectionRules'] });
      showNotice(
        `Rule successfully ${variables.enabled ? 'Allowed (Enabled)' : 'Disallowed (Paused)'}!`,
        'success'
      );
    },
    onError: (err) => {
      showNotice(
        err.response?.data?.message || 'Failed to update rule status. Please check your permissions.',
        'error'
      );
    }
  });

  // Delete Rule
  const deleteMutation = useMutation({
    mutationFn: (id) => rulesApi.deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detectionRules'] });
      showNotice('Detection rule deleted successfully', 'success');
    },
    onError: (err) => {
      showNotice(err.response?.data?.message || 'Failed to delete rule', 'error');
    }
  });

  // Create Rule
  const createMutation = useMutation({
    mutationFn: (newRule) => rulesApi.createRule(newRule),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detectionRules'] });
      setModalOpen(false);
      showNotice('New detection rule deployed successfully!', 'success');
    },
    onError: (err) => {
      setFormError(err.response?.data?.message || 'Failed to create detection rule.');
    }
  });

  // Update / Edit Rule
  const updateMutation = useMutation({
    mutationFn: ({ id, payload }) => rulesApi.updateRule(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detectionRules'] });
      setModalOpen(false);
      showNotice('Detection rule updated successfully!', 'success');
    },
    onError: (err) => {
      setFormError(err.response?.data?.message || 'Failed to update detection rule.');
    }
  });

  const handleRunEngine = async () => {
    setExecuting(true);
    setEngineResult(null);
    try {
      const res = await rulesApi.runAll();
      setEngineResult(res.data);
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
    } catch (err) {
      showNotice(err.response?.data?.message || 'Failed to execute detection engine', 'error');
    } finally {
      setExecuting(false);
    }
  };

  const handleOpenCreate = () => {
    setModalMode('create');
    setEditingRuleId(null);
    setFormData(DEFAULT_FORM_DATA);
    setFormError(null);
    setModalOpen(true);
  };

  const handleOpenEdit = (rule) => {
    setModalMode('edit');
    setEditingRuleId(rule._id);
    setFormData({
      name: rule.name || '',
      description: rule.description || '',
      severity: rule.severity || 'medium',
      enabled: rule.enabled !== undefined ? rule.enabled : true,
      eventType: rule.condition?.eventType || '',
      action: rule.condition?.action || '',
      status: rule.condition?.status || '',
      source: rule.condition?.source || '',
      threshold: rule.condition?.threshold !== undefined ? rule.condition.threshold : 1,
      windowSeconds: rule.condition?.windowSeconds !== undefined ? rule.condition.windowSeconds : 300,
      patternType: rule.condition?.patternType || 'threshold',
      mitreTechniqueId: rule.mitreTechniqueId || '',
      tags: (rule.tags || []).join(', ')
    });
    setFormError(null);
    setModalOpen(true);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setFormError(null);

    const payload = {
      name: formData.name.trim(),
      description: formData.description.trim(),
      severity: formData.severity,
      enabled: Boolean(formData.enabled),
      condition: {
        eventType: formData.eventType.trim(),
        action: formData.action.trim(),
        status: formData.status.trim(),
        source: formData.source.trim(),
        threshold: parseInt(formData.threshold, 10) || 1,
        windowSeconds: parseInt(formData.windowSeconds, 10) || 300,
        patternType: formData.patternType || 'threshold'
      },
      mitreTechniqueId: formData.mitreTechniqueId.trim(),
      tags: formData.tags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean)
    };

    if (modalMode === 'create') {
      createMutation.mutate(payload);
    } else {
      updateMutation.mutate({ id: editingRuleId, payload });
    }
  };

  // Filtered Rules
  const filteredRules = rules.filter((rule) => {
    // Status filter
    if (statusFilter === 'allowed' && !rule.enabled) return false;
    if (statusFilter === 'disallowed' && rule.enabled) return false;

    // Severity filter
    if (severityFilter !== 'all' && rule.severity !== severityFilter) return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = (rule.name || '').toLowerCase().includes(q);
      const matchDesc = (rule.description || '').toLowerCase().includes(q);
      const matchTechnique = (rule.mitreTechniqueId || '').toLowerCase().includes(q);
      const matchTags = (rule.tags || []).some((t) => t.toLowerCase().includes(q));
      if (!matchName && !matchDesc && !matchTechnique && !matchTags) return false;
    }

    return true;
  });

  const totalRules = rules.length;
  const allowedRulesCount = rules.filter((r) => r.enabled).length;
  const disallowedRulesCount = totalRules - allowedRulesCount;

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="p-5 bg-[#0f1422] border border-slate-800 rounded-2xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Sliders className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wide">
              Detection Engine & SIEM Correlation Rules
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Configurable threshold and sequence correlation rules aligned with the MITRE ATT&CK framework.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRunEngine}
            disabled={executing}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-xs font-bold transition-all border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.15)] disabled:opacity-50"
          >
            {executing ? <Spinner size="sm" /> : <Play className="w-4 h-4" />}
            {executing ? 'Evaluating...' : 'Run Detection Engine'}
          </button>

          {canManage && (
            <button
              onClick={handleOpenCreate}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-mono text-xs font-bold hover:brightness-110 shadow-[0_0_12px_rgba(6,182,212,0.3)] transition-all"
            >
              <Plus className="w-4 h-4" /> Create Rule
            </button>
          )}
        </div>
      </div>

      {/* Action Notification Banner */}
      {actionNotice && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between text-xs font-mono transition-all animate-fadeIn ${
            actionNotice.type === 'error'
              ? 'bg-rose-950/40 border-rose-500/60 text-rose-300 shadow-[0_0_15px_rgba(244,63,94,0.15)]'
              : 'bg-emerald-950/40 border-emerald-500/60 text-emerald-300 shadow-[0_0_15px_rgba(16,185,129,0.15)]'
          }`}
        >
          <div className="flex items-center gap-2">
            {actionNotice.type === 'error' ? (
              <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            )}
            <span>{actionNotice.message}</span>
          </div>
          <button
            onClick={() => setActionNotice(null)}
            className="text-slate-400 hover:text-white ml-3"
          >
            &times;
          </button>
        </div>
      )}

      {/* Engine Execution Result Banner */}
      {engineResult && (
        <div className="p-4 rounded-xl bg-[#0f1422] border border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.2)] flex items-center justify-between text-xs font-mono text-emerald-300">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            <span>
              {engineResult.message} &bull; Generated{' '}
              <strong className="text-white">{engineResult.alertsGenerated}</strong> new alerts!
            </span>
          </div>
          <button onClick={() => setEngineResult(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* Metrics & Filter Bar */}
      <div className="p-4 bg-[#0f1422] border border-slate-800 rounded-xl space-y-3">
        {/* Status Counters */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Total Rules:</span>
            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-bold">
              {totalRules}
            </span>
            <span className="text-slate-600 ml-1">&bull;</span>
            <span className="text-emerald-400 font-semibold flex items-center gap-1 ml-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              Allowed: {allowedRulesCount}
            </span>
            <span className="text-slate-600 ml-1">&bull;</span>
            <span className="text-rose-400 font-semibold flex items-center gap-1 ml-1">
              <span className="w-2 h-2 rounded-full bg-rose-400" />
              Disallowed: {disallowedRulesCount}
            </span>
          </div>

          <div className="text-xs text-slate-400 font-mono">
            Showing <strong className="text-cyan-400">{filteredRules.length}</strong> of{' '}
            <strong className="text-slate-200">{totalRules}</strong> rules
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Box */}
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search rule name, description, MITRE technique, tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#080b12] border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs"
              >
                &times;
              </button>
            )}
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1 bg-[#080b12] p-1 border border-slate-800 rounded-lg text-xs font-mono">
            <button
              onClick={() => setStatusFilter('all')}
              className={`px-3 py-1 rounded transition-colors ${
                statusFilter === 'all'
                  ? 'bg-cyan-500/20 text-cyan-400 font-bold border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All Status
            </button>
            <button
              onClick={() => setStatusFilter('allowed')}
              className={`px-3 py-1 rounded transition-colors flex items-center gap-1.5 ${
                statusFilter === 'allowed'
                  ? 'bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Check className="w-3 h-3 text-emerald-400" /> Allowed
            </button>
            <button
              onClick={() => setStatusFilter('disallowed')}
              className={`px-3 py-1 rounded transition-colors flex items-center gap-1.5 ${
                statusFilter === 'disallowed'
                  ? 'bg-rose-500/20 text-rose-400 font-bold border border-rose-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <X className="w-3 h-3 text-rose-400" /> Disallowed
            </button>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1 bg-[#080b12] px-2 py-1 border border-slate-800 rounded-lg text-xs font-mono">
            <Filter className="w-3 h-3 text-slate-500 mr-1" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-slate-300 focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-[#0f1422] text-slate-200">
                All Severities
              </option>
              <option value="critical" className="bg-[#0f1422] text-rose-400">
                Critical
              </option>
              <option value="high" className="bg-[#0f1422] text-amber-400">
                High
              </option>
              <option value="medium" className="bg-[#0f1422] text-yellow-400">
                Medium
              </option>
              <option value="low" className="bg-[#0f1422] text-blue-400">
                Low
              </option>
            </select>
          </div>
        </div>
      </div>

      {/* Rules Grid */}
      {isLoading ? (
        <div className="py-16 text-center">
          <Spinner size="md" />
          <p className="text-xs font-mono text-slate-500 mt-2">Loading detection rules...</p>
        </div>
      ) : filteredRules.length === 0 ? (
        <div className="py-16 text-center bg-[#0f1422] border border-slate-800 rounded-2xl p-8">
          <Sliders className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-bold font-mono text-slate-300 uppercase">
            No Detection Rules Match
          </h3>
          <p className="text-xs text-slate-500 font-mono mt-1 max-w-md mx-auto">
            No rules match your current search or filter criteria. Try clearing filters or create a new detection rule.
          </p>
          {(searchQuery || statusFilter !== 'all' || severityFilter !== 'all') && (
            <button
              onClick={() => {
                setSearchQuery('');
                setStatusFilter('all');
                setSeverityFilter('all');
              }}
              className="mt-4 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-mono"
            >
              Clear Filters
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredRules.map((rule) => {
            const isTogglingThis =
              toggleMutation.isPending && toggleMutation.variables?.id === rule._id;

            return (
              <div
                key={rule._id}
                className={`p-5 rounded-xl border transition-all flex flex-col justify-between relative group ${
                  rule.enabled
                    ? 'bg-[#0f1422] border-slate-800 hover:border-slate-700 shadow-[0_4px_20px_rgba(0,0,0,0.25)]'
                    : 'bg-[#090d16] border-slate-900/80 opacity-75 hover:opacity-100 hover:border-slate-800'
                }`}
              >
                <div>
                  {/* Top Bar: Severity + MITRE ID + ALLOW/DISALLOW Toggle */}
                  <div className="flex items-center justify-between gap-3 mb-3">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SeverityBadge severity={rule.severity} />

                      {rule.mitreTechniqueId && (
                        <span className="px-2 py-0.5 rounded bg-purple-950/80 border border-purple-800/80 text-purple-300 font-mono text-xs font-bold shadow-[0_0_8px_rgba(168,85,247,0.15)]">
                          {rule.mitreTechniqueId}
                        </span>
                      )}

                      {/* Explicit Allowed / Disallowed Status Badge */}
                      {rule.enabled ? (
                        <span className="px-2 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-500/50 text-emerald-400 font-mono text-[10px] font-bold flex items-center gap-1">
                          <Check className="w-2.5 h-2.5 text-emerald-400" />
                          ALLOWED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full bg-rose-950/60 border border-rose-500/50 text-rose-400 font-mono text-[10px] font-bold flex items-center gap-1">
                          <X className="w-2.5 h-2.5 text-rose-400" />
                          DISALLOWED
                        </span>
                      )}
                    </div>

                    {/* Enable / Disable (Allow / Disallow) Interactive Switch */}
                    <div className="flex items-center gap-2">
                      <label
                        className={`relative inline-flex items-center ${
                          canManage && !isTogglingThis ? 'cursor-pointer' : 'cursor-not-allowed opacity-60'
                        }`}
                        title={
                          rule.enabled
                            ? 'Rule is currently Allowed. Click to Disallow (Pause detection)'
                            : 'Rule is currently Disallowed. Click to Allow (Enable detection)'
                        }
                      >
                        <input
                          type="checkbox"
                          checked={rule.enabled}
                          disabled={!canManage || isTogglingThis}
                          onChange={(e) => {
                            toggleMutation.mutate({ id: rule._id, enabled: e.target.checked });
                          }}
                          className="sr-only peer"
                        />
                        <div className="w-10 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-500"></div>
                      </label>
                      {isTogglingThis && <Spinner size="sm" />}
                    </div>
                  </div>

                  {/* Rule Name & Description */}
                  <h4 className="text-sm font-bold font-mono text-slate-100 mb-1 flex items-center gap-2">
                    {rule.name}
                  </h4>
                  <p className="text-xs text-slate-400 font-sans leading-relaxed mb-4">
                    {rule.description}
                  </p>

                  {/* Condition Metadata Summary */}
                  <div className="p-3 rounded-lg bg-[#080b12] border border-slate-800/80 font-mono text-[11px] text-slate-400 space-y-1.5 mb-4">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500 flex items-center gap-1">
                        <Clock className="w-3 h-3 text-cyan-400" /> Condition Window:
                      </span>
                      <strong className="text-slate-200">
                        &ge; {rule.condition?.threshold || 1} hits within {rule.condition?.windowSeconds || 300}s
                      </strong>
                    </div>

                    <div className="flex justify-between items-center">
                      <span className="text-slate-500 flex items-center gap-1">
                        <Shield className="w-3 h-3 text-purple-400" /> Event Match:
                      </span>
                      <strong className="text-cyan-400">
                        {rule.condition?.eventType || 'any'} &bull; {rule.condition?.action || 'any'} (
                        {rule.condition?.status || 'any'})
                      </strong>
                    </div>

                    {rule.condition?.patternType && rule.condition.patternType !== 'threshold' && (
                      <div className="flex justify-between items-center">
                        <span className="text-slate-500 flex items-center gap-1">
                          <Layers className="w-3 h-3 text-amber-400" /> Pattern:
                        </span>
                        <strong className="text-amber-300">
                          {rule.condition.patternType}
                        </strong>
                      </div>
                    )}
                  </div>
                </div>

                {/* Card Footer: Tags & Action Buttons (Edit + Delete) */}
                <div className="flex items-center justify-between pt-3 border-t border-slate-800/80 text-xs font-mono">
                  <div className="flex flex-wrap gap-1 max-w-[65%]">
                    {(rule.tags || []).map((t, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/50"
                      >
                        #{t}
                      </span>
                    ))}
                  </div>

                  <div className="flex items-center gap-1">
                    {canManage && (
                      <>
                        <button
                          onClick={() => handleOpenEdit(rule)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 transition-colors border border-slate-700/60"
                          title="Edit Rule Configuration"
                        >
                          <Edit2 className="w-3.5 h-3.5" />
                          <span className="text-[11px] font-bold">Edit</span>
                        </button>

                        <button
                          onClick={() => {
                            if (
                              window.confirm(
                                `Are you sure you want to delete detection rule "${rule.name}"? This action cannot be undone.`
                              )
                            ) {
                              deleteMutation.mutate(rule._id);
                            }
                          }}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-950/30 transition-colors"
                          title="Delete Rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Unified Create & Edit Rule Modal */}
      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title={modalMode === 'create' ? 'Deploy New Detection Rule' : `Edit Rule: ${formData.name || 'Detection Rule'}`}
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleSubmit} className="space-y-4 font-mono text-xs">
          {formError && (
            <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-500/60 text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>{formError}</span>
            </div>
          )}

          {/* Rule Name & Status */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label className="block text-slate-400 uppercase mb-1">
                Rule Name <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                placeholder="e.g. Mass Password Guessing"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full bg-[#080b12] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-slate-400 uppercase mb-1">Rule Status</label>
              <button
                type="button"
                onClick={() => setFormData({ ...formData, enabled: !formData.enabled })}
                className={`w-full py-2 px-3 rounded-lg font-bold flex items-center justify-center gap-2 border transition-all ${
                  formData.enabled
                    ? 'bg-emerald-950/60 border-emerald-500/60 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.2)]'
                    : 'bg-rose-950/60 border-rose-500/60 text-rose-400'
                }`}
              >
                {formData.enabled ? <Check className="w-3.5 h-3.5" /> : <X className="w-3.5 h-3.5" />}
                {formData.enabled ? 'Allowed' : 'Disallowed'}
              </button>
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="block text-slate-400 uppercase mb-1">
              Description <span className="text-rose-400">*</span>
            </label>
            <textarea
              required
              rows={2}
              placeholder="Explain the detection hypothesis, target attack activity, and investigation instructions..."
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full bg-[#080b12] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none font-sans text-xs"
            />
          </div>

          {/* Severity & MITRE Technique ID */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 uppercase mb-1">Severity</label>
              <select
                value={formData.severity}
                onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                className="w-full bg-[#080b12] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 uppercase mb-1">MITRE Technique ID</label>
              <input
                type="text"
                placeholder="e.g. T1110 or T1003.001"
                value={formData.mitreTechniqueId}
                onChange={(e) => setFormData({ ...formData, mitreTechniqueId: e.target.value })}
                className="w-full bg-[#080b12] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Event Match Criteria */}
          <div className="p-3 bg-[#080b12] rounded-xl border border-slate-800/80 space-y-3">
            <div className="flex items-center gap-1.5 text-cyan-400 font-bold uppercase text-[11px]">
              <Sparkles className="w-3.5 h-3.5" /> Event Telemetry Filter Criteria
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="block text-slate-500 uppercase mb-1 text-[10px]">Event Type</label>
                <input
                  type="text"
                  placeholder="e.g. authentication"
                  value={formData.eventType}
                  onChange={(e) => setFormData({ ...formData, eventType: e.target.value })}
                  className="w-full bg-[#0f1422] border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-500 uppercase mb-1 text-[10px]">Action</label>
                <input
                  type="text"
                  placeholder="e.g. login"
                  value={formData.action}
                  onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                  className="w-full bg-[#0f1422] border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-500 uppercase mb-1 text-[10px]">Status</label>
                <input
                  type="text"
                  placeholder="e.g. failed"
                  value={formData.status}
                  onChange={(e) => setFormData({ ...formData, status: e.target.value })}
                  className="w-full bg-[#0f1422] border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-500 uppercase mb-1 text-[10px]">
                  Source System (optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. windows_event_log or syslog"
                  value={formData.source}
                  onChange={(e) => setFormData({ ...formData, source: e.target.value })}
                  className="w-full bg-[#0f1422] border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-500 uppercase mb-1 text-[10px]">
                  Correlation Pattern Type
                </label>
                <select
                  value={formData.patternType}
                  onChange={(e) => setFormData({ ...formData, patternType: e.target.value })}
                  className="w-full bg-[#0f1422] border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:border-cyan-500 focus:outline-none"
                >
                  <option value="threshold">Threshold (Occurrences count)</option>
                  <option value="failed_then_success_login">Failed followed by Success Login</option>
                  <option value="powershell_obfuscation">PowerShell Obfuscation / Encoded</option>
                  <option value="mass_file_ops">Mass File Encryption / Staging</option>
                </select>
              </div>
            </div>
          </div>

          {/* Threshold & Sliding Window */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 uppercase mb-1">
                Threshold Count (&ge; Hits)
              </label>
              <input
                type="number"
                min="1"
                required
                value={formData.threshold}
                onChange={(e) => setFormData({ ...formData, threshold: e.target.value })}
                className="w-full bg-[#080b12] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-slate-400 uppercase mb-1">
                Window Period (Seconds)
              </label>
              <input
                type="number"
                min="5"
                required
                value={formData.windowSeconds}
                onChange={(e) => setFormData({ ...formData, windowSeconds: e.target.value })}
                className="w-full bg-[#080b12] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Tags */}
          <div>
            <label className="block text-slate-400 uppercase mb-1">Tags (Comma-separated)</label>
            <input
              type="text"
              placeholder="e.g. CredentialAccess, Windows, BruteForce"
              value={formData.tags}
              onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
              className="w-full bg-[#080b12] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          {/* Modal Footer */}
          <div className="pt-4 flex items-center justify-between border-t border-slate-800">
            <span className="text-[11px] text-slate-500">
              {modalMode === 'create'
                ? 'Rule will be active immediately upon deployment.'
                : 'Modifications take effect on subsequent evaluations.'}
            </span>

            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium transition-colors"
              >
                Cancel
              </button>

              <button
                type="submit"
                disabled={createMutation.isPending || updateMutation.isPending}
                className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold font-mono shadow-[0_0_12px_rgba(6,182,212,0.3)] disabled:opacity-50 transition-all flex items-center gap-1.5"
              >
                {createMutation.isPending || updateMutation.isPending ? (
                  <Spinner size="sm" />
                ) : (
                  <Check className="w-4 h-4" />
                )}
                {modalMode === 'create'
                  ? createMutation.isPending
                    ? 'Deploying...'
                    : 'Deploy Rule'
                  : updateMutation.isPending
                  ? 'Saving Changes...'
                  : 'Save Changes'}
              </button>
            </div>
          </div>
        </form>
      </Modal>
    </div>
  );
}
