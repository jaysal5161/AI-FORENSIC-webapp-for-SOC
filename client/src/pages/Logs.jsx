import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  UploadCloud,
  FileCode,
  CheckCircle2,
  ArrowRight,
  Filter,
  X,
  Eye,
  Trash2,
  Download,
  HardDrive,
  Layers,
  FileText,
  ArrowLeft,
  RefreshCw,
  AlertTriangle
} from 'lucide-react';
import LogUploader from '../components/LogUploader';
import UploadedFilesList from '../components/UploadedFilesList';
import EventTable from '../components/EventTable';
import Modal from '../components/Modal';
import Spinner from '../components/Spinner';
import { eventsApi, logsApi } from '../services/api';

export default function Logs() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [selectedFile, setSelectedFile] = useState('');
  const [activeTab, setActiveTab] = useState('events'); // 'events' | 'raw'
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [rawContent, setRawContent] = useState(null);
  const [isLoadingRaw, setIsLoadingRaw] = useState(false);

  // Fetch all uploaded files list for the switcher dropdown and stats
  const { data: uploadedFiles = [], refetch: refetchFiles } = useQuery({
    queryKey: ['uploadedFiles'],
    queryFn: async () => {
      const res = await logsApi.getFiles();
      return res.data;
    }
  });

  // Fetch events (either filtered by selected file or global recent)
  const { data, isLoading, refetch: refetchEvents } = useQuery({
    queryKey: ['recentLogsEvents', { selectedFile }],
    queryFn: async () => {
      const res = await eventsApi.getEvents({
        rawFile: selectedFile || undefined,
        limit: selectedFile ? 500 : 50
      });
      return res.data;
    }
  });

  // Delete mutation for the individual file view
  const deleteMutation = useMutation({
    mutationFn: async (fileName) => {
      const res = await logsApi.deleteFileByName(fileName);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['uploadedFiles'] });
      queryClient.invalidateQueries({ queryKey: ['recentLogsEvents'] });
      queryClient.invalidateQueries({ queryKey: ['eventsExplorer'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
      setSelectedFile('');
      localStorage.removeItem('aegis_active_log_file');
      setShowDeleteModal(false);
    },
    onError: (err) => {
      alert('Failed to delete log file: ' + (err.response?.data?.message || err.message));
    }
  });

  const handleUploadSuccess = (summary) => {
    queryClient.invalidateQueries({ queryKey: ['uploadedFiles'] });
    queryClient.invalidateQueries({ queryKey: ['recentLogsEvents'] });
    queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
    if (summary?.fileName) {
      setSelectedFile(summary.fileName);
      localStorage.setItem('aegis_active_log_file', summary.fileName);
    }
    refetchEvents();
    refetchFiles();
  };

  const handleSelectFile = async (fileName) => {
    setSelectedFile(fileName);
    if (fileName) {
      localStorage.setItem('aegis_active_log_file', fileName);
    }
    setActiveTab('events');
    setRawContent(null);
  };

  const handleLoadRawContent = async () => {
    if (!selectedFile) return;
    const currentFileObj = uploadedFiles.find(f => f.fileName === selectedFile);
    if (!currentFileObj) return;

    setIsLoadingRaw(true);
    setActiveTab('raw');
    try {
      const res = await logsApi.getRawContent(currentFileObj._id);
      setRawContent(res.data);
    } catch (err) {
      setRawContent({ error: err.response?.data?.message || 'Raw content unavailable.' });
    } finally {
      setIsLoadingRaw(false);
    }
  };

  const handleDownloadCurrentFile = async () => {
    const currentFileObj = uploadedFiles.find(f => f.fileName === selectedFile);
    if (!currentFileObj) return;
    try {
      const res = await logsApi.downloadFile(currentFileObj._id);
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', selectedFile);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download: ' + (err.response?.data?.message || err.message));
    }
  };

  const currentFileObj = uploadedFiles.find(f => f.fileName === selectedFile);
  const totalEventsInFiles = uploadedFiles.reduce((acc, f) => acc + (f.eventsCount || 0), 0);

  return (
    <div className="space-y-8 pb-12">
      {/* Header Banner */}
      <div className="p-5 bg-[#0f1422] border border-slate-800 rounded-2xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wide">
              Security Log Ingestion & Forensic Archive
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Upload, archive, inspect, and manage heterogeneous security telemetry with forensic integrity.
          </p>
        </div>

        <button
          onClick={() => navigate(selectedFile ? `/events?rawFile=${encodeURIComponent(selectedFile)}` : '/events')}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-xs font-semibold transition-colors"
        >
          Open in Telemetry Explorer <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* Choose Uploaded File Selector Bar */}
      <div className="p-4 bg-[#0b0f19] border border-slate-800 rounded-xl space-y-3 font-mono text-xs">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-slate-300 font-bold uppercase tracking-wider">
            <Layers className="w-4 h-4 text-cyan-400" /> Choose Uploaded Log File to Inspect:
          </div>

          {selectedFile && (
            <button
              onClick={() => setSelectedFile('')}
              className="flex items-center gap-1 text-xs text-rose-400 hover:text-rose-300 transition-colors"
            >
              <X className="w-3.5 h-3.5" /> Close Individual View (Show All)
            </button>
          )}
        </div>

        {/* Dropdown File Chooser */}
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="w-full sm:flex-1">
            <select
              value={selectedFile}
              onChange={(e) => handleSelectFile(e.target.value)}
              className="w-full bg-[#070a10] border border-cyan-500/40 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-400 text-xs font-mono"
            >
              <option value="">-- View All Ingested Records ({totalEventsInFiles} total events across {uploadedFiles.length} files) --</option>
              {uploadedFiles.map((file) => (
                <option key={file._id} value={file.fileName}>
                  {file.fileName} ({file.eventsCount} events - {file.format?.toUpperCase() || 'LOG'})
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            {selectedFile && (
              <button
                onClick={() => setShowDeleteModal(true)}
                className="w-full sm:w-auto flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 hover:bg-rose-900/60 text-xs font-bold transition-colors"
                title="Delete this chosen file and purge its events"
              >
                <Trash2 className="w-3.5 h-3.5" /> Delete File
              </button>
            )}
          </div>
        </div>

        {/* Quick Clickable File Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <button
            onClick={() => handleSelectFile('')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all border ${
              !selectedFile
                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/60 font-bold'
                : 'bg-[#070a10] text-slate-400 border-slate-800 hover:border-slate-700'
            }`}
          >
            All Files
          </button>
          {uploadedFiles.map((file) => {
            const isSelected = selectedFile === file.fileName;
            return (
              <button
                key={file._id}
                onClick={() => handleSelectFile(file.fileName)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all border flex items-center gap-1.5 ${
                  isSelected
                    ? 'bg-cyan-500 text-black border-cyan-400 font-bold shadow-[0_0_10px_rgba(6,182,212,0.3)]'
                    : 'bg-[#070a10] text-slate-300 border-slate-800 hover:border-slate-700 hover:text-white'
                }`}
              >
                <FileText className="w-3 h-3" />
                <span>{file.fileName}</span>
                <span className={`text-[10px] px-1 py-0.2 rounded ${isSelected ? 'bg-black/20 text-black font-extrabold' : 'bg-slate-800 text-cyan-400'}`}>
                  {file.eventsCount}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* VIEW MODE 1: INDIVIDUAL CHOSEN FILE WORKSPACE */}
      {selectedFile ? (
        <div className="space-y-4">
          {/* Individual File Header Card */}
          <div className="p-5 bg-[#0f1422] border border-cyan-500/40 rounded-2xl space-y-4 shadow-[0_0_20px_rgba(6,182,212,0.1)]">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300 flex-shrink-0">
                  <FileText className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-base font-bold font-mono text-white tracking-wide">
                      {selectedFile}
                    </h3>
                    <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-700 text-cyan-400 text-xs font-mono font-bold uppercase">
                      {currentFileObj?.format || 'LOG'}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-400 text-xs font-mono font-bold">
                      {currentFileObj?.eventsCount ?? data?.events?.length ?? 0} Events
                    </span>
                  </div>
                  {currentFileObj?.sha256 && (
                    <p className="text-[11px] text-slate-400 font-mono mt-1 select-all">
                      SHA-256 Checksum: <span className="text-slate-300">{currentFileObj.sha256}</span>
                    </p>
                  )}
                </div>
              </div>

              {/* Action Buttons for Individual File */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => setShowDeleteModal(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs font-mono font-bold transition-all shadow-[0_0_10px_rgba(225,29,72,0.2)]"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Delete File & Events
                </button>

                <button
                  onClick={handleDownloadCurrentFile}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download
                </button>

                <button
                  onClick={() => setSelectedFile('')}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white text-xs font-mono transition-colors"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  Back to All Files
                </button>
              </div>
            </div>

            {/* View Mode Tabs: Normalized Telemetry vs Raw Log File */}
            <div className="flex items-center gap-2 border-t border-slate-800/80 pt-3">
              <button
                onClick={() => setActiveTab('events')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors ${
                  activeTab === 'events'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                Normalized Event Logs ({data?.events?.length || 0})
              </button>

              <button
                onClick={handleLoadRawContent}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors ${
                  activeTab === 'raw'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                Raw Log File Content
              </button>
            </div>
          </div>

          {/* Individual Tab Content */}
          {activeTab === 'events' ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between font-mono text-xs text-slate-400">
                <span>Showing events exclusively from <strong className="text-cyan-400">{selectedFile}</strong></span>
                <span className="text-slate-500">Sorted by timestamp descending</span>
              </div>
              <EventTable events={data?.events || []} isLoading={isLoading} />
            </div>
          ) : (
            <div className="p-4 bg-[#0b0f19] border border-slate-800 rounded-xl space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between text-slate-400">
                <span>Raw Log Stream Content ({rawContent?.totalLines || 0} lines)</span>
                {rawContent?.isTruncated && <span className="text-amber-400">Showing first 2,000 lines</span>}
              </div>

              {isLoadingRaw ? (
                <div className="py-12 text-center">
                  <Spinner size="md" />
                  <p className="mt-2 text-slate-500 font-mono text-xs">Loading raw file stream...</p>
                </div>
              ) : rawContent?.error ? (
                <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300">
                  {rawContent.error}
                </div>
              ) : (
                <pre className="p-4 bg-[#070a10] border border-slate-800 rounded-xl text-xs text-emerald-400 overflow-x-auto max-h-[600px] leading-relaxed select-text font-mono">
                  {rawContent?.content || 'No raw content available.'}
                </pre>
              )}
            </div>
          )}
        </div>
      ) : (
        /* VIEW MODE 2: ALL FILES WORKSPACE (Uploader + Uploaded Files List + Global Telemetry) */
        <div className="space-y-8">
          {/* 1. Log Uploader Component */}
          <LogUploader onUploadSuccess={handleUploadSuccess} />

          {/* 2. Uploaded Files Archive Table */}
          <UploadedFilesList
            selectedFile={selectedFile}
            onSelectFile={(fileName) => handleSelectFile(fileName)}
            onFileDeleted={() => {
              queryClient.invalidateQueries({ queryKey: ['recentLogsEvents'] });
              refetchEvents();
              refetchFiles();
            }}
          />

          {/* 3. Global Telemetry Stream Table */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                  Recently Ingested Common Event Model Telemetry
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                Showing latest {data?.events?.length || 0} normalized records
              </span>
            </div>

            <EventTable events={data?.events || []} isLoading={isLoading} />
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal for Chosen File */}
      <Modal
        isOpen={showDeleteModal}
        onClose={() => setShowDeleteModal(false)}
        title="Confirm Log File Deletion"
        maxWidth="max-w-md"
      >
        <div className="space-y-4 font-mono text-xs">
          <div className="flex items-start gap-3 p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-400" />
            <div>
              <p className="font-semibold text-sm text-rose-200">Delete uploaded log file?</p>
              <p className="mt-1 text-slate-400 leading-relaxed">
                You are about to permanently delete <strong className="text-white underline">{selectedFile}</strong> and purge all its associated Common Event Model (CEM) records from the database.
              </p>
            </div>
          </div>

          <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800 text-slate-300">
            <span className="text-rose-400 font-bold block mb-1">Impact of Deletion:</span>
            <ul className="list-disc list-inside space-y-1 text-[11px] text-slate-400">
              <li>Purges all normalized security events parsed from this file.</li>
              <li>Removes the raw log file from disk archive.</li>
              <li>Updates all dashboard telemetry counts and alert correlation.</li>
            </ul>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setShowDeleteModal(false)}
              disabled={deleteMutation.isPending}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => deleteMutation.mutate(selectedFile)}
              disabled={deleteMutation.isPending}
              className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold flex items-center gap-1.5 shadow-[0_0_12px_rgba(225,29,72,0.4)] transition-all"
            >
              {deleteMutation.isPending ? <Spinner size="sm" /> : <Trash2 className="w-3.5 h-3.5" />}
              {deleteMutation.isPending ? 'Purging File & Events...' : 'Delete File & Events'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
