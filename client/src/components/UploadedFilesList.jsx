import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import {
  FolderArchive,
  FileText,
  Trash2,
  Eye,
  Download,
  Search,
  RefreshCw,
  HardDrive,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Copy,
  Check,
  X
} from 'lucide-react';
import Modal from './Modal';
import Spinner from './Spinner';
import { logsApi } from '../services/api';

export default function UploadedFilesList({ selectedFile, onSelectFile, onFileDeleted }) {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [previewFile, setPreviewFile] = useState(null);
  const [previewData, setPreviewData] = useState(null);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [purgeEvents, setPurgeEvents] = useState(true);
  const [copiedHash, setCopiedHash] = useState(false);

  // Fetch uploaded files
  const { data: files = [], isLoading, refetch, isFetching } = useQuery({
    queryKey: ['uploadedFiles'],
    queryFn: async () => {
      const res = await logsApi.getFiles();
      return res.data;
    }
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: async ({ id, fileName, purge }) => {
      if (fileName) {
        const res = await logsApi.deleteFileByName(fileName);
        return res.data;
      }
      const res = await logsApi.deleteFile(id, purge);
      return res.data;
    },
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['uploadedFiles'] });
      queryClient.invalidateQueries({ queryKey: ['recentLogsEvents'] });
      queryClient.invalidateQueries({ queryKey: ['eventsExplorer'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
      if (deleteTarget && selectedFile === deleteTarget.fileName) {
        onSelectFile('');
      } else if (variables.fileName && selectedFile === variables.fileName) {
        onSelectFile('');
      }
      setDeleteTarget(null);
      if (onFileDeleted) onFileDeleted();
    },
    onError: (err) => {
      alert('Failed to delete file: ' + (err.response?.data?.message || err.message));
    }
  });

  // Handle preview raw content
  const handleOpenPreview = async (file) => {
    setPreviewFile(file);
    setIsLoadingPreview(true);
    setPreviewData(null);
    try {
      const res = await logsApi.getRawContent(file._id);
      setPreviewData(res.data);
    } catch (err) {
      setPreviewData({ error: err.response?.data?.message || 'Unable to load file content.' });
    } finally {
      setIsLoadingPreview(false);
    }
  };

  // Handle download
  const handleDownload = async (file) => {
    try {
      const res = await logsApi.downloadFile(file._id);
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', file.fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download file: ' + (err.response?.data?.message || err.message));
    }
  };

  const handleCopyHash = (hash) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Filter files by search
  const filteredFiles = files.filter(f =>
    f.fileName.toLowerCase().includes(search.toLowerCase()) ||
    (f.format && f.format.toLowerCase().includes(search.toLowerCase())) ||
    (f.sha256 && f.sha256.toLowerCase().includes(search.toLowerCase()))
  );

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const totalBytes = files.reduce((acc, f) => acc + (f.fileSize || 0), 0);
  const totalEvents = files.reduce((acc, f) => acc + (f.eventsCount || 0), 0);

  return (
    <div className="space-y-4">
      {/* Archive Header & Summary Bar */}
      <div className="p-4 bg-[#0f1422] border border-slate-800 rounded-2xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <FolderArchive className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold font-mono text-slate-100 uppercase tracking-wide">
                Ingested Log Files Archive
              </h3>
              <span className="px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-300 text-[10px] font-mono">
                {files.length} {files.length === 1 ? 'file' : 'files'}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Select any file to inspect its normalized telemetry, view raw logs, or manage archives.
            </p>
          </div>
        </div>

        {/* Quick Stats & Refresh */}
        <div className="flex items-center gap-3 font-mono text-xs">
          <div className="hidden sm:flex items-center gap-3 px-3 py-1.5 rounded-xl bg-[#0a0d14] border border-slate-800 text-slate-400">
            <span>Total Events: <strong className="text-cyan-400">{totalEvents}</strong></span>
            <span className="text-slate-700">|</span>
            <span>Storage: <strong className="text-slate-200">{formatBytes(totalBytes)}</strong></span>
          </div>

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
            title="Refresh Files List"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Files Table Container */}
      <div className="bg-[#0b0f19] border border-slate-800 rounded-xl overflow-hidden font-mono text-xs">
        {/* Table Toolbar */}
        <div className="p-3 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
          <div className="relative w-full sm:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search by file name or hash..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-[#070a10] border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {selectedFile && (
            <div className="flex items-center gap-2 bg-cyan-950/40 border border-cyan-800/60 px-2.5 py-1 rounded-lg text-cyan-300">
              <Eye className="w-3.5 h-3.5" />
              <span>Checking logs for: <strong>{selectedFile}</strong></span>
              <button
                onClick={() => onSelectFile('')}
                className="ml-1 p-0.5 hover:bg-cyan-900/60 rounded text-cyan-400 hover:text-white"
                title="Clear file filter"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#070a10] border-b border-slate-800/80 text-[11px] uppercase text-slate-400">
              <tr>
                <th className="px-4 py-3">File Name & SHA-256</th>
                <th className="px-4 py-3">Format</th>
                <th className="px-4 py-3">Size</th>
                <th className="px-4 py-3">Events Ingested</th>
                <th className="px-4 py-3">Archive Status</th>
                <th className="px-4 py-3">Ingested At</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center">
                    <Spinner size="md" />
                    <p className="mt-2 text-slate-500">Loading ingested files...</p>
                  </td>
                </tr>
              ) : filteredFiles.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    {search ? `No log files found matching "${search}".` : 'No log files in archive yet.'}
                  </td>
                </tr>
              ) : (
                filteredFiles.map((file) => {
                  const isSelected = selectedFile === file.fileName;
                  return (
                    <tr
                      key={file._id}
                      className={`hover:bg-[#121828] transition-colors ${
                        isSelected ? 'bg-cyan-950/20 border-l-2 border-cyan-400' : ''
                      }`}
                    >
                      {/* Name & Hash */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <FileText className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                          <div>
                            <span className="font-semibold text-slate-200 block truncate max-w-xs" title={file.fileName}>
                              {file.fileName}
                            </span>
                            {file.sha256 && (
                              <span
                                onClick={() => handleCopyHash(file.sha256)}
                                className="text-[10px] text-slate-500 hover:text-cyan-400 cursor-pointer flex items-center gap-1 font-mono transition-colors"
                                title="Click to copy full SHA-256"
                              >
                                SHA-256: {file.sha256.substring(0, 16)}...
                                {copiedHash ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                              </span>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Format */}
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700 text-[10px] uppercase font-bold text-slate-300">
                          {file.format || 'text'}
                        </span>
                      </td>

                      {/* Size */}
                      <td className="px-4 py-3 text-slate-400">
                        {formatBytes(file.fileSize)}
                      </td>

                      {/* Events Ingested */}
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/80 text-cyan-400 font-bold">
                          +{file.eventsCount} events
                        </span>
                      </td>

                      {/* Archive Status */}
                      <td className="px-4 py-3">
                        {file.isSaved ? (
                          <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
                            <HardDrive className="w-3 h-3 text-emerald-400" />
                            Archived
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] text-slate-500">
                            Ephemeral
                          </span>
                        )}
                      </td>

                      {/* Timestamp */}
                      <td className="px-4 py-3 text-slate-400 text-[11px]">
                        {file.createdAt ? format(new Date(file.createdAt), 'yyyy-MM-dd HH:mm') : '-'}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* Check Logs button */}
                          <button
                            onClick={() => onSelectFile(isSelected ? '' : file.fileName)}
                            className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1 transition-all ${
                              isSelected
                                ? 'bg-cyan-500 text-black shadow-[0_0_10px_rgba(6,182,212,0.4)]'
                                : 'bg-slate-800 hover:bg-cyan-500/20 text-slate-200 hover:text-cyan-400 border border-slate-700 hover:border-cyan-500/40'
                            }`}
                            title="Filter and check normalized logs from this file"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            {isSelected ? 'Viewing' : 'Check Logs'}
                          </button>

                          {/* Raw Preview button */}
                          <button
                            onClick={() => handleOpenPreview(file)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
                            title="Inspect raw log file content"
                          >
                            <FileCode className="w-3.5 h-3.5" />
                          </button>

                          {/* Download button */}
                          <button
                            onClick={() => handleDownload(file)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
                            title="Download raw file"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>

                          {/* Delete button */}
                          <button
                            onClick={() => setDeleteTarget(file)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950/60 hover:text-rose-400 text-slate-500 transition-colors"
                            title="Delete file and optionally purge its events"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Log Preview Modal */}
      <Modal
        isOpen={Boolean(previewFile)}
        onClose={() => setPreviewFile(null)}
        title={`Raw Log Inspector: ${previewFile?.fileName || ''}`}
        maxWidth="max-w-4xl"
      >
        {previewFile && (
          <div className="space-y-4 font-mono text-xs">
            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <div>
                <span className="text-slate-500 uppercase text-[10px] block">Forensic Checksum (SHA-256)</span>
                <span className="text-cyan-400 text-xs select-all">{previewFile.sha256 || 'None'}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-slate-400">Size: <strong className="text-slate-200">{formatBytes(previewFile.fileSize)}</strong></span>
                <button
                  onClick={() => handleDownload(previewFile)}
                  className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" /> Download
                </button>
              </div>
            </div>

            {isLoadingPreview ? (
              <div className="py-12 text-center">
                <Spinner size="md" />
                <p className="mt-2 text-slate-500">Reading raw log payload...</p>
              </div>
            ) : previewData?.error ? (
              <div className="p-4 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300">
                {previewData.error}
              </div>
            ) : (
              <div>
                <div className="flex items-center justify-between text-[11px] text-slate-500 mb-1">
                  <span>Raw Stream Preview ({previewData?.totalLines || 0} lines)</span>
                  {previewData?.isTruncated && <span className="text-amber-400">Showing first 2,000 lines</span>}
                </div>
                <pre className="p-4 bg-[#070a10] border border-slate-800 rounded-xl text-xs text-emerald-400 overflow-x-auto max-h-96 leading-relaxed select-text font-mono">
                  {previewData?.content || 'No content available'}
                </pre>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={Boolean(deleteTarget)}
        onClose={() => setDeleteTarget(null)}
        title="Confirm Log File Deletion"
        maxWidth="max-w-md"
      >
        {deleteTarget && (
          <div className="space-y-4 font-mono text-xs">
            <div className="flex items-start gap-3 p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300">
              <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-400" />
              <div>
                <p className="font-semibold text-sm text-rose-200">Delete uploaded log file?</p>
                <p className="mt-1 text-slate-400 leading-relaxed">
                  You are about to delete <strong className="text-slate-200">{deleteTarget.fileName}</strong> from storage archive.
                </p>
              </div>
            </div>

            {/* Checkbox to purge events */}
            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={purgeEvents}
                  onChange={(e) => setPurgeEvents(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-700 text-rose-500 focus:ring-rose-500/40 mt-0.5 w-4 h-4"
                />
                <div>
                  <span className="text-slate-200 font-bold block">
                    Purge all associated events ({deleteTarget.eventsCount} records)
                  </span>
                  <span className="text-[11px] text-slate-400 leading-tight block mt-0.5">
                    Also remove all Common Event Model (CEM) records ingested from this specific file.
                  </span>
                </div>
              </label>
            </div>

            {/* Action buttons */}
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => deleteMutation.mutate({ id: deleteTarget._id, fileName: deleteTarget.fileName, purge: purgeEvents })}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold flex items-center gap-1.5 shadow-[0_0_12px_rgba(225,29,72,0.4)] transition-all"
              >
                {deleteMutation.isPending ? <Spinner size="sm" /> : <Trash2 className="w-3.5 h-3.5" />}
                {deleteMutation.isPending ? 'Deleting...' : 'Delete File'}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
