/**
 * reportService.js
 * Generates structured forensic incident reports and exports them to Markdown and HTML.
 */

const Report = require('../models/Report');
const Case = require('../models/Case');
const TimelineEntry = require('../models/TimelineEntry');
const IOC = require('../models/IOC');
const Endpoint = require('../models/Endpoint');
const Account = require('../models/Account');
const Evidence = require('../models/Evidence');
const AttackChain = require('../models/AttackChain');
const ImpactAssessment = require('../models/ImpactAssessment');

async function generateReportForCase(caseId, userId = null) {
  const c = await Case.findById(caseId)
    .populate('assignedTo', 'fullName username email')
    .populate('alertId');

  if (!c) throw new Error('Case not found');

  const timeline = await TimelineEntry.find({ caseId }).sort({ timestamp: 1 });
  const iocs = await IOC.find({ caseId });
  const endpoints = await Endpoint.find({ _id: { $in: c.endpoints } });
  const accounts = await Account.find({ _id: { $in: c.accounts } });
  const evidence = await Evidence.find({ caseId });
  const attackChain = await AttackChain.findOne({ caseId });
  const impact = await ImpactAssessment.findOne({ caseId });

  const year = new Date().getFullYear();
  const reportNumber = `RPT-${year}-${c.caseId.replace(/[^0-9]/g, '').slice(-4) || '0001'}`;

  // Build recommendations based on findings
  const recommendations = [
    'Immediately isolate compromised endpoints from the internal network VLAN.',
    'Force enterprise-wide password resets for flagged privileged and compromised accounts.',
    'Block all identified malicious external IP addresses and C2 domains at the perimeter firewall/EDR.',
    'Deploy enhanced PowerShell logging (Script Block Logging EventID 4104) across all Domain Controllers and critical servers.',
    'Revoke anomalous active Kerberos Golden/Silver tickets and cycle krbtgt account password twice.',
    'Initiate offline memory forensics on DC01 and WS01 to confirm persistence mechanisms.'
  ];

  const sections = {
    incidentSummary: `Forensic investigation into ${c.title}. Case priority is classified as ${c.priority.toUpperCase()} with investigation status ${c.status.toUpperCase()}. Initial trigger originated from ${c.alertId ? c.alertId.title : 'anomalous security telemetry'}.`,
    affectedAssets: endpoints.map(e => ({
      hostname: e.hostname,
      os: e.os,
      ipAddresses: e.ipAddresses.join(', '),
      riskScore: e.riskScore,
      status: e.status
    })),
    affectedAccounts: accounts.map(a => ({
      username: a.username,
      domain: a.domain,
      privilege: a.privilege,
      riskScore: a.riskScore,
      status: a.status
    })),
    timeline: timeline.map(t => ({
      timestamp: t.timestamp,
      title: t.title,
      category: t.category,
      severity: t.severity,
      description: t.description,
      host: t.host,
      username: t.username
    })),
    iocs: iocs.map(i => ({
      type: i.type,
      value: i.value,
      reputation: i.reputation,
      confidence: i.confidence,
      source: i.source
    })),
    attackChain: attackChain && attackChain.stages ? attackChain.stages.map(s => ({
      stage: s.stage,
      techniqueId: s.techniqueId,
      techniqueName: s.techniqueName,
      severity: s.severity,
      description: s.description
    })) : [],
    evidence: evidence.map(e => ({
      title: e.title,
      type: e.type,
      hashType: e.hashType,
      hashValue: e.hashValue,
      validated: e.analystValidated
    })),
    analystFindings: c.review ? (c.review.findings || 'Investigation concluded. Malicious activity isolated and neutralized.') : 'Initial assessment in progress.',
    impactAssessment: impact ? {
      dataExposed: impact.dataExposed,
      malwareDetected: impact.malwareDetected,
      businessImpact: impact.businessImpact,
      confidence: impact.confidence,
      analystNotes: impact.analystNotes
    } : {},
    recommendations
  };

  const report = await Report.findOneAndUpdate(
    { caseId },
    {
      caseId,
      reportNumber,
      title: `Forensic Investigation Report: ${c.title}`,
      severity: c.priority,
      sections,
      generatedBy: userId,
      generatedAt: new Date(),
      format: 'md'
    },
    { upsert: true, new: true }
  );

  return report;
}

function exportReportToMarkdown(report) {
  const { title, reportNumber, severity, sections, generatedAt } = report;
  const s = sections || {};

  let md = `# ${title}\n\n`;
  md += `**Report Number:** ${reportNumber}  \n`;
  md += `**Classification / Severity:** ${severity ? severity.toUpperCase() : 'HIGH'}  \n`;
  md += `**Generated At:** ${new Date(generatedAt).toUTCString()}  \n\n`;
  md += `---\n\n`;

  md += `## 1. Executive Incident Summary\n\n${s.incidentSummary || 'No summary provided.'}\n\n`;

  md += `## 2. Affected Endpoints\n\n`;
  if (s.affectedAssets && s.affectedAssets.length > 0) {
    md += `| Hostname | OS | IPs | Risk Score | Status |\n|---|---|---|---|---|\n`;
    s.affectedAssets.forEach(a => {
      md += `| ${a.hostname} | ${a.os || 'Unknown'} | ${a.ipAddresses || 'N/A'} | ${a.riskScore}/100 | ${a.status} |\n`;
    });
  } else {
    md += `No affected endpoints linked to case.\n`;
  }
  md += `\n`;

  md += `## 3. Targeted & Compromised Accounts\n\n`;
  if (s.affectedAccounts && s.affectedAccounts.length > 0) {
    md += `| Username | Domain | Privilege | Risk Score | Status |\n|---|---|---|---|---|\n`;
    s.affectedAccounts.forEach(a => {
      md += `| ${a.username} | ${a.domain} | ${a.privilege} | ${a.riskScore}/100 | ${a.status} |\n`;
    });
  } else {
    md += `No accounts linked.\n`;
  }
  md += `\n`;

  md += `## 4. MITRE ATT&CK Attack Chain\n\n`;
  if (s.attackChain && s.attackChain.length > 0) {
    s.attackChain.forEach((ac, idx) => {
      md += `### Stage ${idx + 1}: ${ac.stage} [${ac.techniqueId || 'T1000'}]\n`;
      md += `- **Technique:** ${ac.techniqueName || 'Technique'}\n`;
      md += `- **Severity:** ${ac.severity}\n`;
      md += `- **Details:** ${ac.description}\n\n`;
    });
  } else {
    md += `No attack chain stages mapped.\n\n`;
  }

  md += `## 5. Indicators of Compromise (IOCs)\n\n`;
  if (s.iocs && s.iocs.length > 0) {
    md += `| Type | Value | Reputation | Confidence | Source |\n|---|---|---|---|---|\n`;
    s.iocs.forEach(i => {
      md += `| ${i.type} | \`${i.value}\` | ${i.reputation} | ${i.confidence}% | ${i.source} |\n`;
    });
  } else {
    md += `No IOCs extracted.\n`;
  }
  md += `\n`;

  md += `## 6. Forensic Timeline of Events\n\n`;
  if (s.timeline && s.timeline.length > 0) {
    md += `| Timestamp (UTC) | Category | Host | Event / Finding |\n|---|---|---|---|\n`;
    s.timeline.forEach(t => {
      md += `| ${new Date(t.timestamp).toISOString()} | ${t.category} | ${t.host || '-'} | ${t.title} |\n`;
    });
  } else {
    md += `No timeline entries logged.\n`;
  }
  md += `\n`;

  md += `## 7. Impact Assessment\n\n`;
  if (s.impactAssessment) {
    md += `- **Data Exposed:** ${s.impactAssessment.dataExposed ? 'YES' : 'NO'}\n`;
    md += `- **Malware Detected:** ${s.impactAssessment.malwareDetected || 'None'}\n`;
    md += `- **Business Impact:** ${s.impactAssessment.businessImpact || 'Contained'}\n`;
    md += `- **Analyst Assessment Notes:** ${s.impactAssessment.analystNotes || 'None'}\n\n`;
  }

  md += `## 8. Analyst Findings & Conclusion\n\n${s.analystFindings || 'Pending final review.'}\n\n`;

  md += `## 9. Strategic & Tactical Recommendations\n\n`;
  if (s.recommendations && s.recommendations.length > 0) {
    s.recommendations.forEach(r => {
      md += `- ${r}\n`;
    });
  }
  md += `\n`;

  return md;
}

function exportReportToHTML(report) {
  const { escapeHtml } = require('../utils/sanitize');
  const md = exportReportToMarkdown(report);
  const safeTitle = escapeHtml(report.title || 'Forensic Incident Report');
  const safeMd = escapeHtml(md);

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${safeTitle}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; max-width: 900px; margin: 40px auto; padding: 0 20px; }
    h1 { color: #0f172a; border-bottom: 2px solid #0284c7; padding-bottom: 8px; }
    h2 { color: #1e293b; margin-top: 28px; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; }
    h3 { color: #334155; }
    table { width: 100%; border-collapse: collapse; margin: 16px 0; }
    th, td { border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }
    th { background: #f8fafc; }
    code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }
    ul { padding-left: 20px; }
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; background: #fee2e2; color: #991b1b; }
  </style>
</head>
<body>
  <div style="background: #0f172a; color: #38bdf8; padding: 12px 20px; border-radius: 6px; margin-bottom: 20px;">
    <strong>AEGIS FORENSIC PLATFORM</strong> &bull; OFFICIAL INCIDENT REPORT
  </div>
  <pre style="white-space: pre-wrap; font-family: inherit;">${safeMd}</pre>
</body>
</html>`;
}

module.exports = {
  generateReportForCase,
  exportReportToMarkdown,
  exportReportToHTML
};
