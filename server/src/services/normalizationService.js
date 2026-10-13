/**
 * normalizationService.js
 * Normalizes disparate parsed event objects into the Common Event Model (CEM).
 * Handles heterogeneous schemas, date formats, Windows Security events, Syslog, and custom fields.
 */

const VALID_SOURCES = ['windows', 'linux', 'network', 'dns', 'firewall', 'application', 'cloud', 'edr'];
const VALID_EVENT_TYPES = ['authentication', 'process', 'file', 'network', 'dns', 'registry', 'other'];
const VALID_ACTIONS = ['login', 'logout', 'create', 'delete', 'execute', 'connect', 'failed', 'success', 'modify'];
const VALID_STATUSES = ['success', 'failed', 'in_allowed_list'];
const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];

/**
 * Robust date parser supporting ISO 8601, DD-MM-YYYY, DD/MM/YYYY, MM/DD/YYYY, Syslog, and Epoch.
 */
function parseTimestamp(rawTs) {
  if (!rawTs) return new Date();
  if (rawTs instanceof Date && !isNaN(rawTs.getTime())) return rawTs;
  if (typeof rawTs === 'number') {
    return new Date(rawTs > 1e11 ? rawTs : rawTs * 1000);
  }

  const str = String(rawTs).trim();
  if (!str) return new Date();

  // 1. Standard ISO / RFC format
  let d = new Date(str);
  if (!isNaN(d.getTime())) return d;

  // 2. DD-MM-YYYY or DD/MM/YYYY with optional time (common in Windows Event exports, e.g. "23-06-2026 10:13:31")
  const dmyMatch = str.match(/^(\d{1,2})[-\/](\d{1,2})[-\/](\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
  if (dmyMatch) {
    const day = parseInt(dmyMatch[1], 10);
    const month = parseInt(dmyMatch[2], 10) - 1;
    const year = parseInt(dmyMatch[3], 10);
    const hours = parseInt(dmyMatch[4] || '0', 10);
    const minutes = parseInt(dmyMatch[5] || '0', 10);
    const seconds = parseInt(dmyMatch[6] || '0', 10);
    d = new Date(Date.UTC(year, month, day, hours, minutes, seconds));
    if (!isNaN(d.getTime())) return d;
  }

  // 3. YYYY-MM-DD or YYYY/MM/DD
  const ymdMatch = str.match(/^(\d{4})[-\/](\d{1,2})[-\/](\d{1,2})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
  if (ymdMatch) {
    const year = parseInt(ymdMatch[1], 10);
    const month = parseInt(ymdMatch[2], 10) - 1;
    const day = parseInt(ymdMatch[3], 10);
    const hours = parseInt(ymdMatch[4] || '0', 10);
    const minutes = parseInt(ymdMatch[5] || '0', 10);
    const seconds = parseInt(ymdMatch[6] || '0', 10);
    d = new Date(Date.UTC(year, month, day, hours, minutes, seconds));
    if (!isNaN(d.getTime())) return d;
  }

  // 4. Syslog format: "Mmm dd hh:mm:ss"
  const syslogMatch = str.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
  if (syslogMatch) {
    const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
    const month = months[syslogMatch[1]];
    if (month !== undefined) {
      const day = parseInt(syslogMatch[2], 10);
      const year = new Date().getFullYear();
      d = new Date(Date.UTC(year, month, day, parseInt(syslogMatch[3], 10), parseInt(syslogMatch[4], 10), parseInt(syslogMatch[5], 10)));
      if (!isNaN(d.getTime())) return d;
    }
  }

  return new Date();
}

/**
 * Prevent CSV formula injection (OWASP A03)
 */
function sanitizeStringForExport(val) {
  if (typeof val !== 'string') return val;
  const trimmed = val.trim();
  if (/^[=+\-@\t\r]/.test(trimmed)) {
    return `'${trimmed}`;
  }
  return val;
}

function normalizeRecord(raw, fileName = '') {
  const rawObj = raw || {};
  const messageText = (rawObj.message || rawObj.description || rawObj._rawLine || '').toString();

  // 1. Timestamp extraction
  const rawTimeStr = rawObj.timestamp || rawObj.Time || rawObj.time ||
    rawObj['Date and Time'] || rawObj['date and time'] || rawObj['Date & Time'] ||
    rawObj.event_time || rawObj.EventTime || rawObj.eventTime ||
    rawObj.datetime || rawObj.date || rawObj['@timestamp'] || rawObj.syslogTime;
  const timestamp = parseTimestamp(rawTimeStr);

  // 2. Event ID (Windows / Syslog)
  const eventId = String(rawObj['Event ID'] || rawObj.EventID || rawObj.eventId || rawObj.event_id || '').trim();

  // 3. Source determination
  let source = (
    rawObj.source || rawObj.Source || rawObj.src_type || rawObj.log_source || rawObj.sourcetype || ''
  ).toLowerCase();

  if (!source) {
    const fn = (fileName || '').toLowerCase();
    if (fn.includes('windows') || fn.includes('security') || rawObj['Task Category'] || eventId) {
      source = 'windows';
    } else if (fn.includes('syslog') || fn.includes('ssh') || fn.includes('linux')) {
      source = 'linux';
    } else if (fn.includes('vpn') || rawObj.index === 'VPN_Logs') {
      source = 'network';
    } else {
      source = 'windows';
    }
  }

  if (!VALID_SOURCES.includes(source)) {
    if (source.includes('win') || source.includes('microsoft')) source = 'windows';
    else if (source.includes('lin') || source.includes('syslog') || source.includes('auth')) source = 'linux';
    else if (source.includes('net') || source.includes('vpn') || source.includes('pcap')) source = 'network';
    else if (source.includes('dns')) source = 'dns';
    else if (source.includes('fire') || source.includes('fw')) source = 'firewall';
    else if (source.includes('edr') || source.includes('crowd') || source.includes('sentinel')) source = 'edr';
    else if (source.includes('cloud') || source.includes('aws') || source.includes('azure')) source = 'cloud';
    else source = 'windows';
  }

  // 4. Host identification
  let host = (
    rawObj.host || rawObj.hostname || rawObj.ComputerName || rawObj['Computer Name'] ||
    rawObj.computer || rawObj.dhost || rawObj.device_name || rawObj.server || ''
  ).toString().trim();

  if (!host && messageText) {
    const domainMatch = messageText.match(/Account Domain:\s*([^\r\n\t]+)/);
    const compMatch = messageText.match(/(?:Computer Name|Workstation Name):\s*([^\r\n\t]+)/);
    if (compMatch && compMatch[1] && compMatch[1].trim() !== '-') {
      host = compMatch[1].trim();
    } else if (domainMatch && domainMatch[1] && domainMatch[1].trim() !== '-' && domainMatch[1].trim() !== 'WORKGROUP') {
      host = domainMatch[1].trim();
    }
  }
  if (!host) host = 'DC01';

  // 5. Username identification
  let username = (
    rawObj.username || rawObj.user || rawObj.UserName || rawObj.TargetUserName ||
    rawObj['Target Account Name'] || rawObj['Account Name'] || rawObj.account ||
    rawObj.user_name || rawObj.suser || rawObj.identity || ''
  ).toString().trim();

  if ((!username || username === '-' || username === 'SYSTEM') && messageText) {
    const acctMatches = [...messageText.matchAll(/Account Name:\s*([^\r\n\t]+)/g)].map(m => m[1].trim());
    // Find first non-system, non-machine account
    const validAcct = acctMatches.find(a => a && a !== '-' && a !== 'SYSTEM' && !a.endsWith('$'));
    if (validAcct) {
      username = validAcct;
    } else if (acctMatches.length > 0 && acctMatches[0] !== '-') {
      username = acctMatches[0];
    }
  }
  if (!username) username = 'SYSTEM';

  // 6. Source IP identification
  let sourceIP = (
    rawObj.sourceIP || rawObj.source_ip || rawObj.Source_ip || rawObj.src_ip ||
    rawObj.src || rawObj.srcip || rawObj.source_ip || rawObj.IpAddress ||
    rawObj.client_ip || rawObj.src_addr || rawObj['Source Network Address'] ||
    rawObj['Client Address'] || ''
  ).toString().trim();

  if (!sourceIP && messageText) {
    const ipMatch = messageText.match(/Source Network Address:\s*([0-9\.]+)/) ||
      messageText.match(/from ([0-9\.]+) port/i);
    if (ipMatch) sourceIP = ipMatch[1].trim();
  }
  if (sourceIP === '-' || sourceIP === '::1' || sourceIP === '127.0.0.1') {
    // Keep structured value
  }

  // 7. Destination IP identification
  let destinationIP = (
    rawObj.destinationIP || rawObj.destination_ip || rawObj.dst_ip || rawObj.dst ||
    rawObj.dstip || rawObj.dest_ip || rawObj.server_ip || rawObj.dst_addr ||
    rawObj.Target_ip || rawObj['Destination Network Address'] || ''
  ).toString().trim();

  if (!destinationIP && messageText) {
    const dstIpMatch = messageText.match(/Destination Network Address:\s*([0-9\.]+)/) ||
      messageText.match(/to ([0-9\.]+) port/i);
    if (dstIpMatch) destinationIP = dstIpMatch[1].trim();
  }

  // 8. Ports
  const sourcePort = parseInt(
    rawObj.sourcePort || rawObj.src_port || rawObj.srcport || rawObj.spt ||
    rawObj.source_port || rawObj['Source Port'] || 0, 10
  ) || null;

  const destinationPort = parseInt(
    rawObj.destinationPort || rawObj.dst_port || rawObj.dstport || rawObj.dpt ||
    rawObj.dest_port || rawObj.port || rawObj['Destination Port'] || 0, 10
  ) || null;

  // 9. Event Type determination
  let eventType = (
    rawObj.eventType || rawObj.event_type || rawObj.category ||
    rawObj['Task Category'] || rawObj.type || ''
  ).toLowerCase();

  if (eventId) {
    if (['4624', '4625', '4648', '4768', '4769', '4776'].includes(eventId)) eventType = 'authentication';
    else if (['4688', '4689'].includes(eventId)) eventType = 'process';
    else if (['4663', '4656', '4660'].includes(eventId)) eventType = 'file';
    else if (['5156', '5157', '5158'].includes(eventId)) eventType = 'network';
    else if (['4657'].includes(eventId)) eventType = 'registry';
    else if (['4720', '4726', '4738', '4798', '5379'].includes(eventId)) eventType = 'other';
  }

  if (rawObj.index === 'VPN_Logs') eventType = 'network';

  if (!VALID_EVENT_TYPES.includes(eventType)) {
    if (eventType.includes('auth') || eventType.includes('logon')) eventType = 'authentication';
    else if (eventType.includes('proc') || eventType.includes('exec')) eventType = 'process';
    else if (eventType.includes('file')) eventType = 'file';
    else if (eventType.includes('net') || eventType.includes('conn') || eventType.includes('vpn')) eventType = 'network';
    else if (eventType.includes('dns') || eventType.includes('domain')) eventType = 'dns';
    else if (eventType.includes('reg')) eventType = 'registry';
    else eventType = 'other';
  }

  // 10. Action determination
  let action = (rawObj.action || rawObj.act || rawObj.command || '').toLowerCase();
  if (action === 'built') action = 'connect';
  else if (action === 'teardown') action = 'logout';
  else if (eventId === '4624' || eventId === '4625') action = 'login';
  else if (eventId === '4688') action = 'execute';
  else if (eventId === '4720') action = 'create';
  else if (eventId === '4726') action = 'delete';
  else if (['4798', '5379', '4738'].includes(eventId)) action = 'modify';

  if (!VALID_ACTIONS.includes(action)) {
    if (action.includes('login') || action.includes('logon')) action = 'login';
    else if (action.includes('logout') || action.includes('logoff')) action = 'logout';
    else if (action.includes('exec') || action.includes('spawn') || action.includes('run')) action = 'execute';
    else if (action.includes('creat')) action = 'create';
    else if (action.includes('del')) action = 'delete';
    else if (action.includes('conn')) action = 'connect';
    else if (action.includes('fail')) action = 'failed';
    else if (action.includes('succ')) action = 'success';
    else if (action.includes('mod')) action = 'modify';
    else action = eventType === 'authentication' ? 'login' : 'execute';
  }

  // 11. Status determination
  let status = (rawObj.status || rawObj.result || rawObj.outcome || '').toLowerCase();
  const keywords = (rawObj.Keywords || rawObj.keywords || '').toString();

  if (keywords.includes('Audit Failure') || eventId === '4625') {
    status = 'failed';
  } else if (keywords.includes('Audit Success') || eventId === '4624') {
    status = 'success';
  }

  if (!VALID_STATUSES.includes(status)) {
    if (status.includes('fail') || status.includes('den') || status.includes('err') || action === 'failed' || messageText.toLowerCase().includes('failure')) {
      status = 'failed';
    } else if (status.includes('allow') || status.includes('permit') || status.includes('white')) {
      status = 'in_allowed_list';
    } else {
      status = 'success';
    }
  }

  // 12. Severity determination
  let severity = (rawObj.severity || rawObj.level || rawObj.priority || '').toLowerCase();
  if (!VALID_SEVERITIES.includes(severity)) {
    if (severity.includes('crit') || severity.includes('fatal')) severity = 'critical';
    else if (severity.includes('high') || severity.includes('warn') || status === 'failed' || eventId === '4625') severity = 'high';
    else if (severity.includes('med') || eventId === '5379' || eventId === '4720') severity = 'medium';
    else severity = 'low';
  }

  // 13. Technique ID (MITRE ATT&CK mapping)
  let techniqueId = (
    rawObj.techniqueId || rawObj.technique || rawObj.mitre || rawObj.mitreTechniqueId || ''
  ).toString().trim();

  if (!techniqueId && eventId) {
    if (eventId === '4625') techniqueId = 'T1110';
    else if (eventId === '4624') techniqueId = 'T1078';
    else if (eventId === '5379') techniqueId = 'T1555';
    else if (eventId === '4798') techniqueId = 'T1087';
    else if (eventId === '4688') techniqueId = 'T1059';
  }

  // 14. Description construction & sanitization
  let description = rawObj.description || rawObj.message || rawObj['Task Category'] || rawObj.EventData || rawObj._rawLine || '';
  if (!description) {
    description = `${eventType.toUpperCase()} event on ${host} by ${username} (${action} ${status})`;
  }
  description = sanitizeStringForExport(description);

  // 15. Tags collection
  const tags = Array.isArray(rawObj.tags) ? [...rawObj.tags] : [];
  if (techniqueId && !tags.includes(techniqueId)) tags.push(techniqueId);
  if (source && !tags.includes(source)) tags.push(source);
  if (eventType && !tags.includes(eventType)) tags.push(eventType);
  if (eventId && !tags.includes(`EventID:${eventId}`)) tags.push(`EventID:${eventId}`);

  return {
    timestamp,
    source,
    host,
    username,
    sourceIP,
    destinationIP,
    sourcePort,
    destinationPort,
    eventType,
    action,
    status,
    severity,
    raw: rawObj,
    rawFile: fileName,
    techniqueId,
    description,
    tags
  };
}

function normalizeRecords(rawRecords, fileName = '') {
  if (!Array.isArray(rawRecords)) return [];
  return rawRecords.map(r => normalizeRecord(r, fileName));
}

module.exports = {
  normalizeRecord,
  normalizeRecords,
  parseTimestamp,
  sanitizeStringForExport
};
