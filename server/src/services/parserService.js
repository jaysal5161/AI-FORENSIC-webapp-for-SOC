/**
 * parserService.js
 * Automatically parses raw log contents from CSV (RFC 4180), JSON/NDJSON, and TXT/LOG formats.
 * Fully supports multi-line quoted fields, escaped quotes, UTF-8 BOM, and disparate column orders.
 */

function stripBOM(content) {
  if (!content) return '';
  const str = typeof content === 'string' ? content : content.toString('utf8');
  if (str.charCodeAt(0) === 0xFEFF) {
    return str.slice(1);
  }
  return str;
}

/**
 * Robust RFC 4180-compliant CSV parser.
 * Correctly handles:
 * - Newlines (\r\n and \n) embedded inside quotes
 * - Escaped quotation marks ("") inside quotes
 * - Commas embedded inside quotes
 * - Empty fields and arbitrary column counts
 * - Trailing/leading whitespace and carriage returns
 */
function parseCSV(content) {
  const cleanContent = stripBOM(content);
  if (!cleanContent || cleanContent.trim().length === 0) return [];

  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  let i = 0;
  const len = cleanContent.length;

  while (i < len) {
    const char = cleanContent[i];

    if (inQuotes) {
      if (char === '"') {
        if (i + 1 < len && cleanContent[i + 1] === '"') {
          // Escaped quote: "" inside quoted string
          field += '"';
          i += 2;
          continue;
        } else {
          // Closing quote
          inQuotes = false;
          i++;
          continue;
        }
      } else {
        // Any character inside quotes (including \n, \r, commas)
        field += char;
        i++;
        continue;
      }
    }

    if (char === '"') {
      inQuotes = true;
      i++;
    } else if (char === ',') {
      row.push(field.trim());
      field = '';
      i++;
    } else if (char === '\r') {
      if (i + 1 < len && cleanContent[i + 1] === '\n') {
        i++;
      }
      row.push(field.trim());
      // Only keep non-empty rows
      if (row.some(val => val.length > 0)) {
        rows.push(row);
      }
      row = [];
      field = '';
      i++;
    } else if (char === '\n') {
      row.push(field.trim());
      if (row.some(val => val.length > 0)) {
        rows.push(row);
      }
      row = [];
      field = '';
      i++;
    } else {
      field += char;
      i++;
    }
  }

  // Handle remaining field/row at EOF
  if (field.length > 0 || row.length > 0) {
    row.push(field.trim());
    if (row.some(val => val.length > 0)) {
      rows.push(row);
    }
  }

  if (rows.length < 2) return [];

  // Parse header row
  const rawHeaders = rows[0].map(h => h.replace(/^["']|["']$/g, '').trim());
  const headers = rawHeaders.filter(h => h.length > 0);
  if (headers.length === 0) return [];

  const records = [];

  for (let r = 1; r < rows.length; r++) {
    const values = rows[r];
    if (values.length === 0 || !values.some(v => v.length > 0)) continue;

    const record = {};

    headers.forEach((header, idx) => {
      let val = values[idx] !== undefined ? values[idx] : '';
      val = val.replace(/^["']|["']$/g, '').trim();
      record[header] = val;
    });

    // If row has more columns than headers (common in Windows Event Viewer exports
    // where the event description / details are in an un-named trailing column)
    if (values.length > headers.length) {
      for (let extraIdx = headers.length; extraIdx < values.length; extraIdx++) {
        const extraVal = (values[extraIdx] || '').replace(/^["']|["']$/g, '').trim();
        if (extraIdx === headers.length && !record.message && !record.description) {
          record.message = extraVal;
        } else {
          record[`extra_column_${extraIdx + 1}`] = extraVal;
        }
      }
    }

    record._rawLine = values.join(',');
    records.push(record);
  }

  return records;
}

/**
 * Robust JSON parser supporting arrays, single objects, wrapped envelopes, and NDJSON.
 */
function parseJSON(content) {
  const cleanContent = stripBOM(content).trim();
  if (!cleanContent) return [];

  // 1. JSON Array
  if (cleanContent.startsWith('[') && cleanContent.endsWith(']')) {
    try {
      const parsed = JSON.parse(cleanContent);
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch (e) {}
  }

  // 2. Line-delimited JSON (NDJSON)
  const lines = cleanContent.split(/\r?\n/).filter(l => l.trim().length > 0);
  const ndjsonRecords = [];
  let validNdjsonLines = 0;

  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;
    try {
      const item = JSON.parse(trimmedLine);
      if (item && typeof item === 'object') {
        ndjsonRecords.push(item);
        validNdjsonLines++;
      }
    } catch (e) {
      // Not a valid JSON line
    }
  }

  // If majority of lines parsed as valid JSON objects, return NDJSON
  if (validNdjsonLines > 0 && validNdjsonLines >= lines.length * 0.5) {
    return ndjsonRecords;
  }

  // 3. Single JSON Object or Enveloped JSON
  try {
    const single = JSON.parse(cleanContent);
    if (Array.isArray(single)) return single;
    if (single && typeof single === 'object') {
      // Check for common wrapper properties
      if (Array.isArray(single.events)) return single.events;
      if (Array.isArray(single.logs)) return single.logs;
      if (Array.isArray(single.records)) return single.records;
      if (Array.isArray(single.data)) return single.data;
      if (single.hits && Array.isArray(single.hits.hits)) {
        return single.hits.hits.map(h => h._source || h);
      }
      return [single];
    }
  } catch (e) {}

  return ndjsonRecords;
}

/**
 * Text & Syslog log parser for line-based security entries.
 */
function parseTxtOrLog(content) {
  const cleanContent = stripBOM(content);
  const lines = cleanContent.split(/\r?\n/).filter(line => line.trim().length > 0);
  const records = [];

  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;

    const record = { _rawLine: trimmedLine };

    // 1. Key=Value extraction (e.g. src=10.0.0.1 dst=192.168.1.1 user=admin)
    const kvMatches = [...trimmedLine.matchAll(/([a-zA-Z0-9_\-\.]+)=["']?([^"'\s]+)["']?/g)];
    if (kvMatches.length > 0) {
      for (const match of kvMatches) {
        record[match[1]] = match[2];
      }
    }

    // 2. Syslog pattern: "Mmm dd hh:mm:ss host process[pid]: message"
    const syslogMatch = trimmedLine.match(/^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$/);
    if (syslogMatch) {
      record.syslogTime = syslogMatch[1];
      record.host = record.host || syslogMatch[2];
      record.process = syslogMatch[3];
      record.pid = syslogMatch[4];
      record.message = syslogMatch[5];
    }

    // 3. SSHD failed logins
    const sshdFailed = trimmedLine.match(/Failed password for (?:invalid user )?([^\s]+) from ([0-9\.]+) port (\d+)/i);
    if (sshdFailed) {
      record.username = sshdFailed[1];
      record.sourceIP = sshdFailed[2];
      record.sourcePort = sshdFailed[3];
      record.action = 'login';
      record.status = 'failed';
      record.eventType = 'authentication';
    }

    // 4. SSHD accepted logins
    const sshdAccepted = trimmedLine.match(/Accepted (?:password|publickey) for ([^\s]+) from ([0-9\.]+) port (\d+)/i);
    if (sshdAccepted) {
      record.username = sshdAccepted[1];
      record.sourceIP = sshdAccepted[2];
      record.sourcePort = sshdAccepted[3];
      record.action = 'login';
      record.status = 'success';
      record.eventType = 'authentication';
    }

    // 5. Windows Event Log text heuristics
    if (trimmedLine.includes('4625') || trimmedLine.toLowerCase().includes('logon failure') || trimmedLine.toLowerCase().includes('failed login')) {
      record.eventType = 'authentication';
      record.action = 'login';
      record.status = 'failed';
      record.source = 'windows';
    } else if (trimmedLine.includes('4624') || trimmedLine.toLowerCase().includes('successful logon')) {
      record.eventType = 'authentication';
      record.action = 'login';
      record.status = 'success';
      record.source = 'windows';
    } else if (trimmedLine.includes('4688') || trimmedLine.toLowerCase().includes('process creation') || trimmedLine.toLowerCase().includes('powershell')) {
      record.eventType = 'process';
      record.action = 'execute';
      record.source = 'windows';
    }

    records.push(record);
  }

  return records;
}

/**
 * Universal file parser dispatcher.
 */
function parseFile(fileName, content) {
  if (!content) return [];
  const cleanContent = stripBOM(content).trim();
  if (cleanContent.length === 0) return [];

  const ext = (fileName || '').split('.').pop().toLowerCase();

  // 1. If explicit .json or formatted like JSON
  if (ext === 'json') {
    try {
      return parseJSON(cleanContent);
    } catch (e) {
      return [];
    }
  }

  // 2. If formatted like JSON
  if (cleanContent.startsWith('[') || (cleanContent.startsWith('{') && cleanContent.endsWith('}'))) {
    try {
      const jsonResults = parseJSON(cleanContent);
      if (jsonResults.length > 0) return jsonResults;
    } catch (e) {}
  }

  // 3. If explicit .csv
  if (ext === 'csv') {
    try {
      return parseCSV(cleanContent);
    } catch (e) {
      return [];
    }
  }

  // 4. If first line has commas and multiple rows (unnamed CSV)
  const firstLine = cleanContent.split(/\r?\n/)[0] || '';
  if (firstLine.includes(',')) {
    try {
      const csvResults = parseCSV(cleanContent);
      if (csvResults.length > 0) return csvResults;
    } catch (e) {}
  }

  // 5. Check for NDJSON
  try {
    const ndjsonResults = parseJSON(cleanContent);
    if (ndjsonResults.length > 0) return ndjsonResults;
  } catch (e) {}

  // 6. Fallback to line-based TXT/LOG parsing for text and log formats
  return parseTxtOrLog(cleanContent);
}

module.exports = {
  parseFile,
  parseCSV,
  parseJSON,
  parseTxtOrLog
};
