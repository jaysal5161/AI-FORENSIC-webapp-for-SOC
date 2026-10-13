/**
 * log_upload_tests.js
 * Comprehensive automated test suite for log file upload and ingestion pipeline:
 * 1. Small valid CSV upload
 * 2. CSV upload approximately 4.5 MB
 * 3. CSV containing quoted fields (embedded commas, multi-line, escaped quotes)
 * 4. CSV containing missing optional fields
 * 5. Invalid CSV upload (empty/unparseable content)
 * 6. Valid JSON upload (array of event objects)
 * 7. Newline-delimited JSON upload (NDJSON)
 * 8. TXT security log upload (SSHD / key=value)
 * 9. LOG security log upload (Syslog)
 * 10. Empty file upload (0 bytes rejected)
 * 11. File larger than 25 MB (rejected with 400 FileSizeExceeded)
 * 12. Unauthenticated upload rejection (401)
 * 13. Database persistence & checksum integrity
 * 14. Duplicate upload handling
 * 15. Successful dashboard refresh telemetry reflection
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const app = require('../src/server');

const TEST_PORT = 5096;
const HOST = '127.0.0.1';

function sendMultipartRequest(options, fileBuffer, fileName, extraFields = {}) {
  return new Promise((resolve, reject) => {
    const boundary = '----AEGISTestBoundary' + Math.random().toString(36).substring(2);
    const parts = [];

    // Add extra text fields
    for (const [k, v] of Object.entries(extraFields)) {
      parts.push(Buffer.from(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${k}"\r\n\r\n` +
        `${v}\r\n`
      ));
    }

    // Add file field
    if (fileBuffer !== null) {
      parts.push(Buffer.from(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="${fileName}"\r\n` +
        `Content-Type: application/octet-stream\r\n\r\n`
      ));
      parts.push(fileBuffer);
      parts.push(Buffer.from('\r\n'));
    }

    parts.push(Buffer.from(`--${boundary}--\r\n`));
    const fullBody = Buffer.concat(parts);

    const req = http.request({
      host: HOST,
      port: TEST_PORT,
      path: options.path,
      method: options.method || 'POST',
      headers: {
        ...options.headers,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': fullBody.length
      },
      timeout: 30000
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, data: body });
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    req.write(fullBody);
    req.end();
  });
}

function sendJsonRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const payload = data ? (typeof data === 'string' ? data : JSON.stringify(data)) : null;
    const req = http.request({
      host: HOST,
      port: TEST_PORT,
      path: options.path,
      method: options.method || 'GET',
      headers: {
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...options.headers
      },
      timeout: 10000
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, data: body });
        }
      });
    });

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function runUploadTestSuite() {
  console.log('================================================================');
  console.log('   AEGIS SOC PLATFORM // LOG FILE UPLOAD & INGESTION TEST SUITE');
  console.log('================================================================\n');

  let server;
  try {
    server = await new Promise((resolve) => {
      const s = app.listen(TEST_PORT, HOST, () => resolve(s));
    });
  } catch (e) {
    console.error('Failed to start test server:', e);
    process.exit(1);
  }

  let passed = 0;
  let total = 0;

  function report(name, isPass, details = '') {
    total++;
    if (isPass) {
      passed++;
      console.log(`[PASS] Test ${total}: ${name}`);
      if (details) console.log(`       Details: ${details}`);
    } else {
      console.error(`[FAIL] Test ${total}: ${name}`);
      if (details) console.error(`       Details: ${details}`);
    }
  }

  try {
    // Authenticate as analyst
    const loginRes = await sendJsonRequest({
      path: '/api/auth/login',
      method: 'POST'
    }, { username: 'analyst', password: 'analyst123' });

    if (!loginRes.data?.token) {
      console.error('Failed to authenticate analyst:', loginRes);
      process.exit(1);
    }

    const token = loginRes.data.token;
    const authHeaders = { Authorization: `Bearer ${token}` };

    // TEST 1: Small valid CSV upload
    const smallCsv = Buffer.from(
      `timestamp,source,host,username,sourceIP,destinationIP,eventType,action,status,severity,description\r\n` +
      `2026-10-13T10:00:00Z,windows,WS01,analyst,192.168.1.50,10.0.0.1,authentication,login,success,low,Interactive logon for analyst\r\n` +
      `2026-10-13T10:05:00Z,windows,WS01,analyst,192.168.1.50,10.0.0.1,process,execute,success,low,Executed powershell.exe script\r\n`
    );
    const res1 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, smallCsv, 'small_audit.csv', { saveFile: 'false' });
    report(
      'Small Valid CSV Upload',
      res1.status === 201 && res1.data.summary?.eventsInserted === 2,
      `Status=${res1.status}, Inserted=${res1.data.summary?.eventsInserted} events`
    );

    // TEST 2: CSV upload approximately 4.5 MB (or actual security logs.csv)
    let largeCsvBuffer;
    const docPath = 'C:\\Users\\HP\\Documents\\security logs.csv';
    if (fs.existsSync(docPath)) {
      largeCsvBuffer = fs.readFileSync(docPath);
    } else {
      // Generate synthetic 4.5 MB security CSV if file was moved
      const rows = ['Keywords,Date and Time,Source,Event ID,Task Category,message'];
      for (let i = 0; i < 5000; i++) {
        rows.push(`"Audit Success","23-06-2026 10:13:${String(i % 60).padStart(2, '0')}","Microsoft-Windows-Security-Auditing","4798","User Account Management","A user's local group membership was enumerated for user HP on DESKTOP-UERJU8T"`);
      }
      largeCsvBuffer = Buffer.from(rows.join('\r\n'));
    }

    console.log(`       Uploading real/large CSV (~${(largeCsvBuffer.length / (1024 * 1024)).toFixed(2)} MB)...`);
    const res2 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, largeCsvBuffer, 'security log.csv', { saveFile: 'false' });
    report(
      'CSV Upload (~4.5 MB with filename spaces & multi-line fields)',
      res2.status === 201 && res2.data.summary?.eventsInserted > 0,
      `Status=${res2.status}, Events Inserted=${res2.data.summary?.eventsInserted}, IOCs=${res2.data.summary?.iocsExtracted}`
    );

    // TEST 3: CSV containing quoted fields (embedded commas, multi-line, escaped quotes)
    const complexCsv = Buffer.from(
      `"Event ID","Date and Time","User Name","Description"\r\n` +
      `"4625","2026-10-13 11:00:00","admin","Failed logon from IP: 194.26.29.112,\r\nReason: ""Bad Password"", Port: 445"\r\n` +
      `"4624","2026-10-13 11:01:00","admin","Successful logon, with, embedded, commas, and ""escaped"" tokens"\r\n`
    );
    const res3 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, complexCsv, 'complex_quoted.csv', { saveFile: 'false' });
    report(
      'CSV with Multi-line Quoted Fields, Embedded Commas, and Escaped Quotes',
      res3.status === 201 && res3.data.summary?.eventsInserted === 2,
      `Status=${res3.status}, Events Inserted=${res3.data.summary?.eventsInserted}`
    );

    // TEST 4: CSV containing missing optional fields
    const partialCsv = Buffer.from(
      `timestamp,host,username\r\n` +
      `2026-10-13T12:00:00Z,DC01,\r\n` +
      `2026-10-13T12:01:00Z,,guest\r\n`
    );
    const res4 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, partialCsv, 'partial_fields.csv', { saveFile: 'false' });
    report(
      'CSV with Missing Optional Fields (Graceful Defaults)',
      res4.status === 201 && res4.data.summary?.eventsInserted === 2,
      `Status=${res4.status}, Normalized records saved cleanly`
    );

    // TEST 5: Invalid CSV upload (empty/unparseable content)
    const invalidCsv = Buffer.from('JustOneLineWithoutCommasOrHeader');
    const res5 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, invalidCsv, 'invalid.csv', { saveFile: 'false' });
    report(
      'Invalid CSV Handling',
      res5.status === 400 && res5.data.error === 'ParseError',
      `Status=${res5.status}, ErrorMessage="${res5.data.message}"`
    );

    // TEST 6: Valid JSON upload (array of event objects)
    const validJson = Buffer.from(JSON.stringify([
      {
        timestamp: '2026-10-13T13:00:00Z',
        source: 'firewall',
        host: 'FW01-EDGE',
        username: 'external_scanner',
        sourceIP: '45.33.32.156',
        destinationIP: '10.0.0.1',
        destinationPort: 443,
        eventType: 'network',
        action: 'connect',
        status: 'failed',
        severity: 'medium',
        description: 'Inbound port scan dropped by firewall perimeter'
      }
    ]));
    const res6 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, validJson, 'firewall_events.json', { saveFile: 'false' });
    report(
      'Valid JSON Array Upload',
      res6.status === 201 && res6.data.summary?.eventsInserted === 1,
      `Status=${res6.status}, Events Inserted=${res6.data.summary?.eventsInserted}`
    );

    // TEST 7: Newline-delimited JSON upload (NDJSON)
    const ndjson = Buffer.from(
      `{"UserName": "jsmith", "Source_ip": "185.220.101.5", "EventTime": "2026-10-13T14:00:00", "action": "built", "index": "VPN_Logs"}\n` +
      `{"UserName": "jsmith", "Source_ip": "185.220.101.5", "EventTime": "2026-10-13T14:30:00", "action": "teardown", "index": "VPN_Logs"}\n`
    );
    const res7 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, ndjson, 'vpn_telemetry.ndjson', { saveFile: 'false' });
    report(
      'Newline-Delimited JSON (NDJSON) Upload',
      res7.status === 201 && res7.data.summary?.eventsInserted === 2,
      `Status=${res7.status}, Events Inserted=${res7.data.summary?.eventsInserted}`
    );

    // TEST 8: TXT security log upload (SSHD authentication / key=value)
    const txtLog = Buffer.from(
      `Oct 13 15:00:01 bastion sshd[9101]: Failed password for invalid user root from 203.0.113.195 port 55122 ssh2\n` +
      `Oct 13 15:00:05 bastion sshd[9104]: Accepted password for sysadmin from 203.0.113.195 port 55124 ssh2\n`
    );
    const res8 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, txtLog, 'auth_events.txt', { saveFile: 'false' });
    report(
      'TXT Security Log Upload (SSHD)',
      res8.status === 201 && res8.data.summary?.eventsInserted === 2,
      `Status=${res8.status}, Events Inserted=${res8.data.summary?.eventsInserted}`
    );

    // TEST 9: LOG security log upload (Linux Syslog)
    const syslog = Buffer.from(
      `Oct 13 16:00:10 srv-app01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.44 DST=10.0.0.5 PROTO=TCP SPT=41234 DPT=80\n` +
      `Oct 13 16:00:12 srv-app01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.44 DST=10.0.0.5 PROTO=TCP SPT=41235 DPT=443\n`
    );
    const res9 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, syslog, 'firewall.log', { saveFile: 'false' });
    report(
      'LOG Security Log Upload (Syslog / UFW)',
      res9.status === 201 && res9.data.summary?.eventsInserted === 2,
      `Status=${res9.status}, Events Inserted=${res9.data.summary?.eventsInserted}`
    );

    // TEST 10: Empty file upload (0 bytes rejected)
    const emptyBuf = Buffer.alloc(0);
    const res10 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, emptyBuf, 'empty_file.csv', { saveFile: 'false' });
    report(
      'Empty File Upload Rejection (0 bytes)',
      res10.status === 400 && res10.data.error === 'EmptyFileError',
      `Status=${res10.status}, ErrorMessage="${res10.data.message}"`
    );

    // TEST 11: File larger than 25 MB (rejected with 400 FileSizeExceeded)
    // Send request with header Content-Length advertising > 25MB or 26MB buffer
    const oversizedHeaderReq = await new Promise((resolve) => {
      const boundary = '----OversizedTestBoundary';
      const req = http.request({
        host: HOST,
        port: TEST_PORT,
        path: '/api/logs/upload',
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': `multipart/form-data; boundary=${boundary}`
        }
      }, (res) => {
        let b = '';
        res.on('data', c => b += c);
        res.on('end', () => {
          try { resolve({ status: res.statusCode, data: JSON.parse(b) }); }
          catch (e) { resolve({ status: res.statusCode, data: b }); }
        });
      });

      // Write header stating file
      req.write(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="huge_audit.csv"\r\nContent-Type: text/csv\r\n\r\n`);
      // Stream chunks until exceeding 25MB
      const chunk = Buffer.alloc(1024 * 1024, 'A'); // 1MB chunk
      for (let i = 0; i < 26; i++) {
        req.write(chunk);
      }
      req.write(`\r\n--${boundary}--\r\n`);
      req.end();
    });
    report(
      'File Exceeding 25 MB Rejection (FileSizeExceeded)',
      oversizedHeaderReq.status === 400 && oversizedHeaderReq.data.error === 'FileSizeExceeded',
      `Status=${oversizedHeaderReq.status}, ErrorMessage="${oversizedHeaderReq.data?.message}"`
    );

    // TEST 12: Unauthenticated upload rejection (401)
    const unauthRes = await sendMultipartRequest({ path: '/api/logs/upload', headers: {} }, smallCsv, 'unauth.csv');
    report(
      'Unauthenticated Upload Rejection (401 Unauthorized)',
      unauthRes.status === 401,
      `Status=${unauthRes.status}, Error="${unauthRes.data.error}"`
    );

    // TEST 13: Database persistence & checksum integrity
    const fileRecordsRes = await sendJsonRequest({ path: '/api/logs/files', headers: authHeaders });
    const hasFiles = fileRecordsRes.status === 200 && Array.isArray(fileRecordsRes.data) && fileRecordsRes.data.length > 0;
    const latestFile = fileRecordsRes.data?.[0];
    report(
      'Database Ingestion Persistence & SHA256 Checksum Integrity',
      hasFiles && Boolean(latestFile?.sha256),
      `Stored Files Count=${fileRecordsRes.data?.length}, Latest SHA256=${latestFile?.sha256?.slice(0, 16)}...`
    );

    // TEST 14: Duplicate upload handling
    const res14 = await sendMultipartRequest({ path: '/api/logs/upload', headers: authHeaders }, smallCsv, 'small_audit.csv', { saveFile: 'false' });
    report(
      'Duplicate Upload Handling (Graceful Ingestion & Non-crashing)',
      res14.status === 201 && res14.data.summary?.eventsInserted === 2,
      `Status=${res14.status}, Duplicate file processed cleanly`
    );

    // TEST 15: Successful dashboard refresh telemetry reflection
    const dashRes = await sendJsonRequest({ path: '/api/dashboard/summary', headers: authHeaders });
    const eventsCount = dashRes.data.totals?.events ?? dashRes.data.metrics?.totalEvents ?? 0;
    report(
      'Dashboard Forensic Telemetry Reflection (Live Events & Counts)',
      dashRes.status === 200 && eventsCount > 0,
      `Dashboard Status=${dashRes.status}, Total Live Events=${eventsCount}`
    );

    console.log('\n================================================================');
    console.log(`TEST SUITE FINISHED: ${passed}/${total} TESTS PASSED (${((passed / total) * 100).toFixed(0)}%)`);
    console.log('================================================================');

    if (passed !== total) {
      process.exit(1);
    }
  } finally {
    if (server) server.close();
  }
}

runUploadTestSuite().catch((err) => {
  console.error('Fatal test runner error:', err);
  process.exit(1);
});
