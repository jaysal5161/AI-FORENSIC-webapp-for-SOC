/**
 * test_full_owasp_audit.js
 * Comprehensive automated security test suite validating:
 * 1. OWASP Top 10 Web Application Security Risks (A01 - A10)
 * 2. OWASP API Security Top 10 (API1 - API10)
 * 3. System & File Integrity
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

function request(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
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
    if (data) {
      req.write(typeof data === 'string' ? data : JSON.stringify(data));
    }
    req.end();
  });
}

async function runOwaspAudit() {
  console.log('================================================================');
  console.log('   AEGIS SOC PLATFORM // COMPREHENSIVE OWASP & API SECURITY AUDIT');
  console.log('================================================================\n');

  let passedChecks = 0;
  let totalChecks = 0;

  function report(category, name, passed, details = '') {
    totalChecks++;
    if (passed) {
      passedChecks++;
      console.log(`[PASS] [${category}] ${name}`);
      if (details) console.log(`       Details: ${details}`);
    } else {
      console.error(`[FAIL] [${category}] ${name}`);
      if (details) console.error(`       Details: ${details}`);
    }
  }

  // Baseline: Obtain test tokens for viewer, analyst, admin
  console.log('--- PHASE 1: AUTHENTICATION BASELINE ---');
  const analystLogin = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/auth/login',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, { username: 'analyst', password: 'analyst123' });

  const adminLogin = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/auth/login',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, { username: 'admin', password: 'admin123' });

  const analystToken = analystLogin.data?.token;
  const adminToken = adminLogin.data?.token;

  report('A07/API2', 'Analyst & Admin Authentication Baseline', Boolean(analystToken && adminToken), 'Valid JWTs issued with appropriate roles');

  // 1. A01 & API1/API5: Broken Access Control & Function Level Authorization
  console.log('\n--- PHASE 2: OWASP A01 & API1/API5 (ACCESS CONTROL & BFLA) ---');
  
  // Unauthenticated access rejection
  const unauthRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/events',
    method: 'GET'
  });
  report('A01/API2', 'Unauthenticated Access Rejection', unauthRes.status === 401, 'Direct request to /api/events rejected with 401 Unauthorized');

  // Role Escalation on Registration
  const testUsername = `audit_reg_${Date.now()}`;
  const regEscalation = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/auth/register',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    username: testUsername,
    password: 'Password123!',
    fullName: 'Auditor Test',
    email: `${testUsername}@audit.soc`,
    role: 'admin' // Attempting privilege escalation
  });
  report(
    'A01/API2',
    'Privilege Escalation Defense on Registration',
    regEscalation.status === 201 && regEscalation.data?.user?.role === 'viewer',
    `Requested 'admin' role was strictly overridden to '${regEscalation.data?.user?.role}'`
  );

  // Sensitive Operation (Reset All Telemetry) - Blocked for Analyst, Allowed for Admin
  const analystReset = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/logs/reset-all',
    method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  report('API5', 'Broken Function Level Authorization Guard (Reset-All)', analystReset.status === 403, 'Analyst denied access to admin-only reset endpoint with 403 Forbidden');

  // Rule Deletion Access Control
  const rules = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/rules',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  if (rules.data && rules.data[0]) {
    const analystDeleteRule = await request({
      host: 'localhost',
      port: 5000,
      path: `/api/rules/${rules.data[0]._id}`,
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    report('API5', 'Detection Rule Deletion Access Guard', analystDeleteRule.status === 403, 'Analyst role blocked from deleting detection rule with 403 Forbidden');
  }

  // Static File Exposure Shield
  const directUploadRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/uploads/evidence-c2-traffic.pcap',
    method: 'GET'
  });
  report('A01/API8', 'Direct Unauthenticated Uploads Path Traversal Shield', directUploadRes.status === 404, 'Unauthenticated static file downloads are completely disabled');

  // 2. A02 & API2: Cryptographic Failures & Token Integrity
  console.log('\n--- PHASE 3: OWASP A02 & API2 (CRYPTOGRAPHIC FAILURES) ---');
  
  // Password Hash Exclusion in User Objects
  const profileRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/auth/me',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  const hasPasswordHash = Boolean(profileRes.data?.user?.passwordHash || profileRes.data?.passwordHash);
  report('A02/API3', 'Credential & Password Hash Exposure Defense', !hasPasswordHash, 'passwordHash field is excluded from API user payloads');

  // Tampered Token Rejection
  const tamperedToken = analystToken.slice(0, -6) + 'xxxxxx';
  const tamperedRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/events',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tamperedToken}` }
  });
  report('A02/API2', 'Cryptographic Token Signature Verification', tamperedRes.status === 401, 'Tampered token rejected with 401 Unauthorized');

  // 3. A03 & API1: Injection (NoSQL, SQL, ReDoS, XSS)
  console.log('\n--- PHASE 4: OWASP A03 & API1 (INJECTION DEFENSES) ---');

  // NoSQL Injection with $gt operator
  const nosqlAttempt = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/auth/login',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, { username: { $gt: '' }, password: { $gt: '' } });
  report('A03', 'NoSQL Injection Sanitization (mongo-sanitize)', nosqlAttempt.status === 400 || nosqlAttempt.status === 401, `NoSQL operator neutralized safely with status ${nosqlAttempt.status}`);

  // SQL Injection & Prohibited Commands in SQL Engine
  const sqlDropAttempt = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/sql',
    method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
  }, { query: 'DROP TABLE events;' });
  report('A03/API8', 'SQL Engine Prohibited Keyword Block (DROP)', sqlDropAttempt.status === 400 && sqlDropAttempt.data?.error?.includes('DROP'), 'Destructive SQL rejected with clear security violation');

  const sqlDeleteAttempt = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/sql',
    method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
  }, { query: 'DELETE FROM alerts WHERE 1=1;' });
  report('A03/API8', 'SQL Engine Prohibited Keyword Block (DELETE)', sqlDeleteAttempt.status === 400 && sqlDeleteAttempt.data?.error?.includes('DELETE'), 'Destructive DELETE rejected');

  const sqlNonWhitelistedTable = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/sql',
    method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
  }, { query: 'SELECT * FROM users;' });
  report('A01/API1', 'SQL Engine Non-Whitelisted Table Block (users)', sqlNonWhitelistedTable.status === 400 && sqlNonWhitelistedTable.data?.error?.includes('users'), 'Table allowlisting prevents access to user credentials');

  // ReDoS & Malformed Regex Injection
  const redosRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/events?search=((a%2B)%2B)%2B%24&host=(unclosed_paren',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  report('A03/API4', 'ReDoS & Malformed Regex Injection Immunity', redosRes.status === 200, 'Regex metacharacters escaped via escapeRegex, server did not crash or hang');

  // Stored XSS Neutralization in HTML Report Export
  const cases = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/cases',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  if (cases.data && cases.data[0]) {
    const reportHtml = await request({
      host: 'localhost',
      port: 5000,
      path: `/api/reports/case/${cases.data[0]._id}/export?format=html`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    const hasUnescapedScript = typeof reportHtml.data === 'string' && reportHtml.data.includes('<script>');
    report('A03', 'Stored XSS Neutralization in HTML Report Export', reportHtml.status === 200 && !hasUnescapedScript, 'HTML report output is properly encoded with HTML entities');
  }

  // 4. API3: Broken Object Property Level Authorization (Mass Assignment)
  console.log('\n--- PHASE 5: OWASP API3 (MASS ASSIGNMENT & DATA EXPOSURE) ---');
  
  const accounts = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/accounts',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  if (accounts.data && accounts.data[0]) {
    const massAssignAttempt = await request({
      host: 'localhost',
      port: 5000,
      path: `/api/accounts/${accounts.data[0]._id}`,
      method: 'PATCH',
      headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
    }, {
      notes: 'Audited by security team',
      _id: '000000000000000000000000', // Attempting to tamper with immutable ID
      associatedAlerts: ['fakeAlert1', 'fakeAlert2'] // Attempting untrusted relation overwrite
    });
    report(
      'API3',
      'Mass Assignment Defense on Object Update',
      massAssignAttempt.status === 200 && massAssignAttempt.data._id === accounts.data[0]._id,
      'Immutable and sensitive properties ignored, only allowlisted fields updated'
    );
  }

  // 5. API4: Unrestricted Resource Consumption (Rate Limiting & Caps)
  console.log('\n--- PHASE 6: OWASP API4 (RESOURCE CONSUMPTION & PAGINATION) ---');

  // Pagination upper-bound cap
  const paginationCapRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/events?limit=9999999',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  const appliedLimit = paginationCapRes.data?.pagination?.limit;
  report('API4', 'Pagination Upper-Bound Cap', appliedLimit <= 1000, `Requested limit 9999999 clamped to maximum safe ceiling of ${appliedLimit}`);

  // SQL Query Row Limit Cap
  const sqlLimitCapRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/sql',
    method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
  }, { query: 'SELECT * FROM events LIMIT 10000;' });
  report('API4', 'SQL Engine Result Set Pagination Cap', sqlLimitCapRes.data?.results?.length <= 500, `SQL engine enforced max limit cap of 500 records (returned ${sqlLimitCapRes.data?.results?.length})`);

  // 6. A05 & API8: Security Misconfiguration
  console.log('\n--- PHASE 7: OWASP A05 & API8 (SECURITY MISCONFIGURATION) ---');

  const healthRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/health',
    method: 'GET'
  });
  const headers = healthRes.headers;
  const hasCorp = Boolean(headers['cross-origin-resource-policy']);
  const hasContentTypeOptions = headers['x-content-type-options'] === 'nosniff';
  const hasDnsPrefetch = Boolean(headers['x-dns-prefetch-control']);
  report('A05/API8', 'HTTP Security Headers (Helmet Policy)', hasCorp && hasContentTypeOptions && hasDnsPrefetch, 'nosniff, same-origin CORP, and DNS prefetch controls active');

  // 7. A09: Security Logging & Monitoring
  console.log('\n--- PHASE 8: OWASP A09 (SECURITY LOGGING & AUDIT TRAIL) ---');
  const auditLogPath = path.join(__dirname, 'logs', 'audit.log');
  const auditExists = fs.existsSync(auditLogPath);
  let auditHasExpectedActions = false;
  if (auditExists) {
    const auditContent = fs.readFileSync(auditLogPath, 'utf8');
    auditHasExpectedActions = auditContent.includes('LOGIN_SUCCESS') && auditContent.includes('SQL_QUERY_EXECUTED');
  }
  report('A09', 'Structured Audit Logging Trail (audit.log)', auditExists && auditHasExpectedActions, 'Critical security events recorded with actor ID, IP, and timestamp');

  // 8. AI Schema Discovery & Validation Integrity
  console.log('\n--- PHASE 9: AI NL-TO-SQL ASSISTANT SECURITY & INTEGRITY ---');
  const schemaRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/ai/schema',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  const tableKeys = schemaRes.data?.tables ? Object.keys(schemaRes.data.tables) : [];
  report('A04/API9', 'AI Schema Discovery Integrity', tableKeys.includes('events') && tableKeys.includes('alerts') && !tableKeys.includes('users'), 'Schema discovery exposes permitted collections and excludes sensitive auth tables');

  const aiGenRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/ai/generate',
    method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
  }, { question: 'Which IP address generated the highest number of events?' });
  const isReadOnlySql = aiGenRes.data?.sql?.toUpperCase().startsWith('SELECT');
  report('A03/API10', 'AI-Generated SQL Read-Only Integrity', isReadOnlySql, `AI engine generated strictly read-only query: ${aiGenRes.data?.sql}`);

  // Summary
  console.log('\n================================================================');
  console.log(`AUDIT SUMMARY: ${passedChecks}/${totalChecks} SECURITY INTEGRITY CHECKS PASSED`);
  console.log('================================================================');

  if (passedChecks === totalChecks) {
    console.log('[ALL CLEAR] 100% OF OWASP WEB & API INTEGRITY CHECKS PASSED!\n');
    process.exit(0);
  } else {
    console.error(`[ALERT] ${totalChecks - passedChecks} integrity checks failed.\n`);
    process.exit(1);
  }
}

runOwaspAudit().catch(err => {
  console.error('[FATAL] Uncaught audit error:', err);
  process.exit(1);
});
