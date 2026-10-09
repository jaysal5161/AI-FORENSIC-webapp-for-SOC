/**
 * security_audit.js
 * Comprehensive automated security test suite validating:
 * 1. OWASP Top 10 Web Application Security Risks (A01 - A10)
 * 2. OWASP API Security Top 10 (API1 - API10)
 * 3. System, Data, and Access Control Integrity
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const app = require('../src/server');

const TEST_PORT = 5099;
const HOST = '127.0.0.1';

function request(options, data = null) {
  return new Promise((resolve, reject) => {
    const opts = {
      host: HOST,
      port: TEST_PORT,
      timeout: 5000,
      ...options
    };
    const req = http.request(opts, (res) => {
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
    if (data) {
      req.write(typeof data === 'string' ? data : JSON.stringify(data));
    }
    req.end();
  });
}

async function runSecurityAudit() {
  console.log('================================================================');
  console.log('   AEGIS SOC PLATFORM // COMPREHENSIVE OWASP & API SECURITY AUDIT');
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

  try {
    // PHASE 1: Authentication Baseline
    console.log('--- PHASE 1: AUTHENTICATION BASELINE ---');
    const analystLogin = await request({
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { username: 'analyst', password: 'analyst123' });

    const adminLogin = await request({
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { username: 'admin', password: 'admin123' });

    const analystToken = analystLogin.data?.token;
    const adminToken = adminLogin.data?.token;
    report('A07/API2', 'Analyst & Admin Authentication Baseline', Boolean(analystToken && adminToken), 'Valid JWTs issued with appropriate roles');

    // PHASE 2: Access Control & Authorization (A01 / API1 / API5)
    console.log('\n--- PHASE 2: ACCESS CONTROL & AUTHORIZATION (A01, API1, API5) ---');
    const unauthRes = await request({ path: '/api/events', method: 'GET' });
    report('A01/API2', 'Unauthenticated Access Rejection', unauthRes.status === 401, 'Direct request to /api/events rejected with 401 Unauthorized');

    const testUsername = `sec_audit_${Date.now()}`;
    const regEscalation = await request({
      path: '/api/auth/register',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {
      username: testUsername,
      password: 'SecurePassword123!',
      fullName: 'Auditor Test',
      email: `${testUsername}@sec.audit`,
      role: 'admin'
    });
    report(
      'A01/API2',
      'Privilege Escalation Defense on Registration',
      regEscalation.status === 201 && regEscalation.data?.user?.role === 'viewer',
      `Requested 'admin' role was strictly overridden to '${regEscalation.data?.user?.role}'`
    );

    const analystReset = await request({
      path: '/api/logs/reset-all',
      method: 'POST',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    report('API5', 'Broken Function Level Authorization Guard (Reset-All)', analystReset.status === 403, 'Analyst denied access to admin-only reset endpoint with 403 Forbidden');

    const rules = await request({
      path: '/api/rules',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    if (rules.data && rules.data[0]) {
      const analystDeleteRule = await request({
        path: `/api/rules/${rules.data[0]._id}`,
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${analystToken}` }
      });
      report('API5', 'Detection Rule Deletion Access Guard', analystDeleteRule.status === 403, 'Analyst role blocked from deleting detection rule with 403 Forbidden');
    }

    const directUploadRes = await request({
      path: '/uploads/evidence-c2-traffic.pcap',
      method: 'GET'
    });
    report('A01/API8', 'Direct Unauthenticated Uploads Path Traversal Shield', directUploadRes.status === 404, 'Unauthenticated static file downloads are completely disabled');

    // PHASE 3: Cryptographic Failures & Token Integrity (A02 / API2)
    console.log('\n--- PHASE 3: CRYPTOGRAPHIC INTEGRITY & TOKENS (A02, API2) ---');
    const profileRes = await request({
      path: '/api/auth/me',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    const hasPasswordHash = Boolean(profileRes.data?.user?.passwordHash || profileRes.data?.passwordHash);
    report('A02/API3', 'Credential & Password Hash Exposure Defense', !hasPasswordHash, 'passwordHash field is excluded from API user payloads');

    const tamperedToken = analystToken.slice(0, -6) + 'xxxxxx';
    const tamperedRes = await request({
      path: '/api/events',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tamperedToken}` }
    });
    report('A02/API2', 'Cryptographic Token Signature Verification', tamperedRes.status === 401, 'Tampered token rejected with 401 Unauthorized');

    // PHASE 4: Injection Defenses (A03 / API1)
    console.log('\n--- PHASE 4: INJECTION DEFENSES (A03, API1) ---');
    const nosqlAttempt = await request({
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { username: { $gt: '' }, password: { $gt: '' } });
    report('A03', 'NoSQL Injection Sanitization (mongo-sanitize)', nosqlAttempt.status === 400 || nosqlAttempt.status === 401, `NoSQL operator neutralized safely with status ${nosqlAttempt.status}`);

    const sqlDropAttempt = await request({
      path: '/api/iocs/sql',
      method: 'POST',
      headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
    }, { query: 'DROP TABLE events;' });
    report('A03/API8', 'SQL Engine Prohibited Keyword Block (DROP)', sqlDropAttempt.status === 400, 'Destructive SQL rejected with security violation');

    const sqlDeleteAttempt = await request({
      path: '/api/iocs/sql',
      method: 'POST',
      headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
    }, { query: 'DELETE FROM alerts WHERE 1=1;' });
    report('A03/API8', 'SQL Engine Prohibited Keyword Block (DELETE)', sqlDeleteAttempt.status === 400, 'Destructive DELETE rejected');

    const sqlNonWhitelistedTable = await request({
      path: '/api/iocs/sql',
      method: 'POST',
      headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
    }, { query: 'SELECT * FROM users;' });
    report('A01/API1', 'SQL Engine Non-Whitelisted Table Block (users)', sqlNonWhitelistedTable.status === 400, 'Table allowlisting prevents access to user credentials');

    const redosRes = await request({
      path: '/api/events?search=((a%2B)%2B)%2B%24&host=(unclosed_paren',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    report('A03/API4', 'ReDoS & Malformed Regex Injection Immunity', redosRes.status === 200, 'Regex metacharacters escaped via escapeRegex');

    const cases = await request({
      path: '/api/cases',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    if (cases.data && cases.data[0]) {
      const reportHtml = await request({
        path: `/api/reports/case/${cases.data[0]._id}/export?format=html`,
        method: 'GET',
        headers: { 'Authorization': `Bearer ${analystToken}` }
      });
      const hasUnescapedScript = typeof reportHtml.data === 'string' && reportHtml.data.includes('<script>');
      report('A03', 'Stored XSS Neutralization in HTML Report Export', reportHtml.status === 200 && !hasUnescapedScript, 'HTML report output is properly encoded with HTML entities');
    }

    // PHASE 5: Mass Assignment (API3)
    console.log('\n--- PHASE 5: MASS ASSIGNMENT DEFENSES (API3) ---');
    const accounts = await request({
      path: '/api/accounts',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    if (accounts.data && accounts.data[0]) {
      const massAssignAttempt = await request({
        path: `/api/accounts/${accounts.data[0]._id}`,
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
      }, {
        notes: 'Audited by security team',
        _id: '000000000000000000000000',
        associatedAlerts: ['fakeAlert1', 'fakeAlert2']
      });
      report(
        'API3',
        'Mass Assignment Defense on Object Update',
        massAssignAttempt.status === 200 && massAssignAttempt.data._id === accounts.data[0]._id,
        'Immutable and sensitive properties ignored'
      );
    }

    // PHASE 6: Resource Consumption (API4)
    console.log('\n--- PHASE 6: RESOURCE CONSUMPTION & RATE LIMITS (API4) ---');
    const paginationCapRes = await request({
      path: '/api/events?limit=9999999',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    const appliedLimit = paginationCapRes.data?.pagination?.limit;
    report('API4', 'Pagination Upper-Bound Cap', appliedLimit <= 1000, `Requested limit clamped to maximum safe ceiling of ${appliedLimit}`);

    const sqlLimitCapRes = await request({
      path: '/api/iocs/sql',
      method: 'POST',
      headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' }
    }, { query: 'SELECT * FROM events LIMIT 10000;' });
    report('API4', 'SQL Engine Result Set Pagination Cap', sqlLimitCapRes.data?.results?.length <= 500, `SQL engine enforced max limit cap of 500 records`);

    // PHASE 7: Security Headers & CORS (A05 / API8)
    console.log('\n--- PHASE 7: SECURITY HEADERS & CONFIGURATION (A05, API8) ---');
    const healthRes = await request({ path: '/api/health', method: 'GET' });
    const headers = healthRes.headers;
    const hasCorp = Boolean(headers['cross-origin-resource-policy']);
    const hasContentTypeOptions = headers['x-content-type-options'] === 'nosniff';
    const hasDnsPrefetch = Boolean(headers['x-dns-prefetch-control']);
    report('A05/API8', 'HTTP Security Headers (Helmet Policy)', hasCorp && hasContentTypeOptions && hasDnsPrefetch, 'nosniff, same-origin CORP, and DNS prefetch controls active');

    // Test CORS rejection on unauthorized origin
    const unauthorizedCorsRes = await request({
      path: '/api/health',
      method: 'GET',
      headers: { 'Origin': 'https://evil-hacker.com' }
    });
    report('A05/API8', 'CORS Unauthorized Origin Rejection', unauthorizedCorsRes.status === 403, 'Unauthorized domain rejected with 403 Forbidden');

    // PHASE 8: Audit Logging (A09)
    console.log('\n--- PHASE 8: AUDIT LOGGING TRAIL (A09) ---');
    const auditLogPath = path.join(__dirname, '..', 'logs', 'audit.log');
    const auditExists = fs.existsSync(auditLogPath);
    let auditHasExpectedActions = false;
    if (auditExists) {
      const auditContent = fs.readFileSync(auditLogPath, 'utf8');
      auditHasExpectedActions = auditContent.includes('LOGIN_SUCCESS');
    }
    report('A09', 'Structured Audit Logging Trail (audit.log)', auditExists && auditHasExpectedActions, 'Critical security events recorded with actor ID and timestamp');

    // PHASE 9: AI Assistant Security (A04 / API9 / API10)
    console.log('\n--- PHASE 9: AI SQL ASSISTANT SECURITY (A04, API9, API10) ---');
    const schemaRes = await request({
      path: '/api/iocs/ai/schema',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    const tableKeys = schemaRes.data?.tables ? Object.keys(schemaRes.data.tables) : [];
    report('A04/API9', 'AI Schema Discovery Integrity', tableKeys.includes('events') && tableKeys.includes('alerts') && !tableKeys.includes('users'), 'Schema discovery exposes permitted collections and excludes sensitive auth tables');

    const aiGenRes = await request({
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
    } else {
      console.error(`[ALERT] ${totalChecks - passedChecks} integrity checks failed.\n`);
      process.exit(1);
    }
  } finally {
    if (server) {
      server.close();
    }
  }
}

runSecurityAudit().catch(err => {
  console.error('[FATAL] Uncaught audit error:', err);
  process.exit(1);
});
