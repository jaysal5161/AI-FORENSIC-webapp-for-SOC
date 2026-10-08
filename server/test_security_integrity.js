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

async function runSecurityIntegrityTests() {
  console.log('====================================================');
  console.log('   AEGIS SOC PLATFORM // SECURITY INTEGRITY TEST SUITE');
  console.log('====================================================\n');

  let testsPassed = 0;
  let totalTests = 0;

  // Helper function for logging test results
  function report(name, passed, detail = '') {
    totalTests++;
    if (passed) {
      testsPassed++;
      console.log(`[PASS] ${name}${detail ? ' -> ' + detail : ''}`);
    } else {
      console.error(`[FAIL] ${name}${detail ? ' -> ' + detail : ''}`);
    }
  }

  // 1. Authenticate as analyst & admin
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

  const analystToken = analystLogin.data.token;
  const adminToken = adminLogin.data.token;

  report('Authentication Baseline', Boolean(analystToken && adminToken), 'Analyst & Admin tokens issued');

  // 2. Test Privilege Escalation on Public Registration (OWASP A01 / API2)
  const testUsername = `sec_test_${Date.now()}`;
  const regAttempt = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/auth/register',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    username: testUsername,
    password: 'SecurePassword123!',
    fullName: 'Privilege Escalation Test',
    email: `${testUsername}@sec.test`,
    role: 'admin' // Attempting privilege escalation
  });

  const assignedRole = regAttempt.data?.user?.role;
  report(
    'A01/API2 - Privilege Escalation Prevention on Self-Registration',
    regAttempt.status === 201 && assignedRole === 'viewer',
    `Requested 'admin' role, received strictly '${assignedRole}'`
  );

  // 3. Test Static /uploads Shield (OWASP A01 / API1 / API8)
  const uploadStaticRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/uploads/evidence-c2-traffic.pcap',
    method: 'GET'
  });
  report(
    'A01/API8 - Static Uploads Directory Isolation',
    uploadStaticRes.status === 404,
    `Unauthenticated direct /uploads path returns ${uploadStaticRes.status} (Forbidden/Disabled)`
  );

  // 4. Test ReDoS & Regex Injection Resistance (OWASP A03 / API4)
  const redosRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/events?search=((a%2B)%2B)%2B%24&host=(unclosed_paren',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  report(
    'A03/API4 - ReDoS & Malformed Regex Injection Immunity',
    redosRes.status === 200,
    `Catastrophic/malformed regex handled safely with 200 OK without server crash or hanging`
  );

  // 5. Test Broken Function Level Authorization (BFLA) on Reset Data (OWASP API5)
  const analystResetRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/logs/reset-all',
    method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  report(
    'API5 - Broken Function Level Authorization Guard on Reset-All',
    analystResetRes.status === 403,
    `Analyst attempting reset-all correctly rejected with 403 Forbidden (Admin only)`
  );

  // 6. Test Detection Rule Deletion Access Control (OWASP API5)
  const rulesRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/rules',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  const firstRule = rulesRes.data[0];
  if (firstRule) {
    const analystDelRule = await request({
      host: 'localhost',
      port: 5000,
      path: `/api/rules/${firstRule._id}`,
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    report(
      'API5 - Detection Rule Deletion Guard',
      analystDelRule.status === 403,
      `Analyst deleting detection rule blocked with 403 Forbidden`
    );
  }

  // 7. Test Stored XSS Neutralization in HTML Report Export (OWASP A03)
  const casesRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/cases',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  const demoCase = casesRes.data[0];
  if (demoCase) {
    const reportHtmlRes = await request({
      host: 'localhost',
      port: 5000,
      path: `/api/reports/case/${demoCase._id}/export?format=html`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });

    const isHtmlString = typeof reportHtmlRes.data === 'string';
    const hasUnescapedScript = isHtmlString && reportHtmlRes.data.includes('<script>');
    report(
      'A03 - XSS Entity Encoding in HTML Report Export',
      reportHtmlRes.status === 200 && !hasUnescapedScript,
      `Report exported safely with Content-Type: ${reportHtmlRes.headers['content-type']}`
    );
  }

  // 8. Test Structured Security Audit Logging (OWASP A09)
  const auditLogPath = path.join(__dirname, 'logs', 'audit.log');
  const hasAuditLog = fs.existsSync(auditLogPath);
  let auditHasContent = false;
  if (hasAuditLog) {
    const auditContent = fs.readFileSync(auditLogPath, 'utf8');
    auditHasContent = auditContent.includes('[AUDIT]');
  }
  report(
    'A09 - Structured Security Audit Log Trail',
    hasAuditLog && auditHasContent,
    `audit.log records captured successfully in logs/audit.log`
  );

  console.log('\n----------------------------------------------------');
  console.log(`SUMMARY: ${testsPassed}/${totalTests} SECURITY INTEGRITY CHECKS PASSED`);
  console.log('----------------------------------------------------');

  if (testsPassed === totalTests) {
    console.log('[ALL CLEAR] 100% OF SECURITY CHECKS PASSED SUCCESSFULLY!\n');
    process.exit(0);
  } else {
    console.error('[ALERT] Some security integrity tests failed.\n');
    process.exit(1);
  }
}

runSecurityIntegrityTests().catch(err => {
  console.error('[FATAL] Uncaught error in security test runner:', err);
  process.exit(1);
});
