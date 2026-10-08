const http = require('http');

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

async function runEndToEndTests() {
  console.log('================================================================');
  console.log('   RAPID INDICATOR REPUTATION LOOKUP & SQL ENGINE VALIDATION   ');
  console.log('================================================================\n');

  let passed = 0;
  let total = 0;

  function assert(title, condition, detail = '') {
    total++;
    if (condition) {
      passed++;
      console.log(`[PASS] ${title}${detail ? ' -> ' + detail : ''}`);
    } else {
      console.error(`[FAIL] ${title}${detail ? ' -> ' + detail : ''}`);
    }
  }

  // 1. Login as analyst
  const loginRes = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/auth/login',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, { username: 'analyst', password: 'analyst123' });

  assert('Analyst Authentication', loginRes.status === 200 && Boolean(loginRes.data?.token));
  const token = loginRes.data.token;
  const authHeaders = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };

  // --- SECTION A: RAPID INDICATOR REPUTATION LOOKUPS (TASK 3) ---
  console.log('\n--- TESTING RAPID INDICATOR REPUTATION LOOKUP ---');

  // Test A1: IPv4 Lookup with Auto-detection
  const ipLookup = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/lookup',
    method: 'POST',
    headers: authHeaders
  }, { value: '194.26.29.112' });

  assert(
    'IPv4 Reputation Lookup (194.26.29.112)',
    ipLookup.status === 200 &&
    ipLookup.data.type === 'ip' &&
    ipLookup.data.verdict === 'malicious' &&
    ipLookup.data.confidence === 98 &&
    ipLookup.data.threatIntel?.source === 'AlienVault OTX',
    `Verdict: ${ipLookup.data?.verdict}, Feed: ${ipLookup.data?.source}, Alerts: ${ipLookup.data?.associatedAlerts?.length}`
  );

  // Test A2: Domain Lookup with Auto-detection
  const domainLookup = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/lookup',
    method: 'POST',
    headers: authHeaders
  }, { value: 'evil-c2-tunnel.ru' });

  assert(
    'Domain Reputation Lookup (evil-c2-tunnel.ru)',
    domainLookup.status === 200 &&
    domainLookup.data.type === 'domain' &&
    domainLookup.data.verdict === 'malicious' &&
    domainLookup.data.threatIntel?.source === 'Mandiant Threat Intelligence',
    `Verdict: ${domainLookup.data?.verdict}, Feed: ${domainLookup.data?.source}`
  );

  // Test A3: SHA256 Hash Lookup with Auto-detection
  const hashLookup = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/lookup',
    method: 'POST',
    headers: authHeaders
  }, { value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' });

  assert(
    'SHA256 Hash Reputation Lookup',
    hashLookup.status === 200 &&
    hashLookup.data.type === 'hash' &&
    hashLookup.data.verdict === 'malicious' &&
    hashLookup.data.threatIntel?.source === 'VirusTotal',
    `Verdict: ${hashLookup.data?.verdict}, Feed: ${hashLookup.data?.source}`
  );

  // Test A4: Unknown Indicator Distinction
  const unknownLookup = await request({
    host: 'localhost',
    port: 5000,
    path: '/api/iocs/lookup',
    method: 'POST',
    headers: authHeaders
  }, { value: '10.99.88.77' });

  assert(
    'Unknown Indicator Distinction (No Intelligence Available)',
    unknownLookup.status === 200 &&
    unknownLookup.data.verdict === 'no intelligence available' &&
    unknownLookup.data.confidence === 0,
    `Verdict: ${unknownLookup.data?.verdict}`
  );

  // --- SECTION B: SQL QUERY ENGINE API (TASKS 2 & 5) ---
  console.log('\n--- TESTING SQL QUERY ENGINE HTTP API ---');

  const sqlTests = [
    {
      name: 'Query 1: SELECT * FROM indicators LIMIT 10;',
      sql: 'SELECT * FROM indicators LIMIT 10;',
      check: (d) => d.success && d.results.length === 10 && d.columns.includes('indicator_value')
    },
    {
      name: 'Query 2: SELECT COUNT(*) AS total_indicators FROM indicators;',
      sql: 'SELECT COUNT(*) AS total_indicators FROM indicators;',
      check: (d) => d.success && d.results.length === 1 && typeof d.results[0].total_indicators === 'number'
    },
    {
      name: 'Query 3: SELECT indicator_type, COUNT(*) AS total FROM indicators GROUP BY indicator_type;',
      sql: 'SELECT indicator_type, COUNT(*) AS total FROM indicators GROUP BY indicator_type;',
      check: (d) => d.success && d.results.length > 0 && d.results[0].indicator_type && d.results[0].total
    },
    {
      name: 'Query 4: SELECT * FROM indicators WHERE reputation = \'malicious\';',
      sql: "SELECT * FROM indicators WHERE reputation = 'malicious';",
      check: (d) => d.success && d.results.length > 0 && d.results.every(r => r.reputation === 'malicious')
    },
    {
      name: 'Query 5: SELECT DISTINCT indicator_type FROM indicators;',
      sql: 'SELECT DISTINCT indicator_type FROM indicators;',
      check: (d) => d.success && d.results.length > 0 && d.columns.includes('indicator_type')
    },
    {
      name: 'Query 6: SELECT * FROM indicators ORDER BY last_seen DESC LIMIT 20;',
      sql: 'SELECT * FROM indicators ORDER BY last_seen DESC LIMIT 20;',
      check: (d) => d.success && d.results.length === 20
    },
    {
      name: 'Query 7: Threat Intel score query',
      sql: 'SELECT * FROM threat_intel WHERE score >= 90 LIMIT 5;',
      check: (d) => d.success && d.results.length > 0 && d.results[0].score >= 90
    }
  ];

  for (const st of sqlTests) {
    const res = await request({
      host: 'localhost',
      port: 5000,
      path: '/api/iocs/sql',
      method: 'POST',
      headers: authHeaders
    }, { query: st.sql });

    assert(st.name, res.status === 200 && st.check(res.data), `Rows: ${res.data?.totalRecords}, Time: ${res.data?.executionTimeMs}ms`);
  }

  // --- SECTION C: SQL SECURITY & ERROR REJECTION ---
  console.log('\n--- TESTING SQL SECURITY & REJECTION ---');

  const badSqlList = [
    { name: 'Reject DROP TABLE', sql: 'DROP TABLE indicators;' },
    { name: 'Reject DELETE', sql: 'DELETE FROM indicators WHERE 1=1;' },
    { name: 'Reject Inaccessible Table', sql: 'SELECT * FROM users;' }
  ];

  for (const bs of badSqlList) {
    const res = await request({
      host: 'localhost',
      port: 5000,
      path: '/api/iocs/sql',
      method: 'POST',
      headers: authHeaders
    }, { query: bs.sql });

    assert(
      bs.name,
      res.status === 400 && res.data.success === false && Boolean(res.data.error),
      `Status: ${res.status}, Error: ${res.data?.error}`
    );
  }

  console.log('\n================================================================');
  console.log(`SUMMARY: ${passed}/${total} RAPID LOOKUP & SQL INTEGRITY TESTS PASSED`);
  console.log('================================================================');

  if (passed === total) {
    console.log('[ALL CLEAR] 100% OF TESTS PASSED SUCCESSFULLY!\n');
    process.exit(0);
  } else {
    console.error('[ERROR] Some tests failed.\n');
    process.exit(1);
  }
}

runEndToEndTests().catch(e => {
  console.error('[FATAL] Uncaught error in test runner:', e);
  process.exit(1);
});
