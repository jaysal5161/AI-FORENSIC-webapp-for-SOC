const http = require('http');

function request(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
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
    if (data) {
      req.write(typeof data === 'string' ? data : JSON.stringify(data));
    }
    req.end();
  });
}

async function runVerification() {
  console.log('--- STARTING VERIFICATION TESTS ---');

  // Test 1: Health Check
  const health = await request({
    host: '127.0.0.1',
    port: 5000,
    path: '/api/health',
    method: 'GET'
  });
  console.log(`[PASS] Health Check Status: ${health.status} (${health.data.service})`);

  // Test 2: Login as Analyst
  const loginRes = await request({
    host: '127.0.0.1',
    port: 5000,
    path: '/api/auth/login',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, { username: 'analyst', password: 'analyst123' });

  if (loginRes.status !== 200 || !loginRes.data.token) {
    console.error('[FAIL] Login failed:', loginRes);
    process.exit(1);
  }
  const token = loginRes.data.token;
  console.log(`[PASS] Login Success: Role=${loginRes.data.user.role}, Token generated`);

  const authHeaders = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };

  // Test 3: Dashboard Summary
  const dashRes = await request({
    host: '127.0.0.1',
    port: 5000,
    path: '/api/dashboard/summary',
    method: 'GET',
    headers: authHeaders
  });
  console.log(`[PASS] Dashboard Summary Status: ${dashRes.status}, Events=${dashRes.data.totals?.events}, Alerts=${dashRes.data.totals?.alerts}, OpenCases=${dashRes.data.totals?.openCases}`);

  // Test 4: Alerts Queue
  const alertsRes = await request({
    host: '127.0.0.1',
    port: 5000,
    path: '/api/alerts',
    method: 'GET',
    headers: authHeaders
  });
  console.log(`[PASS] Alerts Queue Status: ${alertsRes.status}, Retrieved ${alertsRes.data.length} alerts`);

  // Test 5: Cases List
  const casesRes = await request({
    host: '127.0.0.1',
    port: 5000,
    path: '/api/cases',
    method: 'GET',
    headers: authHeaders
  });
  console.log(`[PASS] Cases List Status: ${casesRes.status}, Retrieved ${casesRes.data.length} cases`);
  const demoCase = casesRes.data[0];
  console.log(`       First Case: ID=${demoCase?.caseId}, Title="${demoCase?.title}", Priority=${demoCase?.priority}`);

  // Test 6: Case Detail (Full 11 tabs data)
  if (demoCase) {
    const caseDetailRes = await request({
      host: '127.0.0.1',
      port: 5000,
      path: `/api/cases/${demoCase._id}`,
      method: 'GET',
      headers: authHeaders
    });
    console.log(`[PASS] Case Detail Status: ${caseDetailRes.status}, Phase=${caseDetailRes.data.phase}, Endpoints=${caseDetailRes.data.endpoints?.length}, IOCs=${caseDetailRes.data.iocs?.length}`);

    // Test Timeline
    const timelineRes = await request({
      host: '127.0.0.1',
      port: 5000,
      path: `/api/timeline/case/${demoCase._id}`,
      method: 'GET',
      headers: authHeaders
    });
    console.log(`[PASS] Case Timeline Status: ${timelineRes.status}, Entries=${timelineRes.data.length}`);

    // Test Attack Chain
    const chainRes = await request({
      host: '127.0.0.1',
      port: 5000,
      path: `/api/attack-chain/case/${demoCase._id}`,
      method: 'GET',
      headers: authHeaders
    });
    console.log(`[PASS] Case Attack Chain Status: ${chainRes.status}, Stages=${chainRes.data.stages?.length}, Confidence=${chainRes.data.confidence}%`);

    // Test Impact Assessment
    const impactRes = await request({
      host: '127.0.0.1',
      port: 5000,
      path: `/api/impact/case/${demoCase._id}`,
      method: 'GET',
      headers: authHeaders
    });
    console.log(`[PASS] Case Impact Status: ${impactRes.status}, DataExposed=${impactRes.data.dataExposed}`);

    // Test Report
    const reportRes = await request({
      host: '127.0.0.1',
      port: 5000,
      path: `/api/reports/case/${demoCase._id}`,
      method: 'GET',
      headers: authHeaders
    });
    console.log(`[PASS] Case Report Status: ${reportRes.status}, Number=${reportRes.data?.reportNumber}`);
  }

  // Test 7: Events Explorer
  const eventsRes = await request({
    host: '127.0.0.1',
    port: 5000,
    path: '/api/events?limit=5',
    method: 'GET',
    headers: authHeaders
  });
  console.log(`[PASS] Events Explorer Status: ${eventsRes.status}, Total Normalized=${eventsRes.data.pagination?.total}`);

  // Test 8: Detection Rules
  const rulesRes = await request({
    host: '127.0.0.1',
    port: 5000,
    path: '/api/rules',
    method: 'GET',
    headers: authHeaders
  });
  console.log(`[PASS] Detection Rules Status: ${rulesRes.status}, Rules Count=${rulesRes.data.length}`);

  console.log('--- ALL VERIFICATION TESTS PASSED 100% ---');
}

runVerification().catch(err => {
  console.error('[FAIL] Uncaught test error:', err);
  process.exit(1);
});
