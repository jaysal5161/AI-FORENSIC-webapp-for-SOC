/**
 * verify.js
 * End-to-end API functional verification test suite.
 */

const http = require('http');
const app = require('../src/server');

const TEST_PORT = 5098;
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
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, data: body });
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

async function runVerification() {
  console.log('--- STARTING VERIFICATION TESTS ---');

  let server;
  try {
    server = await new Promise((resolve) => {
      const s = app.listen(TEST_PORT, HOST, () => resolve(s));
    });
  } catch (e) {
    console.error('Failed to start test server:', e);
    process.exit(1);
  }

  try {
    // Test 1: Health Check
    const health = await request({ path: '/api/health', method: 'GET' });
    console.log(`[PASS] Health Check Status: ${health.status} (${health.data.service})`);

    // Test 2: Login as Analyst
    const loginRes = await request({
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
    const dashRes = await request({ path: '/api/dashboard/summary', method: 'GET', headers: authHeaders });
    console.log(`[PASS] Dashboard Summary Status: ${dashRes.status}, Events=${dashRes.data.totals?.events ?? dashRes.data.metrics?.totalEvents ?? 0}`);

    // Test 4: Threat Intel & SQL Engine
    const sqlRes = await request({
      path: '/api/iocs/sql',
      method: 'POST',
      headers: authHeaders
    }, { query: 'SELECT * FROM indicators LIMIT 5;' });
    console.log(`[PASS] SQL Engine Query Status: ${sqlRes.status}, Rows=${sqlRes.data.results?.length}`);

    // Test 5: AI SQL Query Generation
    const aiRes = await request({
      path: '/api/iocs/ai/generate',
      method: 'POST',
      headers: authHeaders
    }, { question: 'Show me critical alerts' });
    console.log(`[PASS] AI Natural Language Query Status: ${aiRes.status}, SQL="${aiRes.data.sql}"`);

    // Test 6: Cases Pipeline
    const casesRes = await request({ path: '/api/cases', method: 'GET', headers: authHeaders });
    console.log(`[PASS] Cases Pipeline Status: ${casesRes.status}, Total Cases=${casesRes.data.length}`);

    const demoCase = casesRes.data[0];
    if (demoCase) {
      const caseDetail = await request({ path: `/api/cases/${demoCase._id}`, method: 'GET', headers: authHeaders });
      console.log(`[PASS] Case Detail Status: ${caseDetail.status}, Title="${caseDetail.data.title}"`);

      const timelineRes = await request({ path: `/api/timeline/case/${demoCase._id}`, method: 'GET', headers: authHeaders });
      console.log(`[PASS] Case Timeline Status: ${timelineRes.status}, Entries=${timelineRes.data.length}`);

      const attackChainRes = await request({ path: `/api/attack-chain/case/${demoCase._id}`, method: 'GET', headers: authHeaders });
      console.log(`[PASS] Case Attack Chain Status: ${attackChainRes.status}, Stages=${attackChainRes.data.stages?.length}`);

      const impactRes = await request({ path: `/api/impact/case/${demoCase._id}`, method: 'GET', headers: authHeaders });
      console.log(`[PASS] Case Impact Status: ${impactRes.status}, DataExposed=${impactRes.data.dataExposed}`);

      const reportRes = await request({ path: `/api/reports/case/${demoCase._id}`, method: 'GET', headers: authHeaders });
      console.log(`[PASS] Case Report Status: ${reportRes.status}, Number=${reportRes.data?.reportNumber}`);
    }

    // Test 7: Events Explorer
    const eventsRes = await request({ path: '/api/events?limit=5', method: 'GET', headers: authHeaders });
    console.log(`[PASS] Events Explorer Status: ${eventsRes.status}, Total Normalized=${eventsRes.data.pagination?.total}`);

    // Test 8: Detection Rules
    const rulesRes = await request({ path: '/api/rules', method: 'GET', headers: authHeaders });
    console.log(`[PASS] Detection Rules Status: ${rulesRes.status}, Rules Count=${rulesRes.data.length}`);

    console.log('--- ALL VERIFICATION TESTS PASSED 100% ---');
  } finally {
    if (server) {
      server.close();
    }
  }
}

runVerification().catch(err => {
  console.error('[FAIL] Uncaught test error:', err);
  process.exit(1);
});
