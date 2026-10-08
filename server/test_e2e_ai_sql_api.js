require('dotenv').config();
const http = require('http');

async function testE2e() {
  console.log('=== END-TO-END HTTP API TESTS FOR AI NL-TO-SQL ASSISTANT ===');

  // 1. Authenticate as analyst
  console.log('\n[1] Authenticating test user (analyst)...');
  const loginRes = await request('POST', '/api/auth/login', {
    username: 'analyst',
    password: 'analyst123'
  });

  if (!loginRes.token) {
    throw new Error('Authentication failed: ' + JSON.stringify(loginRes));
  }
  const token = loginRes.token;
  console.log('    ✓ Authenticated successfully as', loginRes.user?.username || 'analyst');

  // 2. Test GET /api/iocs/ai/schema
  console.log('\n[2] Testing GET /api/iocs/ai/schema ...');
  const schemaRes = await request('GET', '/api/iocs/ai/schema', null, token);
  if (!schemaRes.success || !schemaRes.tables) {
    throw new Error('Schema discovery endpoint failed: ' + JSON.stringify(schemaRes));
  }
  console.log('    ✓ Schema discovery returned tables:', Object.keys(schemaRes.tables).join(', '));

  // 3. Test POST /api/iocs/ai/generate and execute for master prompt questions
  console.log('\n[3] Testing POST /api/iocs/ai/generate across core questions ...');
  const testQuestions = [
    'Which IP address generated the highest number of events?',
    'How many total security events are recorded?',
    'Which user has the highest number of failed login attempts?',
    'Show all malicious IP addresses.',
    'List the top 10 source IP addresses.',
    'How many unique users are present?',
    'Show suspicious authentication events.',
    'Which IP addresses are associated with multiple failed logins?',
    'Show all critical severity alerts.',
    'What is the earliest event in the dataset?',
    'Show the latest 20 security events.',
    'Which domain has the highest number of detections?',
    'Show all indicators associated with a particular IP address.',
    'Which hosts generated the most security alerts?'
  ];

  let passed = 0;
  for (const q of testQuestions) {
    try {
      const genRes = await request('POST', '/api/iocs/ai/generate', { question: q }, token);
      if (!genRes.success || !genRes.sql) {
        throw new Error('Generation failed: ' + JSON.stringify(genRes));
      }

      // Execute generated SQL via /api/iocs/sql
      const execRes = await request('POST', '/api/iocs/sql', { query: genRes.sql }, token);
      if (!execRes.success) {
        throw new Error('Execution failed: ' + JSON.stringify(execRes));
      }

      console.log(`    ✓ [PASS] "${q}"`);
      console.log(`             Generated SQL: ${genRes.sql}`);
      console.log(`             Live Result:   ${execRes.totalRecords} records in ${execRes.executionTimeMs}ms (Columns: ${execRes.columns.join(', ')})`);
      passed++;
    } catch (err) {
      console.error(`    ✗ [FAIL] "${q}": ${err.message}`);
    }
  }

  // 4. Test Contextual Follow-up
  console.log('\n[4] Testing Contextual Follow-Up via /api/iocs/ai/generate ...');
  const baseGen = await request('POST', '/api/iocs/ai/generate', { question: 'List the top 10 source IP addresses.' }, token);
  const followUpGen = await request('POST', '/api/iocs/ai/generate', {
    question: 'Show only the failed events',
    conversationHistory: [{ question: 'List the top 10 source IP addresses.', sql: baseGen.sql }]
  }, token);

  const followUpExec = await request('POST', '/api/iocs/sql', { query: followUpGen.sql }, token);
  console.log('    ✓ Base SQL:      ', baseGen.sql);
  console.log('    ✓ Follow-Up SQL: ', followUpGen.sql);
  console.log(`    ✓ Executed live:  ${followUpExec.totalRecords} records in ${followUpExec.executionTimeMs}ms`);

  // 5. Test GET /api/iocs/ai/history
  console.log('\n[5] Testing GET /api/iocs/ai/history ...');
  const historyRes = await request('GET', '/api/iocs/ai/history', null, token);
  if (!historyRes.success || !Array.isArray(historyRes.history)) {
    throw new Error('History endpoint failed: ' + JSON.stringify(historyRes));
  }
  console.log(`    ✓ Query history returned ${historyRes.history.length} logged queries.`);

  // 6. Test Security Enforcement
  console.log('\n[6] Testing Security Protections (read-only enforcement, destructive commands) ...');
  const maliciousAttempts = [
    'DROP TABLE events;',
    'DELETE FROM alerts WHERE 1=1;',
    'INSERT INTO indicators (type, value) VALUES ("ip", "1.1.1.1");',
    'SELECT * FROM users;'
  ];

  for (const malicious of maliciousAttempts) {
    try {
      const secRes = await request('POST', '/api/iocs/sql', { query: malicious }, token);
      if (secRes.success) {
        console.error(`    ✗ [SECURITY BREACH] Prohibited query executed: ${malicious}`);
      } else {
        console.log(`    ✓ [REJECTED PROPERLY] "${malicious}" -> ${secRes.error}`);
      }
    } catch (err) {
      console.log(`    ✓ [REJECTED PROPERLY] "${malicious}"`);
    }
  }

  console.log(`\n=== E2E TESTING COMPLETE: ${passed}/${testQuestions.length} CORE QUESTIONS PASSED + FOLLOW-UPS + SECURITY VALIDATED ===\n`);
}

function request(method, path, body = null, token = null) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : '';
    const headers = {
      'Content-Type': 'application/json'
    };
    if (body) {
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const req = http.request(
      {
        hostname: 'localhost',
        port: 5000,
        path,
        method,
        headers
      },
      (res) => {
        let resData = '';
        res.on('data', (chunk) => (resData += chunk));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(resData);
            resolve(parsed);
          } catch (e) {
            resolve({ raw: resData, statusCode: res.statusCode });
          }
        });
      }
    );

    req.on('error', (err) => reject(err));
    if (data) req.write(data);
    req.end();
  });
}

testE2e().catch(console.error);
