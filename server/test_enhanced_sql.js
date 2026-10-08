require('dotenv').config();
const mongoose = require('mongoose');
const { executeSql } = require('./src/services/sqlQueryService');

async function testEnhancedSql() {
  console.log('--- TESTING ENHANCED SQL QUERY SERVICE ACROSS ALL TABLES ---');
  await mongoose.connect(process.env.MONGO_URI);

  const testQueries = [
    {
      title: 'Top IP generating events',
      sql: 'SELECT source_ip, COUNT(*) AS total_events FROM events WHERE source_ip IS NOT NULL AND source_ip != "" GROUP BY source_ip ORDER BY total_events DESC LIMIT 1;'
    },
    {
      title: 'Total security events count',
      sql: 'SELECT COUNT(*) AS total_events FROM events;'
    },
    {
      title: 'Top user with failed login attempts',
      sql: "SELECT username, COUNT(*) AS failed_attempts FROM events WHERE status = 'failed' AND username IS NOT NULL AND username != '' GROUP BY username ORDER BY failed_attempts DESC LIMIT 1;"
    },
    {
      title: 'Top 10 source IPs',
      sql: 'SELECT source_ip, COUNT(*) AS total_events FROM events WHERE source_ip IS NOT NULL AND source_ip != "" GROUP BY source_ip ORDER BY total_events DESC LIMIT 10;'
    },
    {
      title: 'Unique users count',
      sql: 'SELECT COUNT(DISTINCT username) AS unique_users FROM events;'
    },
    {
      title: 'Suspicious authentication events',
      sql: "SELECT timestamp, host, username, source_ip, event_type, action, status, severity FROM events WHERE event_type = 'authentication' AND status = 'failed' ORDER BY timestamp DESC LIMIT 5;"
    },
    {
      title: 'Critical severity alerts',
      sql: "SELECT alert_id, title, severity, status, source_ip, host, count FROM alerts WHERE severity = 'critical' ORDER BY count DESC LIMIT 5;"
    },
    {
      title: 'Earliest event in dataset',
      sql: 'SELECT * FROM events ORDER BY timestamp ASC LIMIT 1;'
    },
    {
      title: 'Latest 5 security events',
      sql: 'SELECT * FROM events ORDER BY timestamp DESC LIMIT 5;'
    },
    {
      title: 'Hosts generating most alerts',
      sql: 'SELECT host, COUNT(*) AS alert_count FROM alerts WHERE host IS NOT NULL AND host != "" GROUP BY host ORDER BY alert_count DESC LIMIT 5;'
    },
    {
      title: 'Malicious IP indicators',
      sql: "SELECT indicator_value, indicator_type, reputation, confidence, source FROM indicators WHERE reputation = 'malicious' AND indicator_type = 'ip' LIMIT 5;"
    },
    {
      title: 'Threat Intel feeds with high score',
      sql: 'SELECT * FROM threat_intel WHERE score >= 75 LIMIT 5;'
    },
    {
      title: 'Forensic cases overview',
      sql: 'SELECT case_id, title, priority, status, phase FROM cases LIMIT 5;'
    }
  ];

  let passed = 0;
  for (const t of testQueries) {
    try {
      const res = await executeSql(t.sql);
      console.log(`[PASS] ${t.title}`);
      console.log(`       Query: ${t.sql}`);
      console.log(`       Execution: ${res.executionTimeMs}ms, Records: ${res.totalRecords}, Columns: [${res.columns.join(', ')}]`);
      if (res.results.length > 0) {
        console.log(`       Sample Row:`, JSON.stringify(res.results[0]));
      }
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${t.title} (${t.sql}): ${err.message}`);
    }
  }

  console.log(`\nResults: ${passed}/${testQueries.length} passed.`);
  await mongoose.disconnect();
}

testEnhancedSql().catch(console.error);
