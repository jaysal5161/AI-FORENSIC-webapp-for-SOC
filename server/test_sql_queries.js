require('dotenv').config();
const mongoose = require('mongoose');
const { executeSql } = require('./src/services/sqlQueryService');

async function testSqlEngine() {
  console.log('--- TESTING SQL QUERY ENGINE AGAINST REAL DATABASE ---');
  await mongoose.connect(process.env.MONGO_URI);

  const testQueries = [
    'SELECT * FROM indicators LIMIT 10;',
    'SELECT COUNT(*) AS total_indicators FROM indicators;',
    'SELECT indicator_type, COUNT(*) AS total FROM indicators GROUP BY indicator_type;',
    "SELECT * FROM indicators WHERE reputation = 'malicious';",
    'SELECT DISTINCT indicator_type FROM indicators;',
    'SELECT * FROM indicators ORDER BY last_seen DESC LIMIT 20;',
    "SELECT indicator_type, AVG(confidence) AS avg_conf, COUNT(*) AS total FROM indicators GROUP BY indicator_type;",
    "SELECT * FROM indicators WHERE reputation = 'malicious' AND confidence >= 80;",
    "SELECT * FROM indicators WHERE reputation IN ('malicious', 'suspicious');",
    "SELECT * FROM indicators WHERE indicator_value LIKE '%c2%' OR indicator_value LIKE '194.%';",
    "SELECT COUNT(DISTINCT indicator_type) AS total_types FROM indicators;",
    "SELECT * FROM threat_intel WHERE score > 70 LIMIT 5;"
  ];

  for (const q of testQueries) {
    try {
      const res = await executeSql(q);
      console.log(`[PASS] "${q}"`);
      console.log(`       Time: ${res.executionTimeMs}ms, Records: ${res.totalRecords}, Columns: [${res.columns.join(', ')}]`);
      if (res.results.length > 0) {
        console.log(`       Sample:`, JSON.stringify(res.results[0]));
      }
    } catch (err) {
      console.error(`[FAIL] "${q}": ${err.message}`);
    }
  }

  // Test security rejections
  const badQueries = [
    'DROP TABLE indicators;',
    'DELETE FROM indicators WHERE 1=1;',
    'SELECT * FROM users;',
    'INSERT INTO indicators VALUES (1, 2);'
  ];

  console.log('\n--- TESTING SECURITY REJECTIONS ---');
  for (const bq of badQueries) {
    try {
      await executeSql(bq);
      console.error(`[FAIL] Expected rejection for "${bq}", but it executed!`);
    } catch (err) {
      console.log(`[PASS] Correctly rejected "${bq}" -> ${err.message}`);
    }
  }

  await mongoose.disconnect();
  console.log('--- ALL SQL TESTS COMPLETED ---');
}

testSqlEngine().catch(e => {
  console.error(e);
  process.exit(1);
});
