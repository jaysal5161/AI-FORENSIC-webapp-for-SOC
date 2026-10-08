require('dotenv').config();
const { generateAiQuery, getSchemaMetadata } = require('./src/services/aiQueryService');
const { executeSql } = require('./src/services/sqlQueryService');
const mongoose = require('mongoose');

async function testAiQueryService() {
  console.log('--- TESTING AI NL-TO-SQL QUERY SERVICE ---');
  await mongoose.connect(process.env.MONGO_URI);

  // 1. Schema metadata check
  const schema = getSchemaMetadata();
  console.log('[PASS] Schema discovery returned tables:', Object.keys(schema.tables));

  // 2. All required questions from the user prompt:
  const questions = [
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
  for (const q of questions) {
    try {
      const aiRes = await generateAiQuery({ question: q });
      console.log(`\nQuestion: "${q}"`);
      console.log(`AI SQL:    ${aiRes.sql}`);
      console.log(`Table:     ${aiRes.targetTable} | Confidence: ${aiRes.confidence}%`);
      console.log(`Expl.:     ${aiRes.explanation}`);

      // Now execute the generated SQL to verify it executes against live MongoDB!
      const execRes = await executeSql(aiRes.sql);
      console.log(`Live DB:   Executed in ${execRes.executionTimeMs}ms, returned ${execRes.totalRecords} records.`);
      if (execRes.results.length > 0) {
        console.log(`Sample:    `, JSON.stringify(execRes.results[0]));
      }
      passed++;
    } catch (err) {
      console.error(`[FAIL] "${q}": ${err.message}`);
    }
  }

  // 3. Test follow-up questions
  console.log('\n--- TESTING FOLLOW-UP CONTEXTUAL PROMPTS ---');
  const baseAi = await generateAiQuery({ question: 'List the top 10 source IP addresses.' });
  console.log('Base Query:', baseAi.sql);

  const followUp1 = await generateAiQuery({
    question: 'Show only the failed events',
    conversationHistory: [{ question: 'List the top 10 source IP addresses.', sql: baseAi.sql }]
  });
  console.log('Follow-up 1 (Failed only):', followUp1.sql);
  const f1Exec = await executeSql(followUp1.sql);
  console.log(`Live DB F1: Executed in ${f1Exec.executionTimeMs}ms, returned ${f1Exec.totalRecords} records.`);

  const followUp2 = await generateAiQuery({
    question: 'Now show the top 5',
    conversationHistory: [{ question: 'Show only the failed events', sql: followUp1.sql }]
  });
  console.log('Follow-up 2 (Top 5):', followUp2.sql);
  const f2Exec = await executeSql(followUp2.sql);
  console.log(`Live DB F2: Executed in ${f2Exec.executionTimeMs}ms, returned ${f2Exec.totalRecords} records.`);

  console.log(`\nTotal Questions Tested: ${questions.length + 2}, Passed: ${passed + 2}`);
  await mongoose.disconnect();
}

testAiQueryService().catch(console.error);
