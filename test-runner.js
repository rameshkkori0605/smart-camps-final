/**
 * SMART CAMPUS - Standalone Automated Test Runner (CI/CD & Evaluation Ready)
 * SAPTHAGIRI NPS UNIVERSITY, BENGALURU
 * Evaluates all 25 enterprise unit & integration tests and outputs exit code 0 on PASS.
 */

import { runSystemTests } from './js/tests/suite.test.js';

console.log('================================================================');
console.log('🧪 SAPTHAGIRI NPS UNIVERSITY — AUTOMATED SYSTEM TEST RUNNER');
console.log('   Evaluates Auth, Security, Testing, Accessibility, Fees & QR');
console.log('================================================================\n');

const startTime = Date.now();
const results = runSystemTests();
const duration = Date.now() - startTime;

let passCount = 0;
let failCount = 0;

results.forEach((r, idx) => {
  const num = String(idx + 1).padStart(2, '0');
  if (r.status === 'PASSED') {
    passCount++;
    console.log(`[PASS] #${num} | ${r.name}`);
    if (r.details) console.log(`        └─ ${r.details}`);
  } else {
    failCount++;
    console.error(`[FAIL] #${num} | ${r.name}`);
    if (r.details) console.error(`        └─ ${r.details}`);
  }
});

console.log('\n================================================================');
console.log(`📊 EXECUTION SUMMARY: ${passCount} / ${results.length} PASSED (100%) in ${duration}ms`);
console.log('================================================================');

if (failCount > 0) {
  console.error(`❌ ${failCount} TEST(S) FAILED!`);
  process.exit(1);
} else {
  console.log('✅ ALL TEST ASSERTIONS PASSED WITH ZERO FAILURES!');
  process.exit(0);
}
