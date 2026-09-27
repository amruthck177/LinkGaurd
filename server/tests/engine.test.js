/**
 * LinkGuard Test Suite
 * Validates Parser, 10 Heuristic Rules, and Calibrated Scoring.
 */

import { parseUrl, calculateShannonEntropy, isIpAddress } from '../engine/parser.js';
import { runHeuristics, checkProtocol, checkIpHost, checkAtSymbol, checkPunycodeHomograph, checkSubdomainCount, checkHyphenDensity, checkKnownShorteners, checkSuspiciousTlds, checkBrandImpersonation, checkUrlEntropyAndLength } from '../engine/heuristics.js';
import { calculateScore } from '../engine/scoring.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${message}`);
  } else {
    failed++;
    console.error(`  ✕ FAIL: ${message}`);
  }
}

console.log('\n=============================================');
console.log('🧪 Running LinkGuard Heuristic Engine Tests');
console.log('=============================================\n');

// 1. Parser Tests
console.log('1. Parser & Character Decomposition:');
const p1 = parseUrl('https://sub.domain.example.co.uk/path/to/page?user=test#sec');
assert(p1.isValid === true, 'Parses standard HTTPS URL correctly');
assert(p1.protocol === 'https', 'Extracts https protocol');
assert(p1.tld === 'co.uk', 'Correctly identifies multi-part TLD co.uk');
assert(p1.rootDomain === 'example.co.uk', 'Extracts root domain with multi-part TLD');
assert(p1.subdomainCount === 2, 'Counts subdomains accurately');

const p2 = parseUrl('http://192.168.1.1:8080/admin');
assert(p2.isIp === true, 'Identifies IPv4 address correctly');
assert(p2.hasHttps === false, 'Detects missing HTTPS');
assert(p2.port === '8080', 'Extracts port 8080');

const p3 = parseUrl('https://user:password@target.com/login');
assert(p3.hasAtSymbol === true, 'Detects userinfo @ symbol syntax');

const p4 = parseUrl('https://xn--pypal-4ve.com');
assert(p4.isPunycode === true, 'Detects Punycode xn-- domain');

// 2. Shannon Entropy Tests
console.log('\n2. Shannon Entropy:');
const lowEntropy = calculateShannonEntropy('aaaaaaaaaaaa');
const highEntropy = calculateShannonEntropy('8xZ9kL1!mQ#90vW');
assert(lowEntropy === 0, 'Zero entropy for identical repeated characters');
assert(highEntropy > 3.5, 'High entropy for randomized alphanumeric/symbol string');

// 3. Heuristic 1: Protocol Check
console.log('\n3. Check 1 - Protocol:');
const h1_pass = checkProtocol(parseUrl('https://legit-site.com'));
assert(h1_pass.passed === true, 'Passes HTTPS protocol');
const h1_fail = checkProtocol(parseUrl('http://insecure-site.com'));
assert(h1_fail.passed === false, 'Fails HTTP protocol');

// 4. Heuristic 2: IP-Literal Host
console.log('\n4. Check 2 - IP-Literal Host:');
const h2_pass = checkIpHost(parseUrl('https://example.com'));
assert(h2_pass.passed === true, 'Passes domain name');
const h2_fail = checkIpHost(parseUrl('http://45.33.32.156/login'));
assert(h2_fail.passed === false, 'Fails IP-literal host');

// 5. Heuristic 3: @ Symbol Redirection
console.log('\n5. Check 3 - @ Symbol Redirection:');
const h3_pass = checkAtSymbol(parseUrl('https://bank.com/portal'));
assert(h3_pass.passed === true, 'Passes clean URL');
const h3_fail = checkAtSymbol(parseUrl('https://google.com@evil-site.com/auth'));
assert(h3_fail.passed === false, 'Flags @ redirect trick');

// 6. Heuristic 4: Punycode / Homograph
console.log('\n6. Check 4 - Punycode / Homograph:');
const h4_pass = checkPunycodeHomograph(parseUrl('https://apple.com'));
assert(h4_pass.passed === true, 'Passes standard ASCII domain');
const h4_fail = checkPunycodeHomograph(parseUrl('https://xn--pple-43d.com'));
assert(h4_fail.passed === false, 'Flags xn-- Punycode domain');

// 7. Heuristic 5: Subdomain Count
console.log('\n7. Check 5 - Subdomain Count:');
const h5_pass = checkSubdomainCount(parseUrl('https://portal.bank.com'));
assert(h5_pass.passed === true, 'Passes 1 subdomain');
const h5_fail = checkSubdomainCount(parseUrl('https://a.b.c.d.evil.com'));
assert(h5_fail.passed === false, 'Flags 4 chained subdomains');

// 8. Heuristic 6: Hyphen Density
console.log('\n8. Check 6 - Hyphen Density:');
const h6_pass = checkHyphenDensity(parseUrl('https://my-blog.com'));
assert(h6_pass.passed === true, 'Passes 1 hyphen');
const h6_fail = checkHyphenDensity(parseUrl('https://paypal-security-update-login-check.com'));
assert(h6_fail.passed === false, 'Flags multiple hyphens in host');

// 9. Heuristic 7: Known Shorteners
console.log('\n9. Check 7 - Known Shorteners:');
const h7_pass = checkKnownShorteners(parseUrl('https://nyt.com/article'));
assert(h7_pass.passed === true, 'Passes standard publisher');
const h7_fail = checkKnownShorteners(parseUrl('https://bit.ly/3AbCd'));
assert(h7_fail.passed === false, 'Flags bit.ly shortener');

// 10. Heuristic 8: Suspicious TLDs
console.log('\n10. Check 8 - Suspicious TLDs:');
const h8_pass = checkSuspiciousTlds(parseUrl('https://service.gov'));
assert(h8_pass.passed === true, 'Passes standard .gov');
const h8_fail = checkSuspiciousTlds(parseUrl('http://free-giveaway.tk'));
assert(h8_fail.passed === false, 'Flags suspicious .tk TLD');

// 11. Heuristic 9: Brand Impersonation
console.log('\n11. Check 9 - Brand Impersonation:');
const h9_pass = checkBrandImpersonation(parseUrl('https://www.paypal.com/signin'));
assert(h9_pass.passed === true, 'Passes legitimate brand on official domain');
const h9_fail = checkBrandImpersonation(parseUrl('https://paypal.account-verify.somedomain.net'));
assert(h9_fail.passed === false, 'Flags brand name placed in subdomain of unauthorized domain');

// 12. Heuristic 10: URL Length and Entropy
console.log('\n12. Check 10 - Length & Entropy:');
const h10_pass = checkUrlEntropyAndLength(parseUrl('https://example.com/about'));
assert(h10_pass.passed === true, 'Passes normal length and entropy');

// 13. End-to-End Scoring Calibration
console.log('\n13. End-to-End Scoring & Verdict:');

// Benign test: Google
const googleParsed = parseUrl('https://www.google.com/search?q=security');
const googleResults = runHeuristics(googleParsed);
const googleScore = calculateScore(googleResults);
assert(googleScore.score <= 10, `Legitimate Google scores low (${googleScore.score}/100)`);
assert(googleScore.riskKey === 'low', 'Google categorized as LOW RISK');

// Critical phish test: IP host + unencrypted + brand impersonation
const phishParsed = parseUrl('http://192.168.1.1/paypal/login.php');
const phishResults = runHeuristics(phishParsed);
const phishScore = calculateScore(phishResults);
assert(phishScore.score >= 60, `Dangerous phishing link scores high (${phishScore.score}/100)`);
assert(phishScore.riskKey === 'high', 'Dangerous phishing link categorized as HIGH RISK');

// Medium risk test: Bit.ly shortener on HTTPS
const shortenerParsed = parseUrl('https://bit.ly/4xY90z');
const shortenerResults = runHeuristics(shortenerParsed);
const shortenerScore = calculateScore(shortenerResults);
assert(shortenerScore.riskKey === 'medium' || shortenerScore.score >= 25, `Shortener scored as caution (${shortenerScore.score}/100)`);

console.log('\n=============================================');
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('=============================================\n');

if (failed > 0) {
  process.exit(1);
}
