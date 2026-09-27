/**
 * LinkGuard Scoring Model
 * Calibrated aggregation of weighted heuristic signals into a 0-100 risk score.
 */

export const RISK_THRESHOLDS = {
  LOW_MAX: 24,
  MEDIUM_MAX: 54,
  HIGH_MIN: 55
};

export const RISK_LEVELS = {
  LOW: {
    key: 'low',
    verdict: 'LOW RISK',
    badge: 'Passed Analysis',
    color: '#2E6B4F',
    bgTint: 'rgba(46, 107, 79, 0.08)',
    summary: 'No high-risk phishing indicators detected. The URL conforms to standard legitimate domain patterns.'
  },
  MEDIUM: {
    key: 'medium',
    verdict: 'MEDIUM RISK',
    badge: 'Caution Recommended',
    color: '#B8823A',
    bgTint: 'rgba(184, 130, 58, 0.10)',
    summary: 'Suspicious attributes detected. Exercise heightened vigilance and verify authenticity before entering credentials.'
  },
  HIGH: {
    key: 'high',
    verdict: 'HIGH RISK',
    badge: 'Critical Phishing Indicators',
    color: '#A63D3D',
    bgTint: 'rgba(166, 61, 61, 0.10)',
    summary: 'Severe phishing indicators identified. Strong likelihood of credential theft, brand spoofing, or deceptive redirection.'
  }
};

/**
 * Calculates aggregate risk score and assigns diagnostic verdict.
 * @param {Array<object>} checkResults
 * @returns {object}
 */
export function calculateScore(checkResults) {
  let rawScore = 0;
  let passedCount = 0;
  let failedCount = 0;

  for (const check of checkResults) {
    if (check.passed && check.scoreContribution === 0) {
      passedCount++;
    } else {
      failedCount++;
      rawScore += (check.scoreContribution || 0);
    }
  }

  // Cap score at 100
  const score = Math.min(100, Math.max(0, Math.round(rawScore)));

  let riskLevel;
  if (score <= RISK_THRESHOLDS.LOW_MAX) {
    riskLevel = RISK_LEVELS.LOW;
  } else if (score <= RISK_THRESHOLDS.MEDIUM_MAX) {
    riskLevel = RISK_LEVELS.MEDIUM;
  } else {
    riskLevel = RISK_LEVELS.HIGH;
  }

  return {
    score,
    verdict: riskLevel.verdict,
    riskKey: riskLevel.key,
    badge: riskLevel.badge,
    color: riskLevel.color,
    bgTint: riskLevel.bgTint,
    summary: riskLevel.summary,
    totalChecks: checkResults.length,
    passedCount,
    failedCount,
    checks: checkResults
  };
}
