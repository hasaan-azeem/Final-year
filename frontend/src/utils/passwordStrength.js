// passwordStrength.js
// Strength is calculated against the same rules the backend enforces,
// so the meter always reflects whether the password will actually pass.
//
// Scoring (each rule that passes = 1 point, max 5):
//   1. At least 8 characters
//   2. At least one lowercase letter       <- backend requirement
//   3. At least one uppercase letter       <- backend requirement
//   4. At least one number                 <- backend requirement
//   5. At least one special character      <- bonus, not required by backend

const rules = [
  { test: (p) => p.length >= 8,            label: "8+ characters" },
  { test: (p) => /[a-z]/.test(p),          label: "Lowercase letter" },
  { test: (p) => /[A-Z]/.test(p),          label: "Uppercase letter" },
  { test: (p) => /[0-9]/.test(p),          label: "Number" },
  { test: (p) => /[^A-Za-z0-9]/.test(p),  label: "Special character" },
];

/**
 * Returns an object describing the current password strength.
 *
 * @param {string} password
 * @returns {{
 *   label: string,
 *   color: string,
 *   score: number,       // 0-5
 *   percent: number,     // 0-100, useful for a progress bar width
 *   passedRules: string[],
 *   failedRules: string[],
 * }}
 *
 * Usage example:
 *   const strength = getPasswordStrength(password);
 *   <div className={`h-1 rounded ${strength.color}`} style={{ width: `${strength.percent}%` }} />
 *   <span>{strength.label}</span>
 */
export const getPasswordStrength = (password) => {
  if (!password) {
    return { label: "", color: "", score: 0, percent: 0, passedRules: [], failedRules: rules.map((r) => r.label) };
  }

  const passedRules = [];
  const failedRules = [];

  for (const rule of rules) {
    if (rule.test(password)) {
      passedRules.push(rule.label);
    } else {
      failedRules.push(rule.label);
    }
  }

  const score = passedRules.length; // 0-5
  const percent = (score / rules.length) * 100;

  // Weak:   passes fewer than 3 rules (definitely fails backend)
  // Fair:   passes 3 rules (may still fail backend if missing a required rule)
  // Good:   passes all 4 backend-required rules
  // Strong: passes all 5 rules including the bonus special character
  let label, color;
  if (score <= 2) {
    label = "Weak";
    color = "bg-red-500";
  } else if (score === 3) {
    label = "Fair";
    color = "bg-yellow-500";
  } else if (score === 4) {
    label = "Good";
    color = "bg-blue-500";
  } else {
    label = "Strong";
    color = "bg-emerald-500";
  }

  return { label, color, score, percent, passedRules, failedRules };
};