// src/components/scanner/scannerConstants.js
// ─────────────────────────────────────────────────────────────────────────────
// Shared constants and helpers used across scanner components
// ─────────────────────────────────────────────────────────────────────────────

export const SCAN_STEPS = [
  { label: "Initializing Scanner", desc: "Setting up scan environment" },
  { label: "Crawling Website", desc: "Discovering pages and endpoints" },
  {
    label: "Passive Security Analysis",
    desc: "Analyzing headers, cookies & configs",
  },
  {
    label: "Active Vulnerability Testing",
    desc: "Testing injection, XSS, SQLi & more",
  },
  {
    label: "Generating Report",
    desc: "Compiling findings and calculating scores",
  },
];

export const MONITOR_STEPS = [
  { label: "Initializing Monitor", desc: "Setting up monitoring environment" },
  { label: "Crawling Website", desc: "Discovering pages and changes" },
  { label: "Security Analysis", desc: "Analyzing security configurations" },
  { label: "Detecting Changes", desc: "Comparing against previous snapshots" },
  { label: "Saving Results", desc: "Storing findings to database" },
];

/**
 * Maps an API status message string to a step index (0-based).
 * Used by MultiStepLoader to highlight the current active step.
 */
export function msgToStep(msg = "") {
  const m = msg.toLowerCase();
  if (m.includes("initializ")) return 0;
  if (m.includes("crawl")) return 1;
  if (m.includes("passive") || m.includes("analyz")) return 2;
  if (m.includes("active") || m.includes("detect") || m.includes("change"))
    return 3;
  if (m.includes("complet") || m.includes("generat") || m.includes("saving"))
    return 4;
  return 0;
}
