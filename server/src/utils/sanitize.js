/**
 * sanitize.js
 * Security sanitation and escaping utilities to prevent Injection (A03 / API3 / ReDoS / XSS).
 */

function escapeRegex(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sanitizeString(val, defaultVal = '') {
  if (typeof val !== 'string') return defaultVal;
  return val.replace(/\0/g, '').trim();
}

module.exports = {
  escapeRegex,
  escapeHtml,
  sanitizeString
};
