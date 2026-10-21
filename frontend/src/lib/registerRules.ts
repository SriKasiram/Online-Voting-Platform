/**
 * Registration rules, the same as the server's (backend/app/config.py). These
 * only give quick feedback: the server checks everything again.
 */

export const PASSWORD_MIN_LENGTH = 12;
const USERNAME = /^[A-Za-z0-9._]{3,32}$/;

/** What is wrong with a username, or "" when it is fine. */
export function usernameProblem(username: string): string {
  return USERNAME.test(username.trim()) ? "" : "Use 3 to 32 letters, digits, dots or underscores.";
}

/** What is wrong with a password, or "" when it is fine. Length is the only rule. */
export function passwordProblem(password: string, username: string): string {
  // Counted in characters, as the server counts them, not UTF-16 units
  if ([...password].length < PASSWORD_MIN_LENGTH) return `Use at least ${PASSWORD_MIN_LENGTH} characters.`;
  if (password.toLowerCase() === username.trim().toLowerCase()) return "Your password must not be your username.";
  return "";
}

/** Splits an authenticator setup key into groups of four, so it is easier to type. */
export function formatSecret(secret: string): string {
  return secret.replace(/(.{4})(?=.)/g, "$1 ");
}
