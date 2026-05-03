// validators.js
// Mirrors the backend validate_password_strength rules exactly:
//   - 8 to 128 characters
//   - at least one uppercase letter
//   - at least one lowercase letter
//   - at least one number

export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;

export const validateEmail = (email) => {
  if (!email) return "Email is required";
  if (!/\S+@\S+\.\S+/.test(email)) return "Invalid email address";
  return "";
};

export const validatePassword = (password) => {
  if (!password) return "Password is required";
  if (password.length < MIN_PASSWORD_LENGTH)
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters long`;
  if (password.length > MAX_PASSWORD_LENGTH)
    return `Password must not exceed ${MAX_PASSWORD_LENGTH} characters`;
  if (!/[A-Z]/.test(password))
    return "Password must contain at least one uppercase letter";
  if (!/[a-z]/.test(password))
    return "Password must contain at least one lowercase letter";
  if (!/[0-9]/.test(password))
    return "Password must contain at least one number";
  return "";
};

export const validateConfirmPassword = (password, confirmPassword) => {
  if (!confirmPassword) return "Please confirm your password";
  if (password !== confirmPassword) return "Passwords do not match";
  return "";
};