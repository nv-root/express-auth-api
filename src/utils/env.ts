export const getEnv = (key: string, defaultValue?: string): string => {
  const value = process.env[key] || defaultValue;
  if (value === undefined) {
    throw new Error(`Missing environment variable ${key}`);
  }
  return value;
};

export const PORT = getEnv("PORT");
export const NODE_ENV = getEnv("NODE_ENV");
export const MONGO_URI = getEnv("MONGO_URI");
export const DB_NAME = getEnv("DB_NAME");
export const APP_ORIGIN = getEnv("APP_ORIGIN");
export const CLIENT_ORIGIN = getEnv("CLIENT_ORIGIN");
export const JWT_ACCESS_SECRET = getEnv("JWT_ACCESS_SECRET");
export const JWT_ACCESS_EXPIRY = getEnv("JWT_ACCESS_EXPIRY");
export const JWT_REFRESH_SECRET = getEnv("JWT_REFRESH_SECRET");
export const JWT_REFRESH_EXPIRY = getEnv("JWT_REFRESH_EXPIRY");
export const EMAIL_SENDER = getEnv("EMAIL_SENDER");
export const RESEND_API_KEY = getEnv("RESEND_API_KEY");
