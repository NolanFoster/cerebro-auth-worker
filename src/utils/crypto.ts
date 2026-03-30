/**
 * Cryptographic utilities for hashing emails and OTPs
 * Uses Web Crypto API available in Cloudflare Workers
 */

/**
 * Hash an email using SHA-256
 * @param email - The email address to hash
 * @returns Promise<string> - The hashed email as a hex string
 */
export async function hashEmail(email: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(email.toLowerCase().trim());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Hash an OTP using SHA-256 with salt
 * @param otp - The OTP to hash
 * @param salt - Optional salt (if not provided, generates random salt)
 * @returns Promise<{hash: string, salt: string}> - The hashed OTP and salt
 */
export async function hashOTP(otp: string, salt?: string): Promise<{hash: string, salt: string}> {
  if (!salt) {
    // Generate a random salt
    const saltArray = new Uint8Array(16);
    crypto.getRandomValues(saltArray);
    salt = Array.from(saltArray).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  const encoder = new TextEncoder();
  const otpData = encoder.encode(otp + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', otpData);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return { hash, salt };
}

/**
 * Verify an OTP against its hash
 * @param otp - The OTP to verify
 * @param hash - The stored hash
 * @param salt - The salt used for hashing
 * @returns Promise<boolean> - True if OTP matches
 */
export async function verifyOTP(otp: string, hash: string, salt: string): Promise<boolean> {
  const { hash: computedHash } = await hashOTP(otp, salt);
  return computedHash === hash;
}

/**
 * Generate a random OTP
 * @param length - Length of the OTP (default: 6)
 * @returns string - The generated OTP
 */
export function generateOTP(length: number = 6): string {
  const digits = '0123456789';
  let otp = '';
  
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * digits.length);
    otp += digits[randomIndex];
  }
  
  return otp;
}

/**
 * Generate a secure random token for session management
 * @param length - Length of the token in bytes (default: 32)
 * @returns string - The generated token as hex string
 */
export function generateSecureToken(length: number = 32): string {
  const tokenArray = new Uint8Array(length);
  crypto.getRandomValues(tokenArray);
  return Array.from(tokenArray).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Create a time-based expiration timestamp
 * @param minutes - Minutes from now for expiration (default: 5)
 * @returns number - Unix timestamp in milliseconds
 */
export function createExpirationTime(minutes: number = 5): number {
  return Date.now() + (minutes * 60 * 1000);
}

/**
 * Check if a timestamp has expired
 * @param timestamp - Unix timestamp in milliseconds
 * @returns boolean - True if expired
 */
export function isExpired(timestamp: number): boolean {
  return Date.now() >= timestamp;
}
