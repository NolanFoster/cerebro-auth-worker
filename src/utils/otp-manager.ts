/**
 * OTP Management utilities for storing and retrieving OTPs from KV
 */

import { hashEmail, hashOTP, verifyOTP, generateOTP, createExpirationTime, isExpired } from './crypto';

export interface OTPRecord {
  hash: string;
  salt: string;
  expiresAt: number;
  attempts: number;
  createdAt: number;
}

export interface OTPResult {
  success: boolean;
  message: string;
  otp?: string;
}

export interface OTPVerificationResult {
  success: boolean;
  message: string;
  remainingAttempts?: number;
  user_id?: string; // Email hash for successful verification
}

const MAX_ATTEMPTS = 3;
const OTP_EXPIRY_MINUTES = 5;

/**
 * Store an OTP for an email address
 * @param otpKV - The OTP KV namespace
 * @param email - The email address
 * @param otp - The OTP to store (if not provided, generates one)
 * @param expiryMinutes - Minutes until expiry (default: 5)
 * @returns Promise<OTPResult>
 */
export async function storeOTP(
  otpKV: KVNamespace,
  email: string,
  otp?: string,
  expiryMinutes: number = OTP_EXPIRY_MINUTES
): Promise<OTPResult> {
  try {
    if (!otp) {
      otp = generateOTP();
    }

    const emailHash = await hashEmail(email);
    const { hash, salt } = await hashOTP(otp);
    const expiresAt = createExpirationTime(expiryMinutes);

    const otpRecord: OTPRecord = {
      hash,
      salt,
      expiresAt,
      attempts: 0,
      createdAt: Date.now()
    };

    // Store with TTL slightly longer than expiry to handle clock skew
    const ttlSeconds = Math.ceil(expiryMinutes * 60 * 1.1);
    await otpKV.put(emailHash, JSON.stringify(otpRecord), {
      expirationTtl: ttlSeconds
    });

    return {
      success: true,
      message: 'OTP stored successfully',
      otp
    };
  } catch (error) {
    console.error('Error storing OTP:', error);
    return {
      success: false,
      message: 'Failed to store OTP'
    };
  }
}

/**
 * Verify an OTP for an email address
 * @param otpKV - The OTP KV namespace
 * @param email - The email address
 * @param otp - The OTP to verify
 * @returns Promise<OTPVerificationResult>
 */
export async function verifyOTPForEmail(
  otpKV: KVNamespace,
  email: string,
  otp: string
): Promise<OTPVerificationResult> {
  try {
    const emailHash = await hashEmail(email);
    const recordData = await otpKV.get(emailHash);

    if (!recordData) {
      return {
        success: false,
        message: 'OTP not found or expired'
      };
    }

    const record: OTPRecord = JSON.parse(recordData);

    // Check if expired
    if (isExpired(record.expiresAt)) {
      await otpKV.delete(emailHash);
      return {
        success: false,
        message: 'OTP has expired'
      };
    }

    // Check attempts
    if (record.attempts >= MAX_ATTEMPTS) {
      await otpKV.delete(emailHash);
      return {
        success: false,
        message: 'Maximum verification attempts exceeded'
      };
    }

    // Verify OTP
    const isValid = await verifyOTP(otp, record.hash, record.salt);

    if (isValid) {
      // OTP is valid, delete it
      await otpKV.delete(emailHash);
      return {
        success: true,
        message: 'OTP verified successfully',
        user_id: emailHash
      };
    } else {
      // Increment attempts
      record.attempts += 1;
      const remainingAttempts = MAX_ATTEMPTS - record.attempts;

      if (remainingAttempts > 0) {
        // Update record with incremented attempts
        const ttlSeconds = Math.ceil((record.expiresAt - Date.now()) / 1000);
        if (ttlSeconds > 0) {
          await otpKV.put(emailHash, JSON.stringify(record), {
            expirationTtl: ttlSeconds
          });
        }

        return {
          success: false,
          message: 'Invalid OTP',
          remainingAttempts
        };
      } else {
        // Max attempts reached, delete record
        await otpKV.delete(emailHash);
        return {
          success: false,
          message: 'Invalid OTP. Maximum attempts exceeded.'
        };
      }
    }
  } catch (error) {
    console.error('Error verifying OTP:', error);
    return {
      success: false,
      message: 'Failed to verify OTP'
    };
  }
}

/**
 * Check if an OTP exists for an email (without verifying)
 * @param otpKV - The OTP KV namespace
 * @param email - The email address
 * @returns Promise<boolean>
 */
export async function hasOTP(otpKV: KVNamespace, email: string): Promise<boolean> {
  try {
    const emailHash = await hashEmail(email);
    const recordData = await otpKV.get(emailHash);
    
    if (!recordData) {
      return false;
    }

    const record: OTPRecord = JSON.parse(recordData);
    return !isExpired(record.expiresAt);
  } catch (error) {
    console.error('Error checking OTP existence:', error);
    return false;
  }
}

/**
 * Delete an OTP for an email address
 * @param otpKV - The OTP KV namespace
 * @param email - The email address
 * @returns Promise<boolean> - True if deleted successfully
 */
export async function deleteOTP(otpKV: KVNamespace, email: string): Promise<boolean> {
  try {
    const emailHash = await hashEmail(email);
    await otpKV.delete(emailHash);
    return true;
  } catch (error) {
    console.error('Error deleting OTP:', error);
    return false;
  }
}

/**
 * Get OTP statistics for monitoring
 * @param otpKV - The OTP KV namespace
 * @param email - The email address
 * @returns Promise<{exists: boolean, attempts?: number, expiresAt?: number}>
 */
export async function getOTPStats(
  otpKV: KVNamespace,
  email: string
): Promise<{exists: boolean, attempts?: number, expiresAt?: number}> {
  try {
    const emailHash = await hashEmail(email);
    const recordData = await otpKV.get(emailHash);
    
    if (!recordData) {
      return { exists: false };
    }

    const record: OTPRecord = JSON.parse(recordData);
    return {
      exists: true,
      attempts: record.attempts,
      expiresAt: record.expiresAt
    };
  } catch (error) {
    console.error('Error getting OTP stats:', error);
    return { exists: false };
  }
}
