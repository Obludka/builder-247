import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

/**
 * Configuration interface for signature validation
 */
export interface SignatureValidationConfig {
  secretKey: string;
  /**
   * Maximum allowed age of the signature in milliseconds
   * Default is 5 minutes (300,000 ms)
   */
  signatureMaxAge?: number;
  
  /**
   * Optional custom validation logic
   */
  customValidation?: (req: Request) => boolean;
}

/**
 * Default configuration for signature validation
 */
const DEFAULT_CONFIG = {
  signatureMaxAge: 5 * 60 * 1000, // 5 minutes
};

/**
 * Signature Validation Middleware
 * Validates request signatures with configurable parameters
 */
export const signatureValidationMiddleware = (config: SignatureValidationConfig) => {
  // Merge default config with provided config
  const validationConfig = {
    ...DEFAULT_CONFIG,
    ...config
  };

  return (req: Request, res: Response, next: NextFunction) => {
    const startTime = performance.now(); // Performance tracking

    try {
      // Extract signature and timestamp from headers
      const signature = req.headers['x-signature'] as string;
      const timestampStr = req.headers['x-timestamp'] as string;

      // Validate presence of required headers
      if (!signature || !timestampStr) {
        return res.status(401).json({ 
          error: 'Signature Validation Failed', 
          message: 'Missing signature or timestamp header' 
        });
      }

      // Parse timestamp and validate
      const requestTimestamp = parseInt(timestampStr, 10);
      const currentTime = Date.now();
      
      if (isNaN(requestTimestamp)) {
        return res.status(401).json({
          error: 'Signature Validation Failed',
          message: 'Invalid timestamp format'
        });
      }

      // Check timestamp age to prevent replay attacks
      const timeDifference = Math.abs(currentTime - requestTimestamp);
      if (timeDifference > validationConfig.signatureMaxAge) {
        return res.status(401).json({
          error: 'Signature Validation Failed',
          message: 'Signature has expired'
        });
      }

      // Convert request body to a consistent string representation
      const bodyString = JSON.stringify(req.body || {});

      // Create signature using HMAC with secret key, body, and timestamp
      const expectedSignature = crypto
        .createHmac('sha256', validationConfig.secretKey)
        .update(`${bodyString}${timestampStr}`)
        .digest('hex');

      // Compare signatures
      if (signature !== expectedSignature) {
        return res.status(401).json({ 
          error: 'Signature Validation Failed', 
          message: 'Invalid signature' 
        });
      }

      // Optional custom validation
      if (validationConfig.customValidation && 
          !validationConfig.customValidation(req)) {
        return res.status(401).json({
          error: 'Signature Validation Failed',
          message: 'Custom validation failed'
        });
      }

      // Calculate and log processing time
      const processingTime = performance.now() - startTime;
      if (processingTime > 10) {
        console.warn(`Signature validation took ${processingTime.toFixed(2)}ms`);
      }

      // All checks passed, proceed to next middleware
      next();
    } catch (error) {
      // Handle any unexpected errors
      console.error('Signature validation error:', error);
      res.status(500).json({ 
        error: 'Internal Server Error', 
        message: 'Failed to validate signature' 
      });
    }
  };
};

/**
 * Utility function to generate signature for testing and client use
 * @param secretKey - Secret key for HMAC
 * @param body - Request body to sign
 * @param timestamp - Optional timestamp (defaults to current time)
 * @returns Object with signature and timestamp
 */
export const generateSignature = (
  secretKey: string, 
  body: any, 
  timestamp: number = Date.now()
): { signature: string; timestamp: number } => {
  const bodyString = JSON.stringify(body || {});
  const signature = crypto
    .createHmac('sha256', secretKey)
    .update(`${bodyString}${timestamp}`)
    .digest('hex');

  return { signature, timestamp };
};