import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

/**
 * Configuration interface for signature validation
 */
export interface SignatureValidationConfig {
  secretKey: string;
  /**
   * Maximum allowed age of the signature in milliseconds
   * Default is 5 minutes
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

      // Check if signature and timestamp are present
      if (!signature || !timestampStr) {
        return res.status(401).json({ 
          error: 'Signature validation failed', 
          message: 'Missing signature or timestamp' 
        });
      }

      // Validate timestamp to prevent replay attacks
      const requestTimestamp = parseInt(timestampStr, 10);
      const currentTime = Date.now();
      
      if (isNaN(requestTimestamp)) {
        return res.status(401).json({
          error: 'Signature validation failed',
          message: 'Invalid timestamp format'
        });
      }

      // Check if timestamp is within the allowed age
      if (Math.abs(currentTime - requestTimestamp) > validationConfig.signatureMaxAge) {
        return res.status(401).json({
          error: 'Signature validation failed',
          message: 'Signature has expired'
        });
      }

      // Convert request body to string for consistent signing
      const bodyString = JSON.stringify(req.body);

      // Create a hash using the secret key, body, and timestamp
      const expectedSignature = crypto
        .createHmac('sha256', validationConfig.secretKey)
        .update(`${bodyString}${timestampStr}`)
        .digest('hex');

      // Compare the signatures
      if (signature !== expectedSignature) {
        return res.status(401).json({ 
          error: 'Signature validation failed', 
          message: 'Invalid signature' 
        });
      }

      // Optional custom validation
      if (validationConfig.customValidation && 
          !validationConfig.customValidation(req)) {
        return res.status(401).json({
          error: 'Signature validation failed',
          message: 'Custom validation failed'
        });
      }

      // Calculate and log middleware processing time
      const processingTime = performance.now() - startTime;
      if (processingTime > 10) {
        console.warn(`Signature validation took ${processingTime}ms`);
      }

      // If all checks pass, proceed to the next middleware
      next();
    } catch (error) {
      // Handle any unexpected errors during signature validation
      console.error('Signature validation error:', error);
      res.status(500).json({ 
        error: 'Internal server error', 
        message: 'Failed to validate signature' 
      });
    }
  };
};

/**
 * Utility function to generate signature for testing and client use
 */
export const generateSignature = (
  secretKey: string, 
  body: any, 
  timestamp: number = Date.now()
): { signature: string; timestamp: number } => {
  const bodyString = JSON.stringify(body);
  const signature = crypto
    .createHmac('sha256', secretKey)
    .update(`${bodyString}${timestamp}`)
    .digest('hex');

  return { signature, timestamp };
};