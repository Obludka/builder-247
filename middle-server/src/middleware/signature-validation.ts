import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

/**
 * Signature Validation Middleware
 * Validates the signature of incoming requests to ensure data integrity and authenticity
 */
export const signatureValidationMiddleware = (secretKey: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Extract signature from headers or body
      const signature = req.headers['x-signature'] as string;
      
      // Check if signature is present
      if (!signature) {
        return res.status(401).json({ 
          error: 'Signature validation failed', 
          message: 'Missing signature' 
        });
      }

      // Convert request body to string for consistent signing
      const bodyString = JSON.stringify(req.body);

      // Create a hash using the secret key and request body
      const expectedSignature = crypto
        .createHmac('sha256', secretKey)
        .update(bodyString)
        .digest('hex');

      // Compare the signatures
      if (signature !== expectedSignature) {
        return res.status(401).json({ 
          error: 'Signature validation failed', 
          message: 'Invalid signature' 
        });
      }

      // If signature is valid, proceed to the next middleware
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

// Utility function to generate signature for testing and client use
export const generateSignature = (secretKey: string, body: any): string => {
  const bodyString = JSON.stringify(body);
  return crypto
    .createHmac('sha256', secretKey)
    .update(bodyString)
    .digest('hex');
};