import { signatureValidationMiddleware, generateSignature } from '../../src/middleware/signature-validation';
import { Request, Response, NextFunction } from 'express';

describe('Signature Validation Middleware', () => {
  const secretKey = 'test-secret-key';
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: jest.MockedFunction<NextFunction>;

  beforeEach(() => {
    mockRequest = {
      headers: {},
      body: {}
    };
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    mockNext = jest.fn();
  });

  it('should validate a valid signature', () => {
    // Prepare a test body
    const testBody = { 
      data: 'test data', 
      timestamp: new Date().toISOString() 
    };

    // Generate a valid signature
    const validSignature = generateSignature(secretKey, testBody);

    // Setup mock request with valid signature
    mockRequest.headers = { 'x-signature': validSignature };
    mockRequest.body = testBody;

    // Call middleware
    const middleware = signatureValidationMiddleware(secretKey);
    middleware(
      mockRequest as Request, 
      mockResponse as Response, 
      mockNext
    );

    // Expect next to be called
    expect(mockNext).toHaveBeenCalled();
    expect(mockResponse.status).not.toHaveBeenCalled();
  });

  it('should reject request with missing signature', () => {
    // No signature in headers
    mockRequest.body = { data: 'test data' };

    // Call middleware
    const middleware = signatureValidationMiddleware(secretKey);
    middleware(
      mockRequest as Request, 
      mockResponse as Response, 
      mockNext
    );

    // Expect unauthorized response
    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'Signature validation failed',
        message: 'Missing signature'
      })
    );
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should reject request with invalid signature', () => {
    // Prepare a test body
    const testBody = { 
      data: 'test data', 
      timestamp: new Date().toISOString() 
    };

    // Generate an invalid signature
    const invalidSignature = 'invalid-signature';

    // Setup mock request with invalid signature
    mockRequest.headers = { 'x-signature': invalidSignature };
    mockRequest.body = testBody;

    // Call middleware
    const middleware = signatureValidationMiddleware(secretKey);
    middleware(
      mockRequest as Request, 
      mockResponse as Response, 
      mockNext
    );

    // Expect unauthorized response
    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'Signature validation failed',
        message: 'Invalid signature'
      })
    );
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should generate consistent signatures', () => {
    const testBody = { 
      data: 'test data', 
      timestamp: '2023-01-01T00:00:00.000Z' 
    };

    // Generate signatures multiple times
    const signature1 = generateSignature(secretKey, testBody);
    const signature2 = generateSignature(secretKey, testBody);

    // Signatures should be identical
    expect(signature1).toBe(signature2);
  });
});