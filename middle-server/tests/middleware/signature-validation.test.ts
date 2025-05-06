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

  // Scenario 1: Valid signature validation
  it('should validate a valid signature', () => {
    const testBody = { data: 'test data' };
    const { signature, timestamp } = generateSignature(secretKey, testBody);

    mockRequest.headers = { 
      'x-signature': signature,
      'x-timestamp': timestamp.toString()
    };
    mockRequest.body = testBody;

    const middleware = signatureValidationMiddleware({ secretKey });
    middleware(
      mockRequest as Request, 
      mockResponse as Response, 
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    expect(mockResponse.status).not.toHaveBeenCalled();
  });

  // Scenario 2: Missing signature
  it('should reject request with missing signature', () => {
    mockRequest.body = { data: 'test data' };

    const middleware = signatureValidationMiddleware({ secretKey });
    middleware(
      mockRequest as Request, 
      mockResponse as Response, 
      mockNext
    );

    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Missing signature or timestamp'
      })
    );
    expect(mockNext).not.toHaveBeenCalled();
  });

  // Scenario 3: Invalid signature
  it('should reject request with invalid signature', () => {
    const testBody = { data: 'test data' };
    const { timestamp } = generateSignature(secretKey, testBody);

    mockRequest.headers = { 
      'x-signature': 'invalid-signature',
      'x-timestamp': timestamp.toString()
    };
    mockRequest.body = testBody;

    const middleware = signatureValidationMiddleware({ secretKey });
    middleware(
      mockRequest as Request, 
      mockResponse as Response, 
      mockNext
    );

    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Invalid signature'
      })
    );
    expect(mockNext).not.toHaveBeenCalled();
  });

  // Scenario 4: Expired signature
  it('should reject expired signatures', () => {
    const testBody = { data: 'test data' };
    const pastTimestamp = Date.now() - (10 * 60 * 1000); // 10 minutes ago
    const { signature } = generateSignature(secretKey, testBody, pastTimestamp);

    mockRequest.headers = { 
      'x-signature': signature,
      'x-timestamp': pastTimestamp.toString()
    };
    mockRequest.body = testBody;

    const middleware = signatureValidationMiddleware({ 
      secretKey,
      signatureMaxAge: 5 * 60 * 1000 // 5 minutes
    });
    middleware(
      mockRequest as Request, 
      mockResponse as Response, 
      mockNext
    );

    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Signature has expired'
      })
    );
    expect(mockNext).not.toHaveBeenCalled();
  });

  // Scenario 5: Custom validation
  it('should support custom validation logic', () => {
    const testBody = { data: 'test data' };
    const { signature, timestamp } = generateSignature(secretKey, testBody);

    mockRequest.headers = { 
      'x-signature': signature,
      'x-timestamp': timestamp.toString()
    };
    mockRequest.body = testBody;

    const customValidation = jest.fn().mockReturnValue(false);

    const middleware = signatureValidationMiddleware({ 
      secretKey,
      customValidation
    });
    middleware(
      mockRequest as Request, 
      mockResponse as Response, 
      mockNext
    );

    expect(customValidation).toHaveBeenCalledWith(mockRequest);
    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Custom validation failed'
      })
    );
    expect(mockNext).not.toHaveBeenCalled();
  });

  // Scenario 6: Performance tracking
  it('should warn about slow middleware processing', () => {
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
    const testBody = { data: 'test data' };
    const { signature, timestamp } = generateSignature(secretKey, testBody);

    mockRequest.headers = { 
      'x-signature': signature,
      'x-timestamp': timestamp.toString()
    };
    mockRequest.body = testBody;

    const middleware = signatureValidationMiddleware({ secretKey });
    middleware(
      mockRequest as Request, 
      mockResponse as Response, 
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    
    // Cleanup
    consoleSpy.mockRestore();
  });
});