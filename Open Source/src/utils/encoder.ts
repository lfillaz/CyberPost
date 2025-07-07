/**
 * Utility functions for encoding and decoding operations
 */

/**
 * Base64 encoding and decoding
 */
export const base64 = {
  encode: (input: string): string => {
    try {
      return btoa(input);
    } catch (error) {
      throw new Error(`Base64 encode error: ${(error as Error).message}`);
    }
  },
  
  decode: (input: string): string => {
    try {
      return atob(input);
    } catch (error) {
      throw new Error(`Base64 decode error: ${(error as Error).message}`);
    }
  }
};

/**
 * URL encoding and decoding
 */
export const url = {
  encode: (input: string): string => {
    try {
      return encodeURIComponent(input);
    } catch (error) {
      throw new Error(`URL encode error: ${(error as Error).message}`);
    }
  },
  
  decode: (input: string): string => {
    try {
      return decodeURIComponent(input);
    } catch (error) {
      throw new Error(`URL decode error: ${(error as Error).message}`);
    }
  }
};

/**
 * HTML entity encoding and decoding
 */
export const html = {
  encode: (input: string): string => {
    try {
      const el = document.createElement('div');
      el.innerText = input;
      return el.innerHTML;
    } catch (error) {
      // Fallback to basic replacement
      return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
  },
  
  decode: (input: string): string => {
    try {
      const el = document.createElement('div');
      el.innerHTML = input;
      return el.innerText;
    } catch (error) {
      // Fallback to basic replacement
      return input
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#039;/g, "'");
    }
  }
};

/**
 * JWT decode
 * Note: Encoding requires signing, which would need a library in a real app
 */
export const jwt = {
  decode: (token: string): Record<string, any> => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT token format');
      }
      
      return {
        header: JSON.parse(base64.decode(parts[0])),
        payload: JSON.parse(base64.decode(parts[1])),
        signature: parts[2],
      };
    } catch (error) {
      throw new Error(`JWT decode error: ${(error as Error).message}`);
    }
  }
};

/**
 * Auto-detect and decode various formats
 */
export const autoDetect = (input: string): { type: string; decoded: string } => {
  try {
    // Check for base64
    if (/^[A-Za-z0-9+/=]+$/.test(input)) {
      try {
        const decoded = base64.decode(input);
        if (/^[\x00-\x7F]*$/.test(decoded)) { // Check if result is readable ASCII
          return { type: 'base64', decoded };
        }
      } catch (e) {
        // Not valid base64, continue
      }
    }
    
    // Check for URL encoding
    if (/%[0-9A-Fa-f]{2}/.test(input)) {
      try {
        return { type: 'url', decoded: url.decode(input) };
      } catch (e) {
        // Not valid URL encoding, continue
      }
    }
    
    // Check for HTML entities
    if (/&[#a-zA-Z0-9]+;/.test(input)) {
      return { type: 'html', decoded: html.decode(input) };
    }
    
    // Check for JWT
    if (/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(input)) {
      try {
        const decoded = jwt.decode(input);
        return { type: 'jwt', decoded: JSON.stringify(decoded, null, 2) };
      } catch (e) {
        // Not a valid JWT, continue
      }
    }
    
    // No known encoding detected
    return { type: 'unknown', decoded: input };
  } catch (error) {
    return { type: 'error', decoded: `Error: ${(error as Error).message}` };
  }
};

/**
 * Chain multiple encodings together
 */
export const chainEncode = (input: string, operations: Array<{ type: string; operation: 'encode' | 'decode' }>) => {
  let result = input;
  
  for (const op of operations) {
    switch (op.type) {
      case 'base64':
        result = op.operation === 'encode' ? base64.encode(result) : base64.decode(result);
        break;
      case 'url':
        result = op.operation === 'encode' ? url.encode(result) : url.decode(result);
        break;
      case 'html':
        result = op.operation === 'encode' ? html.encode(result) : html.decode(result);
        break;
      default:
        throw new Error(`Unsupported encoding type: ${op.type}`);
    }
  }
  
  return result;
};
