

export interface RequestHeader {
  key: string;
  value: string;
}

export interface RequestParam {
  key: string;
  value: string;
}

export interface RequestConfig {
  id: string;
  name: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';
  headers: RequestHeader[];
  params: RequestParam[];
  body: string;
  bodyType: 'raw' | 'json' | 'form-data' | 'x-www-form-urlencoded';
  useCorsProxy?: boolean;
}

export interface RequestResponse {
  status: number;
  statusText: string;
  headers: [string, string][];
  data: any;
  time: number;
  error?: string;
  request?: {
    url: string;
    method: string;
    headers: RequestHeader[];
    body?: string;
  };
}


export const buildUrl = (baseUrl: string, params: RequestParam[]): string => {
  try {

    if (!baseUrl || typeof baseUrl !== 'string' || !baseUrl.trim()) {
      return 'https://api.example.com';
    }
    

    let urlString = baseUrl;
    if (!urlString.match(/^https?:\/\//i)) {
      urlString = 'https://' + urlString;
    }
    
    const url = new URL(urlString);
    

    const validParams = params.filter(param => param.key && param.value);
    
    validParams.forEach(({ key, value }) => {
      url.searchParams.append(key, value);
    });
    
    return url.toString();
  } catch (error) {
    console.error('Invalid URL:', error);
    return baseUrl;
  }
};


export const buildHeaders = (headers: RequestHeader[]): HeadersInit => {
  const headerObj: Record<string, string> = {};
  return headers
    .filter(header => header.key && header.value)
    .reduce<Record<string, string>>((acc, { key, value }) => {
      acc[key] = value;
      return acc;
    }, headerObj);
};


export const buildBody = (body: string, bodyType: string): BodyInit | null | undefined => {
  if (!body) return null;
  
  switch (bodyType) {
    case 'json':
      return body;
    case 'form-data':
      try {
        const formData = new FormData();
        const jsonData = JSON.parse(body);
        
        Object.entries(jsonData).forEach(([key, value]) => {
          formData.append(key, String(value));
        });
        
        return formData;
      } catch (error) {
        console.error('Failed to parse form-data:', error);
        return body;
      }
    case 'x-www-form-urlencoded':
      try {
        const urlEncoded = new URLSearchParams();
        const jsonData = JSON.parse(body);
        
        Object.entries(jsonData).forEach(([key, value]) => {
          urlEncoded.append(key, String(value));
        });
        
        return urlEncoded;
      } catch (error) {
        console.error('Failed to parse url-encoded data:', error);
        return body;
      }
    case 'raw':
    default:
      return body;
  }
};


export const executeRequest = async (config: RequestConfig): Promise<RequestResponse> => {
  const { url, method, headers, params, body, bodyType, useCorsProxy } = config;
  
  try {

    if (!url || typeof url !== 'string' || !url.trim()) {
      throw new Error('Invalid URL: URL cannot be empty');
    }
    

    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
      throw new Error('Cannot make requests to Chrome extension URLs due to security restrictions');
    }
    

    let targetUrl = url;
    if (useCorsProxy) {
      targetUrl = `https://cors-anywhere.herokuapp.com/${url}`;
    }

    const finalUrl = buildUrl(targetUrl, params);
    const headerObj = buildHeaders(headers) as Record<string, string>;

    if (method !== 'GET' && body && !headerObj['Content-Type']) {
      switch (bodyType) {
        case 'json':
          headerObj['Content-Type'] = 'application/json';
          break;
        case 'x-www-form-urlencoded':
          headerObj['Content-Type'] = 'application/x-www-form-urlencoded';
          break;
      }
    }

    const requestOptions: RequestInit = {
      method,
      headers: headerObj,
      mode: 'cors',
      credentials: 'same-origin'
    };

    if (method !== 'GET' && method !== 'HEAD' && body) {
      requestOptions.body = buildBody(body, bodyType);
    }

    const startTime = performance.now();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);
    requestOptions.signal = controller.signal;

    try {
      const response = await fetch(finalUrl, requestOptions);
      const endTime = performance.now();
      clearTimeout(timeoutId);

      let responseData;
      const contentType = response.headers.get('content-type');

      try {
        if (contentType && contentType.includes('application/json')) {
          responseData = await response.json();
        } else {
          responseData = await response.text();
        }
      } catch (parseError) {
        responseData = `Error parsing response: ${(parseError as Error).message}`;
      }

      return {
        status: response.status,
        statusText: response.statusText,
        headers: Array.from(response.headers.entries()),
        data: responseData,
        time: endTime - startTime,
        request: {
          url: finalUrl,
          method,
          headers: Object.entries(headerObj).map(([key, value]) => ({ key, value }))
        }
      };
    } catch (fetchError) {
      clearTimeout(timeoutId);
      if ((fetchError as DOMException).name === 'AbortError') {
        throw new Error('Request timeout: The request took too long to complete');
      }
      throw fetchError;
    }
  } catch (error) {
    let errorMessage = (error as Error).message;

    if (errorMessage === 'Failed to fetch') {
      errorMessage = 'Network error: Unable to connect to the server. This might be due to CORS restrictions, the server being unavailable, or network connectivity issues.';
    }

    console.error('Request error:', error);

    return {
      status: 0,
      statusText: 'Error',
      headers: [],
      data: null,
      time: 0,
      error: errorMessage,
      request: {
        url: buildUrl(url, params),
        method,
        headers: headers.filter(h => h.key && h.value)
      }
    };
  }
};

export const generateCurlCommand = (config: RequestConfig): string => {
  const { url, method, headers, params, body, bodyType } = config;
  const finalUrl = buildUrl(url, params);

  let curl = `curl -X ${method} `;

  headers
    .filter(header => header.key && header.value)
    .forEach(({ key, value }) => {
      curl += `-H "${key}: ${value}" `;
    });

  if (method !== 'GET' && method !== 'HEAD' && body) {
    if (bodyType === 'form-data') {
      try {
        const jsonData = JSON.parse(body);
        Object.entries(jsonData).forEach(([key, value]) => {
          curl += `-F "${key}=${value}" `;
        });
      } catch {
        curl += `-d '${body}' `;
      }
    } else {
      curl += `-d '${body}' `;
    }
  }

  curl += `"${finalUrl}"`;

  return curl;
};

export const generateMockResponse = (config: RequestConfig): RequestResponse => {
  const finalUrl = buildUrl(config.url, config.params);

  return {
    status: 200,
    statusText: 'OK',
    headers: [
      ['content-type', 'application/json'],
      ['server', 'CyberPost Mock Server'],
      ['x-mock', 'true'],
      ['date', new Date().toUTCString()]
    ],
    data: {
      message: 'This is a mocked response',
      mock: true,
      timestamp: new Date().toISOString(),
      request: {
        url: finalUrl,
        method: config.method,
        headers: config.headers.filter(h => h.key && h.value),
        params: config.params.filter(p => p.key && p.value),
        body: config.body || null
      }
    },
    time: Math.random() * 100 + 50
  };
};
