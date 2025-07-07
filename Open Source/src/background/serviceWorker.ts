/// <reference lib="webworker" />

// @ts-ignore
const sw = self as unknown as ServiceWorkerGlobalScope;




const MOCK_HOSTNAME = 'local.fakeapi';


interface MockConfig {
  statusCode: number;
  contentType: string;
  responseBody: string;
  delay: number;
  reflectPost: boolean;
}

interface MockConfigs {
  [key: string]: MockConfig;
}


let mockConfigs: MockConfigs = {

  '/cybertest': {
    statusCode: 200,
    contentType: 'application/json',
    responseBody: JSON.stringify({ message: 'Mock API response' }),
    delay: 500,
    reflectPost: true,
  }
};


sw.addEventListener('install', (event) => {
  console.log('CyberPost Mock API Service Worker installed');

  event.waitUntil(sw.skipWaiting());
});


sw.addEventListener('activate', (event) => {
  console.log('CyberPost Mock API Service Worker activated');
  event.waitUntil(sw.clients.claim());
});


const getUrlParam = (url: string, param: string) => {
  const searchParams = new URL(url).searchParams;
  return searchParams.get(param);
};


const createResponseHeaders = (contentType: string) => {
  return {
    'Content-Type': contentType,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Powered-By': 'CyberPost Mock API',
    'X-Mock-Response': 'true'
  };
};


sw.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'configure-mock') {
    const { endpoint, config } = event.data;
    if (endpoint && config) {
      mockConfigs[endpoint] = config as MockConfig;
      event.ports[0].postMessage({ status: 'success', message: 'Mock API configured' });
    } else {
      event.ports[0].postMessage({ status: 'error', message: 'Invalid configuration' });
    }
  }
});


sw.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  

  if (url.hostname !== MOCK_HOSTNAME) {
    return;
  }
  
  event.respondWith((async () => {
    try {

      const pathname = url.pathname;
      let mockConfig = mockConfigs[pathname as keyof typeof mockConfigs];
      

      if (!mockConfig) {
        return new Response(
          JSON.stringify({ error: 'No mock configuration for this endpoint' }),
          { 
            status: 404,
            headers: createResponseHeaders('application/json')
          }
        );
      }
      

      let requestBody = null;
      if (event.request.method === 'POST' && mockConfig.reflectPost) {
        try {
          const clonedRequest = event.request.clone();
          const contentType = event.request.headers.get('content-type') || '';
          if (contentType.includes('application/json')) {
            requestBody = await clonedRequest.json();
          } else if (contentType.includes('application/x-www-form-urlencoded')) {
            const formData = await clonedRequest.formData();
            requestBody = Object.fromEntries(formData);
          } else {
            requestBody = await clonedRequest.text();
          }
        } catch (error) {
          console.error('Error processing request body:', error);
        }
      }
      

      if (mockConfig.delay) {
        await new Promise(resolve => setTimeout(resolve, mockConfig.delay));
      }
      

      let responseBody = mockConfig.responseBody;
      

      if (mockConfig.reflectPost && requestBody) {
        try {
          const responseObject = typeof responseBody === 'string' 
            ? JSON.parse(responseBody) 
            : responseBody;
            
          responseObject.request = {
            body: requestBody,
            method: event.request.method,
            headers: Object.fromEntries(Array.from(event.request.headers.entries()) as Array<[string, string]>),
            url: event.request.url
          };
          
          responseBody = JSON.stringify(responseObject);
        } catch (error) {
          console.error('Error reflecting request body:', error);
        }
      }
      

      return new Response(responseBody, {
        status: mockConfig.statusCode,
        headers: createResponseHeaders(mockConfig.contentType)
      });
    } catch (error) {
      console.error('Error in mock API:', error);
      return new Response(
        JSON.stringify({ error: 'Mock API error', details: (error as Error).message }),
        { 
          status: 500,
          headers: createResponseHeaders('application/json')
        }
      );
    }
  })());
});
