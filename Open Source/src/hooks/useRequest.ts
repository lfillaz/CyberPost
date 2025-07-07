import { useState, useCallback, useEffect } from 'react';
import { v4 as uuidv4 } from 'uuid';
import { executeRequest, generateMockResponse } from '../utils/requestBuilder';
import { saveRequest, getRequest } from '../storage/historyManager';
import type { RequestConfig, RequestResponse } from '../types';


function useRequest(initialRequestId?: string) {

  const defaultRequest: RequestConfig = {
    id: '',
    name: 'New Request',
    url: 'https://api.example.com',
    method: 'GET',
    headers: [{ key: '', value: '' }],
    params: [{ key: '', value: '' }],
    body: '',
    bodyType: 'json'
  };


  const [requestConfig, setRequestConfig] = useState<RequestConfig>(defaultRequest);
  

  const [response, setResponse] = useState<RequestResponse | null>(() => {
    const savedResponse = localStorage.getItem('cyberpost_response');
    if (savedResponse) {
      try {
        return JSON.parse(savedResponse);
      } catch (e) {
        console.error('Error parsing saved response', e);
      }
    }
    return null;
  });
  
  const [isLoading, setIsLoading] = useState<boolean>(false);
  

  const [error, setError] = useState<string | null>(() => {
    const savedError = localStorage.getItem('cyberpost_error');
    return savedError;
  });
  

  useEffect(() => {
    if (response) {
      try {
        localStorage.setItem('cyberpost_response', JSON.stringify(response));
      } catch (e) {
        console.error('Error saving response to localStorage', e);
      }
    }
  }, [response]);
  

  useEffect(() => {
    if (error) {
      localStorage.setItem('cyberpost_error', error);
    } else {
      localStorage.removeItem('cyberpost_error');
    }
  }, [error]);


  const loadRequest = useCallback(async (id: string) => {
    try {
      const savedRequest = await getRequest(id);
      if (savedRequest) {
        setRequestConfig(savedRequest);
        return true;
      }
      return false;
    } catch (err) {
      setError(`Error loading request: ${(err as Error).message}`);
      return false;
    }
  }, []);


  useState(() => {
    if (initialRequestId) {
      loadRequest(initialRequestId);
    }
  });


  const createRequest = useCallback(() => {
    const newId = uuidv4();
    const newRequest = {
      ...defaultRequest,
      id: newId
    };
    setRequestConfig(newRequest);
    return newId;
  }, [defaultRequest]);


  const saveCurrentRequest = useCallback(async () => {
    try {
      if (!requestConfig.id) {
        requestConfig.id = uuidv4();
      }
      await saveRequest(requestConfig);
      return requestConfig.id;
    } catch (err) {
      setError(`Error saving request: ${(err as Error).message}`);
      return null;
    }
  }, [requestConfig]);


  const updateRequestField = useCallback(<K extends keyof RequestConfig>(
    field: K, 
    value: RequestConfig[K]
  ) => {
    setRequestConfig(prev => ({ ...prev, [field]: value }));
  }, []);


  const sendRequest = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {

      const response = await executeRequest(requestConfig);
      setResponse(response);
      

      if (response.error) {
        setError(response.error);
        console.log('Request error details:', response.error);
      }
      
      return response;
    } catch (err) {

      const errorMsg = (err as Error).message;
      console.error('Unexpected error in sendRequest:', err);
      

      const userFriendlyError = errorMsg.includes('Failed to fetch') ?
        'Network error: Unable to connect to the server. This might be due to CORS restrictions, the server being unavailable, or network connectivity issues.' : 
        `Request failed: ${errorMsg}`;
      
      setError(userFriendlyError);
      

      setResponse({
        status: 0,
        statusText: 'Error',
        headers: [],
        data: null,
        time: 0,
        error: userFriendlyError,
        request: {
          url: requestConfig.url,
          method: requestConfig.method,
          headers: requestConfig.headers
        }
      });
      return null;
    } finally {
      setIsLoading(false);
    }
  }, [requestConfig]);


  const sendMockRequest = useCallback(() => {
    setIsLoading(true);
    setError(null);
    

    setTimeout(() => {
      const mockResponse = generateMockResponse(requestConfig);
      setResponse(mockResponse);
      setIsLoading(false);
    }, 500);
  }, [requestConfig]);


  const clearResponse = useCallback(() => {
    setResponse(null);
    setError(null);
    localStorage.removeItem('cyberpost_response');
    localStorage.removeItem('cyberpost_error');
  }, []);

  return {
    requestConfig,
    setRequestConfig,
    response,
    isLoading,
    error,
    loadRequest,
    createRequest,
    saveCurrentRequest,
    updateRequestField,
    sendRequest,
    sendMockRequest,
    clearResponse
  };
}

export default useRequest;
