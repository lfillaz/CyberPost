import React, { useState } from 'react';
import { RequestConfig } from '../types';

interface KeyValuePair {
  key: string;
  value: string;
}

interface RequestEditorProps {
  requestConfig: RequestConfig;
  setRequestConfig: (updatedConfig: RequestConfig) => void;
  setResponse: () => Promise<any>;
  setMockResponse: () => void;
  isLoading?: boolean;
}

export const RequestEditor: React.FC<RequestEditorProps> = ({
  requestConfig,
  setRequestConfig,
  setResponse,
  setMockResponse,
  isLoading = false
}) => {
  const [activeSection, setActiveSection] = useState<'params' | 'headers' | 'body'>('params');
  

  const headers = Array.isArray(requestConfig.headers) ? requestConfig.headers : [];
  const params = Array.isArray(requestConfig.params) ? requestConfig.params : [];
  

  const body = requestConfig.body || '';
  const bodyType = requestConfig.bodyType || 'raw';
  

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setRequestConfig({
      ...requestConfig,
      url: e.target.value
    });
  };
  

  const handleMethodChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setRequestConfig({
      ...requestConfig,
      method: e.target.value as any
    });
  };
  

  const handleHeaderChange = (index: number, field: 'key' | 'value', value: string) => {
    const updatedHeaders = [...headers];
    updatedHeaders[index] = { ...updatedHeaders[index], [field]: value };
    

    if (index === updatedHeaders.length - 1 && value !== '') {
      updatedHeaders.push({ key: '', value: '' });
    }
    
    setRequestConfig({
      ...requestConfig,
      headers: updatedHeaders
    });
  };
  

  const removeHeader = (index: number) => {
    const updatedHeaders = [...headers];
    updatedHeaders.splice(index, 1);
    
    setRequestConfig({
      ...requestConfig,
      headers: updatedHeaders
    });
  };
  

  const addHeader = () => {
    const updatedHeaders = [...headers, { key: '', value: '' }];
    
    setRequestConfig({
      ...requestConfig,
      headers: updatedHeaders
    });
  };
  

  const handleParamChange = (index: number, field: 'key' | 'value', value: string) => {
    const updatedParams = [...params];
    updatedParams[index] = { ...updatedParams[index], [field]: value };
    

    if (index === updatedParams.length - 1 && value !== '') {
      updatedParams.push({ key: '', value: '' });
    }
    
    setRequestConfig({
      ...requestConfig,
      params: updatedParams
    });
  };
  

  const removeParam = (index: number) => {
    const updatedParams = [...params];
    updatedParams.splice(index, 1);
    
    setRequestConfig({
      ...requestConfig,
      params: updatedParams
    });
  };
  

  const addParam = () => {
    const updatedParams = [...params, { key: '', value: '' }];
    
    setRequestConfig({
      ...requestConfig,
      params: updatedParams
    });
  };
  

  const handleBodyTypeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setRequestConfig({
      ...requestConfig,
      bodyType: e.target.value as 'raw' | 'json' | 'form-data' | 'x-www-form-urlencoded'
    });
  };
  

  const handleBodyChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setRequestConfig({
      ...requestConfig,
      body: e.target.value
    });
  };
  

  const handleSendRequest = async () => {
    await setResponse();
  };
  

  const handleMockRequest = () => {
    setMockResponse();
  };
  
  return (
    <div style={{height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '8px 12px'}}>

      <div className="flex mb-2">
        <select 
          className="mr-2 bg-gray-800 border border-gray-700 rounded text-sm px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyber-green focus:border-cyber-green"
          value={requestConfig.method}
          onChange={handleMethodChange}
          disabled={isLoading}
        >
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
          <option value="PATCH">PATCH</option>
          <option value="HEAD">HEAD</option>
          <option value="OPTIONS">OPTIONS</option>
        </select>
        <input 
          type="text" 
          className="flex-1 bg-gray-800 border border-gray-700 rounded text-sm px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyber-green focus:border-cyber-green" 
          placeholder="https://api.example.com"
          value={requestConfig.url || ''}
          onChange={handleUrlChange}
          disabled={isLoading}
        />
      </div>
      
      {/* CORS Proxy Toggle */}
      <div className="flex items-center mb-3 bg-gray-800/30 rounded p-1.5 text-xs border border-gray-700">
        <input
          type="checkbox"
          id="cors-proxy"
          className="mr-2 accent-cyber-cyan"
          checked={Boolean(requestConfig.useCorsProxy)}
          onChange={(e) => {
            setRequestConfig({
              ...requestConfig,
              useCorsProxy: e.target.checked
            });
          }}
          disabled={isLoading}
        />
        <label htmlFor="cors-proxy" className="cursor-pointer flex items-center">
          <span className="mr-1 text-cyber-cyan">🔄 Use CORS Proxy</span> 
          <span className="text-gray-400">
            - Helps fix "Failed to fetch" errors
          </span>
        </label>
      </div>
      
      {/* Action Buttons */}
      <div style={{display: 'flex', marginBottom: '16px', gap: '8px'}}>
        <button
          style={{
            flex: 1,
            padding: '8px 0',
            fontSize: '14px',
            fontWeight: 500,
            borderRadius: '4px',
            border: 'none',
            backgroundColor: isLoading ? '#4b5563' : 'rgba(0, 255, 157, 0.2)',
            color: isLoading ? '#9ca3af' : '#00ff9d',
            cursor: isLoading ? 'default' : 'pointer'
          }}
          onClick={handleSendRequest}
          disabled={isLoading}
        >
          {isLoading ? 'Sending...' : 'Send'}
        </button>
        <button
          style={{
            flex: 1,
            padding: '8px 0',
            fontSize: '14px',
            fontWeight: 500,
            borderRadius: '4px',
            border: isLoading ? 'none' : '1px solid rgba(0, 255, 157, 0.3)',
            backgroundColor: isLoading ? '#4b5563' : '#1f2937',
            color: isLoading ? '#9ca3af' : '#00ff9d',
            cursor: isLoading ? 'default' : 'pointer'
          }}
          onClick={handleMockRequest}
          disabled={isLoading}
        >
          Mock Response
        </button>
      </div>
      
      {/* Tab Selector */}
      <div style={{display: 'flex', marginBottom: '12px', borderBottom: '1px solid #374151'}}>
        <button
          style={{
            padding: '8px 12px',
            fontSize: '12px',
            fontWeight: 500,
            background: 'none',
            border: 'none',
            borderBottom: activeSection === 'params' ? '2px solid #00ff9d' : 'none',
            color: activeSection === 'params' ? '#00ff9d' : '#9ca3af',
            cursor: 'pointer'
          }}
          onClick={() => setActiveSection('params')}
          disabled={isLoading}
        >
          Parameters
        </button>
        <button
          style={{
            padding: '8px 12px',
            fontSize: '12px',
            fontWeight: 500,
            background: 'none',
            border: 'none',
            borderBottom: activeSection === 'headers' ? '2px solid #00ff9d' : 'none',
            color: activeSection === 'headers' ? '#00ff9d' : '#9ca3af',
            cursor: 'pointer'
          }}
          onClick={() => setActiveSection('headers')}
          disabled={isLoading}
        >
          Headers
        </button>
        <button
          style={{
            padding: '8px 12px',
            fontSize: '12px',
            fontWeight: 500,
            background: 'none',
            border: 'none',
            borderBottom: activeSection === 'body' ? '2px solid #00ff9d' : 'none',
            color: activeSection === 'body' ? '#00ff9d' : '#9ca3af',
            cursor: 'pointer'
          }}
          onClick={() => setActiveSection('body')}
          disabled={isLoading}
        >
          Body
        </button>
      </div>
      
      {/* Content Section */}
      <div className="flex-1 overflow-auto">

        {activeSection === 'params' && (
          <div className="space-y-2">
            {params.map((param: KeyValuePair, index: number) => (
              <div key={index} className="flex items-center">
                <input
                  type="text"
                  className="flex-1 mr-1 bg-gray-800 border border-gray-700 rounded-l px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyber-green focus:border-cyber-green"
                  placeholder="Key"
                  value={param.key}
                  onChange={(e) => handleParamChange(index, 'key', e.target.value)}
                  disabled={isLoading}
                />
                <input
                  type="text"
                  className="flex-1 bg-gray-800 border border-gray-700 rounded-r px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyber-green focus:border-cyber-green"
                  placeholder="Value"
                  value={param.value}
                  onChange={(e) => handleParamChange(index, 'value', e.target.value)}
                  disabled={isLoading}
                />
                {index < params.length - 1 && (
                  <button
                    className="ml-1 text-gray-500 hover:text-gray-300 w-6 h-6 flex items-center justify-center"
                    onClick={() => removeParam(index)}
                    disabled={isLoading}
                  >
                    ×
                  </button>
                )}
              </div>
            ))}
            {params.length === 0 && (
              <div className="text-gray-400 text-xs italic p-2">No parameters added</div>
            )}
            <button 
              onClick={addParam} 
              className="mt-2 bg-gray-800 hover:bg-gray-700 text-xs text-cyber-green border border-gray-700 rounded px-3 py-1"
              disabled={isLoading}
            >
              + Add Parameter
            </button>
          </div>
        )}


        {activeSection === 'headers' && (
          <div className="space-y-2">
            {headers.map((header: KeyValuePair, index: number) => (
              <div key={index} className="flex items-center">
                <input
                  type="text"
                  className="flex-1 mr-1 bg-gray-800 border border-gray-700 rounded-l px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyber-green focus:border-cyber-green"
                  placeholder="Header"
                  value={header.key}
                  onChange={(e) => handleHeaderChange(index, 'key', e.target.value)}
                  disabled={isLoading}
                />
                <input
                  type="text"
                  className="flex-1 bg-gray-800 border border-gray-700 rounded-r px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyber-green focus:border-cyber-green"
                  placeholder="Value"
                  value={header.value}
                  onChange={(e) => handleHeaderChange(index, 'value', e.target.value)}
                  disabled={isLoading}
                />
                {index < headers.length - 1 && (
                  <button
                    className="ml-1 text-gray-500 hover:text-gray-300 w-6 h-6 flex items-center justify-center"
                    onClick={() => removeHeader(index)}
                    disabled={isLoading}
                  >
                    ×
                  </button>
                )}
              </div>
            ))}
            {headers.length === 0 && (
              <div className="text-gray-400 text-xs italic p-2">No headers added</div>
            )}
            <button 
              onClick={addHeader} 
              className="mt-2 bg-gray-800 hover:bg-gray-700 text-xs text-cyber-green border border-gray-700 rounded px-3 py-1"
              disabled={isLoading}
            >
              + Add Header
            </button>
          </div>
        )}


        {activeSection === 'body' && (
          <div className="flex flex-col h-full">

            <div className="mb-2">
              <select
                className="w-full bg-gray-800 border border-gray-700 rounded text-xs px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyber-green focus:border-cyber-green"
                value={bodyType}
                onChange={handleBodyTypeChange}
                disabled={isLoading}
              >
                <option value="raw">Raw</option>
                <option value="json">JSON</option>
                <option value="form-data">Form Data</option>
                <option value="x-www-form-urlencoded">x-www-form-urlencoded</option>
              </select>
            </div>

            <textarea
              className="flex-1 w-full bg-gray-800 border border-gray-700 rounded px-2 py-2 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-cyber-green focus:border-cyber-green resize-none"
              value={body}
              onChange={handleBodyChange}
              placeholder={bodyType === 'json' ? '{\n  "key": "value"\n}' : 'Enter request body'}
              disabled={isLoading}
            />
          </div>
        )}
      </div>
    </div>
  );
};
