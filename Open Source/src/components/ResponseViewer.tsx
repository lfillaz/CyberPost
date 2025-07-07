import React, { useState } from 'react';
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomOneDark } from 'react-syntax-highlighter/dist/esm/styles/hljs';


interface ResponseHeader {
  key: string;
  value: string;
}

interface RequestDetails {
  method: string;
  url: string;
  headers?: ResponseHeader[];
  body?: string;
}

interface ResponseData {
  status: number;
  statusText: string;
  headers: [string, string][];
  data: any;
  time?: number;
  request?: RequestDetails;
}

interface ResponseViewerProps {
  response: ResponseData | null;
  isLoading: boolean;
  error?: string | null;
}

export const ResponseViewer: React.FC<ResponseViewerProps> = ({ response, isLoading, error }) => {
  const [activeTab, setActiveTab] = useState<'raw' | 'pretty' | 'headers' | 'preview'>('pretty');
  const [copySuccess, setCopySuccess] = useState<boolean>(false);
  
  const formatJson = (data: any): string => {
    try {
      return JSON.stringify(data, null, 2);
    } catch (e) {
      return String(data);
    }
  };

  const copyToClipboard = (text: string): void => {
    navigator.clipboard.writeText(text).then(
      () => {

        setCopySuccess(true);
        setTimeout(() => {
          setCopySuccess(false);
        }, 1000);
      },
      (err) => {
        console.error('Could not copy text: ', err);
      }
    );
  };

  const getStatusColor = (status: number): string => {
    if (status >= 200 && status < 300) return 'text-cyber-green';
    if (status >= 300 && status < 400) return 'text-cyber-cyan';
    if (status >= 400 && status < 500) return 'text-cyber-red';
    if (status >= 500) return 'text-cyber-purple';
    return 'text-gray-300';
  };

  const generateCurlCommand = () => {
    if (!response) return '';
    
    let curl = `curl -X ${response.request?.method || 'GET'} `;
    
    if (response.request?.headers && response.request.headers.length > 0) {
      response.request.headers.forEach((header: { key: string; value: string }) => {
        if (header.key && header.value) {
          curl += `-H "${header.key}: ${header.value}" `;
        }
      });
    }
    
    if (response.request?.body && response.request?.method !== 'GET') {
      curl += `-d '${response.request.body}' `;
    }
    
    curl += `"${response.request?.url || ''}"`;
    
    return curl;
  };

  return (
    <div className="w-full h-full flex flex-col bg-cyber-dark-light">
      {isLoading ? (
        <div className="flex-1 flex flex-col items-center justify-center">
          <div className="text-cyber-cyan animate-pulse text-xl">Loading...</div>
          <div className="mt-2 text-gray-400 text-sm">Fetching response data...</div>
        </div>
      ) : error ? (
        <div className="flex-1 flex flex-col items-center justify-center p-3">
          <div className="text-cyber-red text-lg mb-2">
            <span className="mr-2">⚠️</span>
            Request Failed
          </div>
          <div className="bg-gray-800 rounded-md p-3 text-gray-300 text-center text-xs max-w-full overflow-auto">
            {error}
          </div>
          
          <div className="mt-3 flex space-x-2">
            <button 
              onClick={() => window.open('https://cors-anywhere.herokuapp.com/', '_blank')}
              className="text-xs bg-cyber-dark-light hover:bg-gray-700 text-cyber-cyan px-2 py-1 rounded flex items-center"
              title="If you're experiencing CORS errors, you may need to enable a CORS proxy"
            >
              Try CORS Proxy
            </button>
          </div>
        </div>
      ) : response ? (
        <>

          <div className="px-2 py-1 border-b border-gray-700 bg-cyber-dark flex items-center gap-1">
            <div className="flex items-center px-2 py-0.5 rounded bg-cyber-dark-light">
              <span className={`font-medium ${getStatusColor(response.status)}`}>
                {response.status}
              </span>
              <span className={`ml-1 text-xs ${getStatusColor(response.status)}`}>
                {response.statusText}
              </span>
            </div>
            
            {response.time && (
              <div className="px-2 py-0.5 rounded bg-cyber-dark-light flex items-center">
                <span className="text-xs text-cyber-cyan mr-1">⏱️</span>
                <span className="text-xs text-gray-300">
                  {Math.round(response.time)}ms
                </span>
              </div>
            )}
          </div>

          {/* Tabs and Action Buttons */}
          <div className="flex justify-between items-center border-b border-gray-700 bg-cyber-dark px-2">
            <div className="flex">
              <button
                onClick={() => setActiveTab('pretty')}
                className={`py-1 px-3 text-xs font-medium flex items-center ${activeTab === 'pretty' ? 'text-cyber-green border-b border-cyber-green' : 'text-gray-400 hover:text-gray-200'}`}
              >
                <span className="mr-1 text-xs">🔍</span> JSON
              </button>
              <button
                onClick={() => setActiveTab('raw')}
                className={`py-1 px-3 text-xs font-medium flex items-center ${activeTab === 'raw' ? 'text-cyber-green border-b border-cyber-green' : 'text-gray-400 hover:text-gray-200'}`}
              >
                <span className="mr-1 text-xs">📝</span> Raw
              </button>
              <button
                onClick={() => setActiveTab('headers')}
                className={`py-1 px-3 text-xs font-medium flex items-center ${activeTab === 'headers' ? 'text-cyber-green border-b border-cyber-green' : 'text-gray-400 hover:text-gray-200'}`}
              >
                <span className="mr-1 text-xs">📋</span> Headers
              </button>
              <button
                onClick={() => setActiveTab('preview')}
                className={`py-1 px-3 text-xs font-medium flex items-center ${activeTab === 'preview' ? 'text-cyber-green border-b border-cyber-green' : 'text-gray-400 hover:text-gray-200'}`}
              >
                <span className="mr-1 text-xs">🖥️</span> Preview
              </button>
            </div>
            
            <div className="flex items-center space-x-1">
              <div className={`text-xs text-cyber-green transition-opacity duration-300 ${copySuccess ? 'opacity-100' : 'opacity-0'}`}>
                Copied!
              </div>
              <button 
                onClick={() => {
                  if (activeTab === 'pretty') {
                    copyToClipboard(formatJson(response.data));
                  } else if (activeTab === 'raw') {
                    copyToClipboard(typeof response.data === 'object' ? JSON.stringify(response.data) : String(response.data));
                  } else if (activeTab === 'headers') {
                    copyToClipboard(response.headers.map(([key, value]) => `${key}: ${value}`).join('\n'));
                  }
                }}
                title="Copy Content"
                className="px-1.5 py-0.5 bg-cyber-dark-light hover:bg-gray-700 text-cyber-green text-xs rounded flex items-center"
              >
                <span>📋</span>
              </button>
              {response.request && (
                <button 
                  onClick={() => copyToClipboard(generateCurlCommand())}
                  title="Copy as cURL"
                  className="px-1.5 py-0.5 bg-cyber-dark-light hover:bg-gray-700 text-cyber-cyan text-xs rounded flex items-center"
                >
                  <span>cURL</span>
                </button>
              )}
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-auto p-2">
            {activeTab === 'pretty' && (
              <div className="rounded-sm overflow-hidden border border-gray-700 bg-gray-900 shadow">
                <div className="bg-cyber-dark-light py-1 px-2 flex items-center justify-between border-b border-gray-700">
                  <span className="text-xs text-cyber-green">JSON Response</span>
                  <button 
                    onClick={() => copyToClipboard(formatJson(response.data))}
                    className="text-xs text-gray-400 hover:text-cyber-green"
                  >
                    Copy
                  </button>
                </div>
                <div className="font-code text-xs p-1">
                  <SyntaxHighlighter
                    language="json"
                    style={atomOneDark}
                    customStyle={{ backgroundColor: 'transparent', margin: 0 }}
                  >
                    {formatJson(response.data)}
                  </SyntaxHighlighter>
                </div>
              </div>
            )}
            {activeTab === 'raw' && (
              <div className="rounded-sm overflow-hidden border border-gray-700 bg-gray-900 shadow">
                <div className="bg-cyber-dark-light py-1 px-2 flex items-center justify-between border-b border-gray-700">
                  <span className="text-xs text-cyber-green">Raw Response</span>
                  <button 
                    onClick={() => copyToClipboard(typeof response.data === 'object' ? JSON.stringify(response.data) : String(response.data))}
                    className="text-xs text-gray-400 hover:text-cyber-green"
                  >
                    Copy
                  </button>
                </div>
                <div className="font-code text-xs p-2 whitespace-pre-wrap">
                  {typeof response.data === 'object' 
                    ? JSON.stringify(response.data)
                    : String(response.data)}
                </div>
              </div>
            )}
            {activeTab === 'headers' && (
              <div className="rounded-sm overflow-hidden border border-gray-700 bg-gray-900 shadow">
                <div className="bg-cyber-dark-light py-1 px-2 flex items-center justify-between border-b border-gray-700">
                  <span className="text-xs text-cyber-green">Response Headers</span>
                  <button 
                    onClick={() => copyToClipboard(response.headers.map(([key, value]) => `${key}: ${value}`).join('\n'))}
                    className="text-xs text-gray-400 hover:text-cyber-green"
                  >
                    Copy All
                  </button>
                </div>
                <div className="p-1 space-y-1">
                  {response.headers && response.headers.map(([key, value], index) => (
                    <div key={index} className="flex p-1 rounded bg-gray-800 hover:bg-gray-750">
                      <span className="font-medium text-cyber-green w-1/3 text-xs">{key}:</span>
                      <span className="text-gray-300 break-all text-xs">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {activeTab === 'preview' && (
              <div className="rounded-md overflow-hidden border border-gray-700 bg-white shadow-lg">
                <div className="bg-cyber-dark-light py-1 px-3 flex items-center justify-between border-b border-gray-700">
                  <span className="text-xs text-cyber-green">HTML Preview</span>
                </div>
                <div className="min-h-[250px] text-black">
                  {typeof response.data === 'string' && response.data.includes('<!DOCTYPE html') ? (
                    <iframe
                      srcDoc={response.data}
                      className="w-full h-[250px] border-0"
                      title="Response Preview"
                    />
                  ) : (
                    <div className="text-center text-gray-500 py-4 text-xs">
                      No HTML content to preview
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="flex-1 flex flex-col items-center justify-center text-gray-400 p-2">
          <div className="text-4xl mb-4 animate-pulse">📡</div>
          <div className="text-lg font-medium text-cyber-green mb-2">No Response Data</div>
          <div className="text-center max-w-xs">
            <p className="mb-2 text-xs">
              Send a request using the Request tab to see response data here
            </p>
            <div className="text-xs bg-gray-800 p-2 rounded-md inline-block">
              <span className="text-cyber-cyan">TIP:</span> Use Tools tab for additional utilities
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
