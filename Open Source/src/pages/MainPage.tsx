import React, { useState, useEffect } from 'react';
import { RequestEditor } from '../components/RequestEditor';
import { ResponseViewer } from '../components/ResponseViewer';
import { PayloadToolbox } from '../components/PayloadToolbox';
import useRequest from '../hooks/useRequest';
import { v4 as uuidv4 } from 'uuid';
import { RequestConfig } from '../types';


const getHostname = (urlString: string): string => {
  try {

    let url = urlString;
    if (!url.match(/^https?:\/\//i)) {
      url = 'https://' + url;
    }
    return new URL(url).hostname;
  } catch (error) {

    return urlString;
  }
};

export const MainPage: React.FC = () => {

  const [activeTab, setActiveTab] = useState<string>(() => {
    const savedActiveTab = localStorage.getItem('cyberpost_activeTab');
    return savedActiveTab || 'default';
  });
  
  const [tabs, setTabs] = useState<Record<string, RequestConfig>>(() => {
    const savedTabs = localStorage.getItem('cyberpost_tabs');
    if (savedTabs) {
      try {
        return JSON.parse(savedTabs);
      } catch (e) {
        console.error('Error parsing saved tabs', e);
      }
    }
    return {
      default: {
        id: 'default',
        name: 'New Request',
        url: 'https://api.example.com',
        method: 'GET',
        headers: [{ key: '', value: '' }],
        params: [{ key: '', value: '' }],
        body: '',
        bodyType: 'json',
      },
    };
  });
  
  const {
    requestConfig,
    setRequestConfig,
    response,
    isLoading,
    sendRequest,
    sendMockRequest,
    error,
  } = useRequest();


  const handleNewTab = () => {
    const newId = uuidv4();
    const newRequest: RequestConfig = {
      id: newId,
      name: 'New Request',
      url: 'https://api.example.com',
      method: 'GET',
      headers: [{ key: '', value: '' }],
      params: [{ key: '', value: '' }],
      body: '',
      bodyType: 'json',
    };
    
    setTabs(prevTabs => ({
      ...prevTabs,
      [newId]: newRequest,
    }));
    setActiveTab(newId);
    setRequestConfig(newRequest);
  };


  const handleCloseTab = (tabId: string) => {
    if (Object.keys(tabs).length === 1) {
      return;
    }
    
    const newTabs = { ...tabs };
    delete newTabs[tabId];
    
    setTabs(newTabs);
    

    if (activeTab === tabId) {
      const remainingTabIds = Object.keys(newTabs);
      setActiveTab(remainingTabIds[0]);
      setRequestConfig(newTabs[remainingTabIds[0]]);
    }
  };


  const handleTabChange = (tabId: string) => {
    setActiveTab(tabId);
    setRequestConfig(tabs[tabId]);
  };


  const handleRequestChange = (updatedConfig: RequestConfig) => {
    setRequestConfig(updatedConfig);
    setTabs(prevTabs => ({
      ...prevTabs,
      [activeTab]: updatedConfig,
    }));
  };

  const [viewMode, setViewMode] = useState<'request' | 'response' | 'payload'>(() => {
    const savedViewMode = localStorage.getItem('cyberpost_viewMode');
    return (savedViewMode as 'request' | 'response' | 'payload') || 'request';
  });
  

  useEffect(() => {
    localStorage.setItem('cyberpost_activeTab', activeTab);
  }, [activeTab]);
  
  useEffect(() => {
    localStorage.setItem('cyberpost_tabs', JSON.stringify(tabs));
  }, [tabs]);
  
  useEffect(() => {
    localStorage.setItem('cyberpost_viewMode', viewMode);
  }, [viewMode]);

  return (
    <div className="flex flex-col h-[500px] w-[400px] bg-cyber-dark text-gray-100 overflow-hidden">

      <header className="bg-gradient-to-r from-cyber-dark-light to-cyber-dark border-b border-gray-700 py-2 px-3">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-cyber-green">CyberPost Lab</h1>
          
          {/* Request Tabs */}
          <div className="flex space-x-1">
            <button
              onClick={handleNewTab}
              className="py-1 px-2 bg-cyber-green/20 hover:bg-cyber-green/30 text-cyber-green rounded text-xs"
              title="New Request"
            >
              + New
            </button>
          </div>
        </div>


        <div className="flex mt-2 overflow-x-auto scrollbar-thin scrollbar-thumb-gray-600">
          {Object.entries(tabs).map(([id, tab]) => (
            <div 
              key={id}
              className={`flex items-center py-1 px-3 mr-1 rounded-t cursor-pointer text-xs ${
                activeTab === id ? 'bg-gray-800 text-cyber-green border-t border-r border-l border-gray-700' : 'bg-gray-900 hover:bg-gray-800'
              }`}
              onClick={() => handleTabChange(id)}
            >
              <span className="mr-1 font-medium">{tab.method}</span>
              <span className="truncate max-w-[100px]">{tab.name}</span>
              {Object.keys(tabs).length > 1 && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handleCloseTab(id);
                  }}
                  className="ml-2 text-gray-500 hover:text-gray-300"
                >
                  ✕
                </button>
              )}
            </div>
          ))}
        </div>
      </header>
      

      <div className="flex border-b border-gray-700 bg-cyber-dark-light">
        <button
          className={`py-2 px-4 text-sm font-medium ${viewMode === 'request' ? 'text-cyber-green border-b-2 border-cyber-green' : 'text-gray-400 hover:text-gray-200'}`}
          onClick={() => setViewMode('request')}
        >
          Request
        </button>
        <button
          className={`py-2 px-4 text-sm font-medium ${viewMode === 'response' ? 'text-cyber-green border-b-2 border-cyber-green' : 'text-gray-400 hover:text-gray-200'}`}
          onClick={() => setViewMode('response')}
        >
          Response
        </button>
        <button
          className={`py-2 px-4 text-sm font-medium ${viewMode === 'payload' ? 'text-cyber-green border-b-2 border-cyber-green' : 'text-gray-400 hover:text-gray-200'}`}
          onClick={() => setViewMode('payload')}
        >
          Tools
        </button>
      </div>
      

      <div className="flex-1 overflow-hidden">

        <div className={`h-full transition-all duration-200 ${viewMode === 'request' ? 'block' : 'hidden'}`}>
          <div className="h-full overflow-auto">
            <RequestEditor
              requestConfig={requestConfig}
              setRequestConfig={handleRequestChange}
              setResponse={sendRequest}
              setMockResponse={sendMockRequest}
              isLoading={isLoading}
            />
          </div>
        </div>
        

        <div className={`h-full transition-all duration-200 ${viewMode === 'response' ? 'block' : 'hidden'}`}>
          <div className="h-full overflow-auto">
            <ResponseViewer 
              response={response} 
              isLoading={isLoading}
              error={error} 
            />
          </div>
        </div>
        

        <div className={`h-full transition-all duration-200 ${viewMode === 'payload' ? 'block' : 'hidden'}`}>
          <div className="h-full overflow-auto">
            <PayloadToolbox />
          </div>
        </div>
      </div>
      

      <div className="bg-cyber-dark-light border-t border-gray-700 py-1 px-3 text-xs flex justify-between items-center">
        <div className="text-gray-400">
          {isLoading ? 'Loading...' : response ? `${response.status} ${response.statusText}` : 'Ready'}
        </div>
        <div className="text-cyber-green">
          {requestConfig.method} {requestConfig.url && getHostname(requestConfig.url)}
        </div>
      </div>
    </div>
  );
};
