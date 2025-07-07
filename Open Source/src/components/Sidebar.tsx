import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getAllRequests } from '../storage/historyManager';
import { RequestConfig } from '../types';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tabId: string) => void;
  onNewRequest: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab, onNewRequest }: SidebarProps) => {
  const [savedRequests, setSavedRequests] = useState<RequestConfig[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeSection, setActiveSection] = useState<'requests' | 'payloads' | 'settings'>('requests');
  const [isLoading, setIsLoading] = useState<boolean>(false);

  useEffect(() => {
    const loadRequests = async () => {
      setIsLoading(true);
      try {
        const requests = await getAllRequests();
        setSavedRequests(requests);
      } catch (error) {
        console.error('Failed to load requests:', error);
      } finally {
        setIsLoading(false);
      }
    };
    loadRequests();
  }, []);

  const getMethodColor = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET':
        return 'text-cyber-cyan';
      case 'POST':
        return 'text-cyber-green';
      case 'PUT':
        return 'text-yellow-400';
      case 'DELETE':
        return 'text-cyber-red';
      default:
        return 'text-gray-300';
    }
  };

  const filteredRequests = searchQuery 
    ? savedRequests.filter((req: RequestConfig) => 
        req.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
        req.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        req.method.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : savedRequests;

  return (
    <div className="w-64 bg-cyber-dark-light border-r border-gray-700 flex flex-col h-full">
      <div className="p-4 border-b border-gray-700">
        <button 
          onClick={onNewRequest}
          className="w-full btn-primary flex items-center justify-center"
        >
          <span className="mr-2">+</span> New Request
        </button>
      </div>

      <div className="flex border-b border-gray-700">
        <button 
          className={`flex-1 py-2 ${activeSection === 'requests' ? 'border-b-2 border-cyber-cyan text-cyber-cyan' : 'text-gray-400'}`}
          onClick={() => setActiveSection('requests')}
        >
          Requests
        </button>
        <button 
          className={`flex-1 py-2 ${activeSection === 'payloads' ? 'border-b-2 border-cyber-cyan text-cyber-cyan' : 'text-gray-400'}`}
          onClick={() => setActiveSection('payloads')}
        >
          Payloads
        </button>
        <button 
          className={`flex-1 py-2 ${activeSection === 'settings' ? 'border-b-2 border-cyber-cyan text-cyber-cyan' : 'text-gray-400'}`}
          onClick={() => setActiveSection('settings')}
        >
          Settings
        </button>
      </div>

      <div className="overflow-y-auto flex-1">
        {activeSection === 'requests' && (
          <div className="p-2">
            <div className="mb-2">
              <input 
                type="text" 
                value={searchQuery}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                placeholder="Search requests..." 
                className="input w-full text-sm"
              />
            </div>
            
            {isLoading ? (
              <div className="flex justify-center py-4">
                <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-cyber-cyan"></div>
              </div>
            ) : filteredRequests.length > 0 ? (
              <div className="space-y-1">
                {filteredRequests.map((request) => (
                  <div 
                    key={request.id}
                    onClick={() => setActiveTab(request.id)}
                    className={`p-2 rounded cursor-pointer ${activeTab === request.id ? 'bg-gray-700' : 'hover:bg-gray-800'}`}
                  >
                    <div className="flex items-center">
                      <span className={`font-medium mr-2 ${getMethodColor(request.method)}`}>
                        {request.method}
                      </span>
                      <span className="text-sm truncate">{request.name}</span>
                    </div>
                    <div className="text-xs text-gray-400 truncate">{request.url}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-4 text-gray-500">
                {searchQuery ? 'No matching requests found' : 'No saved requests yet'}
              </div>
            )}
          </div>
        )}
        {activeSection === 'payloads' && (
          <div className="p-4">
            <h3 className="text-cyber-green text-sm uppercase font-medium mb-2">Payload Libraries</h3>
            <ul className="space-y-1">
              <li className="px-2 py-1 hover:bg-gray-800 rounded cursor-pointer">XSS Payloads</li>
              <li className="px-2 py-1 hover:bg-gray-800 rounded cursor-pointer">SQL Injection</li>
              <li className="px-2 py-1 hover:bg-gray-800 rounded cursor-pointer">Command Injection</li>
              <li className="px-2 py-1 hover:bg-gray-800 rounded cursor-pointer">LFI/RFI</li>
              <li className="px-2 py-1 hover:bg-gray-800 rounded cursor-pointer">Custom Payloads</li>
            </ul>
          </div>
        )}
        {activeSection === 'settings' && (
          <div className="p-4">
            <h3 className="text-cyber-green text-sm uppercase font-medium mb-2">Quick Settings</h3>
            <div className="space-y-3">
              <div>
                <label className="flex items-center space-x-2">
                  <input type="checkbox" className="form-checkbox" />
                  <span>Dark Mode</span>
                </label>
              </div>
              <div>
                <label className="flex items-center space-x-2">
                  <input type="checkbox" className="form-checkbox" />
                  <span>Auto-save requests</span>
                </label>
              </div>
              <div>
                <label className="block text-sm mb-1">Theme</label>
                <select className="input w-full">
                  <option>Cyber Green</option>
                  <option>Cyber Cyan</option>
                  <option>Cyber Red</option>
                </select>
              </div>
              
              <Link
                to="/settings"
                className="btn-secondary w-full mt-4 text-sm block text-center"
              >
                All Settings
              </Link>
            </div>
          </div>
        )}
      </div>
      
      <div className="p-2 border-t border-gray-700 flex items-center justify-between">
        <span className="text-xs text-gray-400">Offline Mode</span>
        <span className="text-xs px-1.5 py-0.5 bg-cyber-green text-cyber-dark rounded">Active</span>
      </div>
    </div>
  );
};
