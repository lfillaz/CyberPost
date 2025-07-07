import React, { useState, useEffect } from 'react';


type EncodingType = 'base64' | 'url' | 'html' | 'jwt';
type EncodingDirection = 'encode' | 'decode';
type PayloadCategory = 'xss' | 'sql' | 'cmd' | 'lfi';
type Payloads = Record<PayloadCategory, string[]>;

export const PayloadToolbox: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'encoder' | 'generator'>('encoder');
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [encodingType, setEncodingType] = useState<EncodingType>('base64');
  const [direction, setDirection] = useState<EncodingDirection>('encode');
  const [copySuccess, setCopySuccess] = useState<{input: boolean; output: boolean}>({input: false, output: false});
  

  const [activeCategory, setActiveCategory] = useState<PayloadCategory>('xss');
  

  useEffect(() => {
    if (copySuccess.input || copySuccess.output) {
      const timer = setTimeout(() => setCopySuccess({input: false, output: false}), 2000);
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

          setOutput(
            input
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;')
          );
        } else {

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

  const copyToClipboard = (text: string, target: 'input' | 'output') => {
    navigator.clipboard.writeText(text);
    setCopySuccess(prev => ({ ...prev, [target]: true }));
  };

  return (
    <div className="h-full flex flex-col bg-cyber-dark">
      {/* Header with tabs */}
      <div className="border-b border-gray-700">
        <div className="flex">
          <button
            className={`py-1 px-4 ${activeTab === 'encoder' ? 'bg-cyber-green text-black' : 'bg-transparent text-gray-400'}`}
            onClick={() => setActiveTab('encoder')}
          >
            Encoder
          </button>
          <button
            className={`py-1 px-4 ${activeTab === 'generator' ? 'bg-cyber-green text-black' : 'bg-transparent text-gray-400'}`}
            onClick={() => setActiveTab('generator')}
          >
            Payload Generator
          </button>
        </div>
      </div>
      
      {/* Encoder Tab */}
      {activeTab === 'encoder' && (
        <div className="p-2 flex flex-col h-full">
          <div className="grid grid-cols-3 gap-2 items-center mb-2">
            <div className="text-gray-300 text-sm">Type</div>
            <div className="text-gray-300 text-sm">Input</div>
            <div className="text-gray-300 text-sm text-right">Copy</div>
          </div>
          
          <div className="grid grid-cols-3 gap-2 items-center mb-4">
            <div>
              <select 
                value={encodingType}
                onChange={(e) => setEncodingType(e.target.value as EncodingType)}
                className="bg-gray-800 border border-gray-700 rounded px-2 py-1 w-full text-sm text-gray-300"
              >
                <option value="base64">Base64</option>
                <option value="url">URL</option>
                <option value="html">HTML</option>
                <option value="jwt">JWT</option>
              </select>
            </div>
            
            <div className="col-span-1">
              <textarea 
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="w-full h-24 bg-gray-800 border border-gray-700 rounded p-2 text-gray-300 text-sm font-mono"
                placeholder="Enter text to encode or decode..."
              />
            </div>
            
            <div className="flex justify-end">
              <button 
                onClick={() => copyToClipboard(input, 'input')}
                className="bg-gray-700 hover:bg-gray-600 text-xs text-gray-300 rounded px-2 py-1"
              >
                Copy
                {copySuccess.input && <span className="ml-1 text-cyber-green">✓</span>}
              </button>
            </div>
          </div>
          
          <div className="grid grid-cols-3 gap-2 items-center mb-2">
            <div className="text-gray-300 text-sm">Action</div>
            <div className="text-gray-300 text-sm">Output</div>
            <div className="text-gray-300 text-sm text-right">Copy</div>
          </div>
          
          <div className="grid grid-cols-3 gap-2 items-center">
            <div className="flex space-x-1">
              <button 
                className={`px-3 py-1 text-xs ${direction === 'encode' ? 'bg-cyber-green text-black' : 'bg-gray-700 text-gray-300'}`}
                onClick={() => {
                  setDirection('encode');
                  handleEncodeOrDecode();
                }}
              >
                Encode
              </button>
              <button 
                className={`px-3 py-1 text-xs ${direction === 'decode' ? 'bg-cyber-green text-black' : 'bg-gray-700 text-gray-300'}`}
                onClick={() => {
                  setDirection('decode');
                  handleEncodeOrDecode();
                }}
              >
                Decode
              </button>
            </div>
            
            <div className="col-span-1">
              <textarea 
                value={output}
                readOnly
                className="w-full h-24 bg-gray-800 border border-gray-700 rounded p-2 text-gray-300 text-sm font-mono"
                placeholder="Output will appear here..."
              />
            </div>
            
            <div className="flex justify-end items-start">
              <button 
                onClick={() => copyToClipboard(output, 'output')}
                className="bg-gray-700 hover:bg-gray-600 text-xs text-gray-300 rounded px-2 py-1"
              >
                Copy
                {copySuccess.output && <span className="ml-1 text-cyber-green">✓</span>}
              </button>
            </div>
          </div>
          
          <div className="mt-2 flex justify-center">
            <button 
              onClick={swapInputOutput}
              className="flex items-center justify-center bg-gray-800 hover:bg-gray-700 text-xs text-gray-300 rounded px-3 py-1"
            >
              <span className="mr-1">↑↓</span> 
              Swap
            </button>
          </div>
        </div>
      )}
      

      {activeTab === 'generator' && (
        <div className="p-2 flex flex-col h-full">
          <div className="grid grid-cols-4 gap-2">
            <div className="col-span-1">
              <div className="mb-2 text-sm text-gray-300">Categories</div>
              <div className="space-y-1">
                {Object.keys(payloads).map((category) => (
                  <button
                    key={category}
                    onClick={() => setActiveCategory(category as PayloadCategory)}
                    className={`w-full text-left text-xs px-2 py-1 rounded ${activeCategory === category ? 'bg-cyber-green text-black' : 'bg-gray-700 text-gray-300'}`}
                  >
                    {category.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
            
            <div className="col-span-3">
              <div className="mb-2 text-sm text-gray-300">Payloads</div>
              <div className="space-y-1 border border-gray-700 rounded p-2 bg-gray-800">
                {payloads[activeCategory].map((payload, index) => (
                  <div key={index} className="flex justify-between items-center bg-gray-700 rounded p-1">
                    <div className="text-xs text-gray-300 font-mono truncate flex-1 px-2">{payload}</div>
                    <div className="flex space-x-1">
                      <button 
                        onClick={() => handlePayloadSelect(payload)}
                        className="bg-gray-600 hover:bg-gray-500 text-xs text-gray-300 rounded px-2 py-1"
                      >
                        Use
                      </button>
                      <button 
                        onClick={() => copyToClipboard(payload, 'input')}
                        className="bg-gray-600 hover:bg-gray-500 text-xs text-gray-300 rounded px-2 py-1"
                      >
                        Copy{copySuccess.input && <span className="ml-1 text-cyber-green">✓</span>}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
