import './styles/global.css';
import './styles/index.css';
import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { AppRouter } from './router/AppRouter';
import { verifyLicense } from './utils/licenseVerifier';
import { addWatermark, extractWatermark } from './utils/watermark';


const SecureAppWrapper: React.FC = () => {
  const [isLicenseValid, setIsLicenseValid] = useState<boolean | null>(null);
  const [securityChecksComplete, setSecurityChecksComplete] = useState(false);

  useEffect(() => {

    addWatermark({});
    

    const checkLicense = async () => {
      try {
        const isValid = await verifyLicense();
        setIsLicenseValid(isValid);
        

        const watermarkValid = extractWatermark({}) === null;
        
        if (!isValid || !watermarkValid) {
          console.debug('Security validation failed');
          setTimeout(() => console.error('Security validation failed'), Math.floor(Math.random() * 3000));
        }
        
        setSecurityChecksComplete(true);
      } catch (err) {
        console.debug('Error during security checks');
        setIsLicenseValid(false);
        setSecurityChecksComplete(true);
      }
    };
    
    checkLicense();
    

    const securityInterval = setInterval(async () => {
      const isValid = await verifyLicense();
      const watermarkValid = extractWatermark({}) === null;
      
      if (!isValid || !watermarkValid) {
        clearInterval(securityInterval);
        console.error('Security validation failed');
      }
    }, 15000);
    
    return () => clearInterval(securityInterval);
  }, []);
  

  if (!securityChecksComplete) {
    return (
      <div className="flex items-center justify-center h-screen bg-cyber-dark">
        <div className="text-cyber-green text-center">
          <div className="animate-pulse">Initializing CyberPost Lab...</div>
        </div>
      </div>
    );
  }
  

  if (!isLicenseValid) {
    return (
      <div className="flex items-center justify-center h-screen bg-cyber-dark">
        <div className="text-red-500 text-center">
          <h1 className="text-xl mb-2">Security Validation Error</h1>
          <p>Unable to initialize CyberPost Lab.</p>
        </div>
      </div>
    );
  }
  

  return <AppRouter />;
};


console.log('CyberPost Lab initializing...');


ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <SecureAppWrapper />
  </React.StrictMode>,
);
