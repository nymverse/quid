/**
 * QuID React Example Application
 */

import React, { useState } from 'react';
import { QuIDSigninButton, useQuID } from '@quid/sdk';
import type { AuthenticationResponse, QuIDIdentity } from '@quid/sdk';

// Identity List Component
const IdentityList: React.FC = () => {
  const { identities, createIdentity, refreshIdentities, isLoading, error } = useQuID();
  const [newIdentityName, setNewIdentityName] = useState('');

  const handleCreateIdentity = async () => {
    if (!newIdentityName.trim()) return;

    try {
      await createIdentity({
        name: newIdentityName,
        securityLevel: 'Level1',
        networks: ['web']
      });
      setNewIdentityName('');
    } catch (err) {
      console.error('Failed to create identity:', err);
    }
  };

  return (
    <div className="identity-section">
      <h3>Your QuID Identities</h3>
      
      <div className="create-identity">
        <input
          type="text"
          value={newIdentityName}
          onChange={(e) => setNewIdentityName(e.target.value)}
          placeholder="Identity name"
          disabled={isLoading}
        />
        <button onClick={handleCreateIdentity} disabled={isLoading || !newIdentityName.trim()}>
          Create Identity
        </button>
      </div>

      <button onClick={refreshIdentities} disabled={isLoading}>
        Refresh
      </button>

      {error && (
        <div className="error">
          Error: {error.message}
        </div>
      )}

      <div className="identity-list">
        {identities.length === 0 ? (
          <p>No identities found. Create one to get started!</p>
        ) : (
          identities.map((identity: QuIDIdentity) => (
            <div key={identity.id} className="identity-item">
              <h4>{identity.name || identity.id}</h4>
              <p>Security Level: {identity.securityLevel}</p>
              <p>Networks: {identity.networks.join(', ')}</p>
              <p>Status: {identity.isActive ? 'Active' : 'Inactive'}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

// Status Component
const QuIDStatus: React.FC = () => {
  const { isReady, extensionAvailable, isLoading, error, getStatus } = useQuID();
  const [statusInfo, setStatusInfo] = useState<any>(null);

  const handleCheckStatus = async () => {
    try {
      const status = await getStatus();
      setStatusInfo(status);
    } catch (err) {
      console.error('Failed to get status:', err);
    }
  };

  return (
    <div className="status-section">
      <h3>QuID Status</h3>
      
      <div className="status-indicators">
        <div className={`indicator ${isReady ? 'success' : 'pending'}`}>
          SDK Ready: {isReady ? '✅' : '⏳'}
        </div>
        <div className={`indicator ${extensionAvailable ? 'success' : 'warning'}`}>
          Extension: {extensionAvailable ? '✅ Connected' : '⚠️ Not Available'}
        </div>
        <div className={`indicator ${isLoading ? 'pending' : 'success'}`}>
          Loading: {isLoading ? '⏳' : '✅'}
        </div>
      </div>

      {error && (
        <div className="error">
          Error: {error.message}
        </div>
      )}

      <button onClick={handleCheckStatus}>Check Detailed Status</button>

      {statusInfo && (
        <div className="status-details">
          <h4>Detailed Status:</h4>
          <pre>{JSON.stringify(statusInfo, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

// Main App Component
const App: React.FC = () => {
  const [authResult, setAuthResult] = useState<AuthenticationResponse | null>(null);
  const { authenticate, clearError } = useQuID({ debug: true });

  const handleSigninSuccess = (response: AuthenticationResponse) => {
    console.log('Signin successful:', response);
    setAuthResult(response);
  };

  const handleSigninError = (error: Error) => {
    console.error('Signin failed:', error);
    setAuthResult({
      success: false,
      error: error.message
    });
  };

  const handleManualAuth = async () => {
    try {
      const response = await authenticate({
        userVerification: 'preferred'
      });
      setAuthResult(response);
    } catch (error) {
      console.error('Manual authentication failed:', error);
    }
  };

  const clearResults = () => {
    setAuthResult(null);
    clearError();
  };

  return (
    <div className="app">
      <header className="app-header">
        <h1>🔐 QuID React Example</h1>
        <p>Quantum-resistant authentication for React applications</p>
      </header>

      <main className="app-main">
        <section className="demo-section">
          <h2>QuID Status</h2>
          <QuIDStatus />
        </section>

        <section className="demo-section">
          <h2>Quick Signin</h2>
          <QuIDSigninButton
            onSuccess={handleSigninSuccess}
            onError={handleSigninError}
            buttonText="Sign in with QuID"
            style={{
              width: '300px',
              height: '48px',
              fontSize: '16px'
            }}
            showBranding={true}
          />
        </section>

        <section className="demo-section">
          <h2>Manual Authentication</h2>
          <button onClick={handleManualAuth} className="btn-primary">
            Authenticate Manually
          </button>
        </section>

        {authResult && (
          <section className="demo-section">
            <h2>Authentication Result</h2>
            <div className={`result ${authResult.success ? 'success' : 'error'}`}>
              <button onClick={clearResults} className="close-btn">×</button>
              <h3>{authResult.success ? 'Success!' : 'Failed'}</h3>
              <pre>{JSON.stringify(authResult, null, 2)}</pre>
            </div>
          </section>
        )}

        <section className="demo-section">
          <h2>Identity Management</h2>
          <IdentityList />
        </section>
      </main>

      <style jsx>{`
        .app {
          max-width: 900px;
          margin: 0 auto;
          padding: 20px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }

        .app-header {
          text-align: center;
          margin-bottom: 40px;
          padding: 30px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border-radius: 12px;
        }

        .app-header h1 {
          margin: 0 0 10px 0;
          font-size: 2.5em;
        }

        .demo-section {
          margin: 30px 0;
          padding: 25px;
          background: white;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .demo-section h2 {
          margin-top: 0;
          color: #333;
          border-bottom: 2px solid #667eea;
          padding-bottom: 10px;
        }

        .status-indicators {
          display: flex;
          gap: 15px;
          margin: 15px 0;
        }

        .indicator {
          padding: 8px 12px;
          border-radius: 4px;
          font-weight: 500;
        }

        .indicator.success {
          background: #d4edda;
          color: #155724;
        }

        .indicator.warning {
          background: #fff3cd;
          color: #856404;
        }

        .indicator.pending {
          background: #d1ecf1;
          color: #0c5460;
        }

        .error {
          background: #f8d7da;
          color: #721c24;
          padding: 12px;
          border-radius: 4px;
          margin: 10px 0;
        }

        .result {
          position: relative;
          padding: 20px;
          border-radius: 6px;
          margin: 15px 0;
        }

        .result.success {
          background: #d4edda;
          border: 1px solid #c3e6cb;
          color: #155724;
        }

        .result.error {
          background: #f8d7da;
          border: 1px solid #f5c6cb;
          color: #721c24;
        }

        .close-btn {
          position: absolute;
          top: 10px;
          right: 15px;
          background: none;
          border: none;
          font-size: 20px;
          cursor: pointer;
          color: inherit;
        }

        .create-identity {
          display: flex;
          gap: 10px;
          margin: 15px 0;
        }

        .create-identity input {
          flex: 1;
          padding: 8px 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }

        .identity-list {
          max-height: 300px;
          overflow-y: auto;
          border: 1px solid #e0e0e0;
          border-radius: 6px;
          margin: 15px 0;
        }

        .identity-item {
          padding: 15px;
          border-bottom: 1px solid #f0f0f0;
        }

        .identity-item h4 {
          margin: 0 0 8px 0;
          color: #667eea;
        }

        .identity-item p {
          margin: 4px 0;
          font-size: 14px;
          color: #666;
        }

        button {
          padding: 10px 20px;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          font-size: 14px;
          margin: 5px;
          transition: background-color 0.2s;
        }

        .btn-primary {
          background: #667eea;
          color: white;
        }

        .btn-primary:hover:not(:disabled) {
          background: #5a6fd8;
        }

        button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        pre {
          background: #f8f9fa;
          padding: 15px;
          border-radius: 4px;
          overflow-x: auto;
          font-size: 12px;
          margin: 10px 0;
        }

        .status-details {
          margin-top: 15px;
        }
      `}</style>
    </div>
  );
};

export default App;