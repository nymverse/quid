/**
 * QuID React Signin Button Component
 * React wrapper for QuID authentication
 */

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { QuIDClient } from '../../core/quid-client';
import { SigninOptions, AuthenticationResponse, QuIDEvent } from '../../types';

export interface QuIDSigninButtonProps extends Omit<SigninOptions, 'onSuccess' | 'onError'> {
  /** Callback when authentication succeeds */
  onSuccess?: (response: AuthenticationResponse) => void;
  /** Callback when authentication fails */
  onError?: (error: Error) => void;
  /** Additional CSS class names */
  className?: string;
  /** Whether the button is disabled */
  disabled?: boolean;
  /** Children to render instead of default button text */
  children?: React.ReactNode;
}

/**
 * QuID Signin Button React Component
 */
export const QuIDSigninButton: React.FC<QuIDSigninButtonProps> = ({
  challenge,
  userVerification = 'preferred',
  timeout = 60000,
  onSuccess,
  onError,
  style = {},
  buttonText = 'Sign in with QuID',
  showBranding = true,
  className = '',
  disabled = false,
  children,
  ...props
}) => {
  const clientRef = useRef<QuIDClient | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isReady, setIsReady] = useState(false);
  const [extensionAvailable, setExtensionAvailable] = useState(false);
  const [showWarning, setShowWarning] = useState(false);

  // Initialize QuID client
  useEffect(() => {
    clientRef.current = new QuIDClient();
    
    const unsubscribe = clientRef.current.on((event: QuIDEvent) => {
      switch (event.type) {
        case 'ready':
          setIsReady(true);
          break;
        case 'extension-connected':
          setExtensionAvailable(true);
          break;
        case 'extension-disconnected':
          setExtensionAvailable(false);
          setShowWarning(true);
          break;
      }
    });

    return () => {
      unsubscribe();
      if (clientRef.current) {
        clientRef.current.disconnect();
      }
    };
  }, []);

  // Check extension availability after ready
  useEffect(() => {
    if (isReady && clientRef.current) {
      const available = clientRef.current.extensionAvailable;
      setExtensionAvailable(available);
      if (!available) {
        setShowWarning(true);
        // Auto-hide warning after 10 seconds
        setTimeout(() => setShowWarning(false), 10000);
      }
    }
  }, [isReady]);

  const handleClick = useCallback(async () => {
    if (!clientRef.current || isLoading || disabled) {
      return;
    }

    try {
      setIsLoading(true);

      // Generate challenge if not provided
      const authChallenge = challenge || generateChallenge();

      // Authenticate
      const response = await clientRef.current.authenticate({
        challenge: authChallenge,
        userVerification,
        timeout,
        origin: window.location.origin
      });

      if (response.success) {
        onSuccess?.(response);
      } else {
        onError?.(new Error(response.error || 'Authentication failed'));
      }

    } catch (error) {
      onError?.(error instanceof Error ? error : new Error('Authentication failed'));
    } finally {
      setIsLoading(false);
    }
  }, [challenge, userVerification, timeout, onSuccess, onError, isLoading, disabled]);

  const generateChallenge = (): string => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  };

  const defaultStyle: React.CSSProperties = {
    width: '100%',
    height: '44px',
    backgroundColor: '#667eea',
    color: '#ffffff',
    borderRadius: '6px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontSize: '16px',
    padding: '0 16px',
    margin: '8px 0',
    border: 'none',
    cursor: isLoading || disabled ? 'not-allowed' : 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    transition: 'all 0.2s ease',
    textDecoration: 'none',
    fontWeight: '500',
    lineHeight: '1',
    outline: 'none',
    position: 'relative',
    overflow: 'hidden',
    opacity: disabled ? 0.6 : 1,
    ...style
  };

  const buttonContent = children || (
    <>
      {showBranding && <span style={{ fontSize: '18px' }}>🔐</span>}
      <span>{isLoading ? 'Authenticating...' : buttonText}</span>
      {isLoading && (
        <div
          style={{
            width: '16px',
            height: '16px',
            border: '2px solid transparent',
            borderTop: '2px solid currentColor',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite'
          }}
        />
      )}
    </>
  );

  return (
    <div>
      <button
        type="button"
        onClick={handleClick}
        disabled={disabled || isLoading || !isReady}
        className={`quid-signin-button ${className}`}
        style={defaultStyle}
        {...props}
      >
        {buttonContent}
      </button>
      
      {showWarning && (
        <div
          style={{
            background: '#fff3cd',
            border: '1px solid #ffeaa7',
            color: '#856404',
            padding: '8px 12px',
            borderRadius: '4px',
            fontSize: '12px',
            marginTop: '4px',
            fontFamily: defaultStyle.fontFamily
          }}
        >
          ⚠️ QuID browser extension not detected.{' '}
          <a
            href="https://quid.dev/download"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: 'inherit', textDecoration: 'underline' }}
          >
            Install extension
          </a>{' '}
          for full functionality.
        </div>
      )}
      
      <style jsx>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default QuIDSigninButton;