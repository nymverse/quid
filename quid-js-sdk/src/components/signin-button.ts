/**
 * Sign in with QuID Button
 * Vanilla JavaScript component for QuID authentication
 */

import { QuIDClient } from '../core/quid-client';
import { SigninOptions, ComponentStyle, AuthenticationResponse } from '../types';

export class QuIDSigninButton {
  private client: QuIDClient;
  private container: HTMLElement;
  private button: HTMLButtonElement;
  private options: Required<SigninOptions>;
  private isLoading = false;

  constructor(container: HTMLElement | string, options: SigninOptions = {}) {
    // Get container element
    if (typeof container === 'string') {
      const element = document.querySelector(container) as HTMLElement;
      if (!element) {
        throw new Error(`Container element not found: ${container}`);
      }
      this.container = element;
    } else {
      this.container = container;
    }

    // Set default options
    this.options = {
      challenge: options.challenge || '',
      userVerification: options.userVerification || 'preferred',
      timeout: options.timeout || 60000,
      onSuccess: options.onSuccess || (() => {}),
      onError: options.onError || (() => {}),
      style: options.style || {},
      buttonText: options.buttonText || 'Sign in with QuID',
      showBranding: options.showBranding !== false
    };

    // Initialize QuID client
    this.client = new QuIDClient();

    // Create the button
    this.createButton();
    this.setupEventListeners();
  }

  /**
   * Create the signin button element
   */
  private createButton(): void {
    this.button = document.createElement('button');
    this.button.type = 'button';
    this.button.className = 'quid-signin-button';
    
    // Apply styles
    this.applyStyles();
    
    // Set content
    this.updateButtonContent();
    
    // Add to container
    this.container.appendChild(this.button);
  }

  /**
   * Apply styles to the button
   */
  private applyStyles(): void {
    const defaultStyle: ComponentStyle = {
      width: '100%',
      height: '44px',
      backgroundColor: '#667eea',
      color: '#ffffff',
      borderRadius: '6px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: '16px',
      padding: '0 16px',
      margin: '8px 0'
    };

    const style = { ...defaultStyle, ...this.options.style };

    // Apply styles
    Object.assign(this.button.style, {
      width: style.width,
      height: style.height,
      backgroundColor: style.backgroundColor,
      color: style.color,
      borderRadius: style.borderRadius,
      fontFamily: style.fontFamily,
      fontSize: style.fontSize,
      padding: style.padding,
      margin: style.margin,
      border: 'none',
      cursor: 'pointer',
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
      overflow: 'hidden'
    });

    // Add custom class if provided
    if (style.className) {
      this.button.className += ` ${style.className}`;
    }

    // Add hover effects
    this.button.addEventListener('mouseenter', () => {
      if (!this.isLoading) {
        this.button.style.transform = 'translateY(-1px)';
        this.button.style.boxShadow = '0 4px 12px rgba(102, 126, 234, 0.3)';
      }
    });

    this.button.addEventListener('mouseleave', () => {
      if (!this.isLoading) {
        this.button.style.transform = 'translateY(0)';
        this.button.style.boxShadow = 'none';
      }
    });
  }

  /**
   * Update button content
   */
  private updateButtonContent(): void {
    if (this.isLoading) {
      this.button.innerHTML = `
        <div class="quid-spinner" style="
          width: 16px;
          height: 16px;
          border: 2px solid transparent;
          border-top: 2px solid currentColor;
          border-radius: 50%;
          animation: quid-spin 1s linear infinite;
        "></div>
        <span>Authenticating...</span>
      `;
    } else {
      const icon = this.options.showBranding ? 
        '<span style="font-size: 18px;">🔐</span>' : '';
      
      this.button.innerHTML = `
        ${icon}
        <span>${this.options.buttonText}</span>
      `;
    }

    // Add spinner animation CSS if not already added
    if (!document.querySelector('#quid-spinner-styles')) {
      const style = document.createElement('style');
      style.id = 'quid-spinner-styles';
      style.textContent = `
        @keyframes quid-spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `;
      document.head.appendChild(style);
    }
  }

  /**
   * Set up event listeners
   */
  private setupEventListeners(): void {
    this.button.addEventListener('click', this.handleClick.bind(this));
    
    // Listen for QuID client events
    this.client.on((event) => {
      if (event.type === 'ready' && !this.client.extensionAvailable) {
        this.showWarning();
      }
    });
  }

  /**
   * Handle button click
   */
  private async handleClick(): Promise<void> {
    if (this.isLoading) {
      return;
    }

    try {
      this.setLoading(true);

      // Generate challenge if not provided
      const challenge = this.options.challenge || this.generateChallenge();

      // Authenticate
      const response = await this.client.authenticate({
        challenge,
        userVerification: this.options.userVerification,
        timeout: this.options.timeout,
        origin: window.location.origin
      });

      if (response.success) {
        this.options.onSuccess(response);
      } else {
        this.options.onError(new Error(response.error || 'Authentication failed'));
      }

    } catch (error) {
      this.options.onError(error instanceof Error ? error : new Error('Authentication failed'));
    } finally {
      this.setLoading(false);
    }
  }

  /**
   * Set loading state
   */
  private setLoading(loading: boolean): void {
    this.isLoading = loading;
    this.button.disabled = loading;
    this.updateButtonContent();
    
    if (loading) {
      this.button.style.transform = 'translateY(0)';
      this.button.style.boxShadow = 'none';
      this.button.style.cursor = 'wait';
    } else {
      this.button.style.cursor = 'pointer';
    }
  }

  /**
   * Show warning when extension is not available
   */
  private showWarning(): void {
    const warningElement = document.createElement('div');
    warningElement.className = 'quid-warning';
    warningElement.style.cssText = `
      background: #fff3cd;
      border: 1px solid #ffeaa7;
      color: #856404;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 12px;
      margin-top: 4px;
      font-family: ${this.options.style?.fontFamily || 'inherit'};
    `;
    warningElement.innerHTML = `
      ⚠️ QuID browser extension not detected. 
      <a href="https://quid.dev/download" target="_blank" style="color: inherit; text-decoration: underline;">
        Install extension
      </a> for full functionality.
    `;

    this.container.appendChild(warningElement);

    // Auto-hide after 10 seconds
    setTimeout(() => {
      if (warningElement.parentElement) {
        warningElement.parentElement.removeChild(warningElement);
      }
    }, 10000);
  }

  /**
   * Generate random challenge
   */
  private generateChallenge(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Update options
   */
  public updateOptions(newOptions: Partial<SigninOptions>): void {
    Object.assign(this.options, newOptions);
    this.applyStyles();
    this.updateButtonContent();
  }

  /**
   * Destroy the component
   */
  public destroy(): void {
    if (this.button && this.button.parentElement) {
      this.button.parentElement.removeChild(this.button);
    }
    this.client.disconnect();
  }

  /**
   * Get the underlying QuID client
   */
  public getClient(): QuIDClient {
    return this.client;
  }
}

/**
 * Factory function to create signin button
 */
export function createSigninButton(container: HTMLElement | string, options?: SigninOptions): QuIDSigninButton {
  return new QuIDSigninButton(container, options);
}