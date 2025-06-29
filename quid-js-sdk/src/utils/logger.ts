/**
 * Logger
 * Simple logging utility for QuID SDK
 */

export class Logger {
  private debug: boolean;
  private prefix = '[QuID SDK]';

  constructor(debug = false) {
    this.debug = debug;
  }

  /**
   * Set debug mode
   */
  public setDebug(debug: boolean): void {
    this.debug = debug;
  }

  /**
   * Log debug message (only in debug mode)
   */
  public debug(message: string, ...args: any[]): void {
    if (this.debug) {
      console.debug(this.prefix, message, ...args);
    }
  }

  /**
   * Log info message
   */
  public info(message: string, ...args: any[]): void {
    if (this.debug) {
      console.info(this.prefix, message, ...args);
    }
  }

  /**
   * Log warning message
   */
  public warn(message: string, ...args: any[]): void {
    console.warn(this.prefix, message, ...args);
  }

  /**
   * Log error message
   */
  public error(message: string, ...args: any[]): void {
    console.error(this.prefix, message, ...args);
  }
}