/**
 * Event Emitter
 * Simple type-safe event emitter for QuID SDK
 */

export type EventListener<T> = (event: T) => void;

export class EventEmitter<T> {
  private listeners: EventListener<T>[] = [];

  /**
   * Add an event listener
   */
  public on(listener: EventListener<T>): () => void {
    this.listeners.push(listener);
    
    // Return unsubscribe function
    return () => {
      const index = this.listeners.indexOf(listener);
      if (index > -1) {
        this.listeners.splice(index, 1);
      }
    };
  }

  /**
   * Add a one-time event listener
   */
  public once(listener: EventListener<T>): () => void {
    const onceListener: EventListener<T> = (event: T) => {
      listener(event);
      unsubscribe();
    };

    const unsubscribe = this.on(onceListener);
    return unsubscribe;
  }

  /**
   * Emit an event to all listeners
   */
  public emit(event: T): void {
    // Create a copy of listeners to avoid issues if listeners are modified during iteration
    const currentListeners = [...this.listeners];
    
    for (const listener of currentListeners) {
      try {
        listener(event);
      } catch (error) {
        console.error('Error in event listener:', error);
      }
    }
  }

  /**
   * Remove all listeners
   */
  public removeAllListeners(): void {
    this.listeners = [];
  }

  /**
   * Get the number of listeners
   */
  public get listenerCount(): number {
    return this.listeners.length;
  }
}