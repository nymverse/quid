/**
 * QuID Browser Extension Popup Script
 * Manages the extension popup interface
 */

class QuIDPopup {
  constructor() {
    this.isConnected = false;
    this.identities = [];
    this.pendingRequests = [];
    
    this.init();
  }
  
  async init() {
    console.log('🔐 QuID popup initialized');
    
    // Set up event listeners
    this.setupEventListeners();
    
    // Load initial data
    await this.loadExtensionStatus();
    await this.loadIdentities();
    await this.loadPendingRequests();
    
    // Set up periodic updates
    setInterval(() => {
      this.refreshData();
    }, 5000);
  }
  
  setupEventListeners() {
    // Refresh button
    document.getElementById('refreshBtn').addEventListener('click', () => {
      this.refreshData();
    });
    
    // Open options button
    document.getElementById('openOptionsBtn').addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
      window.close();
    });
    
    // Create identity button
    document.getElementById('createIdentityBtn').addEventListener('click', () => {
      this.showCreateIdentityModal();
    });
    
    // Modal controls
    document.getElementById('closeModalBtn').addEventListener('click', () => {
      this.hideCreateIdentityModal();
    });
    
    document.getElementById('cancelCreateBtn').addEventListener('click', () => {
      this.hideCreateIdentityModal();
    });
    
    // Create identity form
    document.getElementById('createIdentityForm').addEventListener('submit', (e) => {
      e.preventDefault();
      this.handleCreateIdentity();
    });
    
    // Help and about links
    document.getElementById('helpLink').addEventListener('click', (e) => {
      e.preventDefault();
      chrome.tabs.create({ url: 'https://quid.dev/help' });
    });
    
    document.getElementById('aboutLink').addEventListener('click', (e) => {
      e.preventDefault();
      chrome.tabs.create({ url: 'https://quid.dev/about' });
    });
    
    // Close modal when clicking outside
    document.getElementById('createIdentityModal').addEventListener('click', (e) => {
      if (e.target.classList.contains('modal')) {
        this.hideCreateIdentityModal();
      }
    });
  }
  
  async loadExtensionStatus() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'GET_EXTENSION_STATUS'
      });
      
      this.isConnected = response.isConnected;
      this.updateStatusIndicator(response);
      this.updateConnectionStatus(response);
    } catch (error) {
      console.error('Failed to load extension status:', error);
      this.updateStatusIndicator({ isConnected: false, error: error.message });
    }
  }
  
  async loadIdentities() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'GET_IDENTITIES'
      });
      
      if (response.success) {
        this.identities = response.identities || [];
        this.updateIdentityList();
      } else {
        console.error('Failed to load identities:', response.error);
        this.showError('Failed to load identities');
      }
    } catch (error) {
      console.error('Failed to load identities:', error);
      this.showError('Failed to connect to QuID');
    }
  }
  
  async loadPendingRequests() {
    // For now, we'll simulate pending requests
    // In a real implementation, this would come from the background script
    this.pendingRequests = [];
    this.updatePendingRequests();
  }
  
  async refreshData() {
    await Promise.all([
      this.loadExtensionStatus(),
      this.loadIdentities(),
      this.loadPendingRequests()
    ]);
  }
  
  updateStatusIndicator(status) {
    const indicator = document.getElementById('statusIndicator');
    const dot = indicator.querySelector('.status-dot');
    const text = indicator.querySelector('.status-text');
    
    if (status.isConnected) {
      dot.className = 'status-dot connected';
      text.textContent = 'Connected';
    } else {
      dot.className = 'status-dot';
      text.textContent = status.error ? 'Error' : 'Disconnected';
    }
  }
  
  updateConnectionStatus(status) {
    document.getElementById('nativeHostStatus').textContent = 
      status.isConnected ? 'Connected' : 'Disconnected';
    document.getElementById('nativeHostStatus').className = 
      `status-value ${status.isConnected ? 'connected' : 'error'}`;
    
    document.getElementById('identityCount').textContent = 
      status.hasIdentities ? this.identities.length : '0';
    
    document.getElementById('extensionVersion').textContent = 
      status.version || '1.0.0';
  }
  
  updateIdentityList() {
    const listContainer = document.getElementById('identityList');
    const emptyState = document.getElementById('emptyState');
    
    if (this.identities.length === 0) {
      emptyState.style.display = 'block';
      return;
    }
    
    emptyState.style.display = 'none';
    
    // Clear existing items except empty state
    const existingItems = listContainer.querySelectorAll('.identity-item');
    existingItems.forEach(item => item.remove());
    
    // Add identity items
    this.identities.forEach(identity => {
      const item = this.createIdentityItem(identity);
      listContainer.appendChild(item);
    });
  }
  
  createIdentityItem(identity) {
    const item = document.createElement('div');
    item.className = 'identity-item';
    
    item.innerHTML = `
      <div class="identity-header">
        <span class="identity-name">${this.escapeHtml(identity.name || identity.id)}</span>
        <span class="identity-status">${identity.is_active ? 'Active' : 'Inactive'}</span>
      </div>
      <div class="identity-details">
        <span class="identity-id">ID: ${this.truncateId(identity.id)}</span>
        <div class="identity-networks">
          ${identity.networks ? identity.networks.map(network => 
            `<span class="network-tag">${network}</span>`
          ).join('') : ''}
        </div>
      </div>
    `;
    
    // Add click handler for identity management
    item.addEventListener('click', () => {
      this.showIdentityDetails(identity);
    });
    
    return item;
  }
  
  updatePendingRequests() {
    const requestsSection = document.getElementById('requestsSection');
    const requestList = document.getElementById('requestList');
    const requestCount = document.getElementById('requestCount');
    
    if (this.pendingRequests.length === 0) {
      requestsSection.style.display = 'none';
      return;
    }
    
    requestsSection.style.display = 'block';
    requestCount.textContent = this.pendingRequests.length;
    
    // Clear existing requests
    requestList.innerHTML = '';
    
    // Add request items
    this.pendingRequests.forEach(request => {
      const item = this.createRequestItem(request);
      requestList.appendChild(item);
    });
  }
  
  createRequestItem(request) {
    const item = document.createElement('div');
    item.className = 'request-item';
    
    const timeAgo = this.getTimeAgo(request.timestamp);
    
    item.innerHTML = `
      <div class="request-header">
        <span class="request-origin">${this.escapeHtml(request.origin)}</span>
        <span class="request-time">${timeAgo}</span>
      </div>
      <div class="request-actions">
        <button class="btn btn-approve" data-request-id="${request.id}">
          <span class="icon">✅</span>
          Approve
        </button>
        <button class="btn btn-deny" data-request-id="${request.id}">
          <span class="icon">❌</span>
          Deny
        </button>
      </div>
    `;
    
    // Add event listeners for approve/deny buttons
    const approveBtn = item.querySelector('.btn-approve');
    const denyBtn = item.querySelector('.btn-deny');
    
    approveBtn.addEventListener('click', () => {
      this.handleRequestResponse(request.id, true);
    });
    
    denyBtn.addEventListener('click', () => {
      this.handleRequestResponse(request.id, false);
    });
    
    return item;
  }
  
  async handleRequestResponse(requestId, approved) {
    try {
      await chrome.runtime.sendMessage({
        type: 'RESPOND_TO_REQUEST',
        requestId,
        approved
      });
      
      // Remove request from list
      this.pendingRequests = this.pendingRequests.filter(r => r.id !== requestId);
      this.updatePendingRequests();
      
    } catch (error) {
      console.error('Failed to respond to request:', error);
      this.showError('Failed to respond to request');
    }
  }
  
  showCreateIdentityModal() {
    document.getElementById('createIdentityModal').style.display = 'flex';
    
    // Focus on name input
    setTimeout(() => {
      document.getElementById('identityName').focus();
    }, 100);
  }
  
  hideCreateIdentityModal() {
    document.getElementById('createIdentityModal').style.display = 'none';
    
    // Reset form
    document.getElementById('createIdentityForm').reset();
  }
  
  async handleCreateIdentity() {
    const form = document.getElementById('createIdentityForm');
    const formData = new FormData(form);
    
    // Get selected networks
    const networkCheckboxes = form.querySelectorAll('input[type="checkbox"]:checked');
    const networks = Array.from(networkCheckboxes).map(cb => cb.value);
    
    const config = {
      name: formData.get('identityName') || 'Unnamed Identity',
      securityLevel: formData.get('securityLevel') || 'Level1',
      networks: networks.length > 0 ? networks : ['web']
    };
    
    // Disable form during creation
    const submitBtn = document.getElementById('confirmCreateBtn');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<span class="icon">🔄</span> Creating...';
    submitBtn.disabled = true;
    
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'CREATE_IDENTITY',
        config
      });
      
      if (response.success) {
        console.log('✅ Identity created successfully');
        this.hideCreateIdentityModal();
        await this.loadIdentities(); // Refresh the list
        this.showSuccess('Identity created successfully!');
      } else {
        throw new Error(response.error || 'Failed to create identity');
      }
    } catch (error) {
      console.error('❌ Failed to create identity:', error);
      this.showError(error.message);
    } finally {
      // Restore button state
      submitBtn.innerHTML = originalText;
      submitBtn.disabled = false;
    }
  }
  
  showIdentityDetails(identity) {
    // For now, just log the identity details
    // In a full implementation, this would show a detailed view
    console.log('Identity details:', identity);
    
    // Show a simple alert for demonstration
    alert(`Identity: ${identity.name || identity.id}\nNetworks: ${identity.networks ? identity.networks.join(', ') : 'Unknown'}`);
  }
  
  showError(message) {
    // Simple error display - in a real implementation you'd want a proper notification system
    console.error(message);
    
    // You could add a toast notification here
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      right: 10px;
      background: #dc3545;
      color: white;
      padding: 12px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 10000;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
      document.body.removeChild(notification);
    }, 3000);
  }
  
  showSuccess(message) {
    console.log(message);
    
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      right: 10px;
      background: #28a745;
      color: white;
      padding: 12px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 10000;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
      document.body.removeChild(notification);
    }, 3000);
  }
  
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  
  truncateId(id) {
    if (!id) return 'Unknown';
    return id.length > 12 ? `${id.substr(0, 6)}...${id.substr(-6)}` : id;
  }
  
  getTimeAgo(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new QuIDPopup();
});