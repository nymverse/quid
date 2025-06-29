<template>
  <div class="app">
    <header class="app-header">
      <h1>🔐 QuID Vue Example</h1>
      <p>Quantum-resistant authentication for Vue applications</p>
    </header>

    <main class="app-main">
      <!-- Status Section -->
      <section class="demo-section">
        <h2>QuID Status</h2>
        <div class="status-indicators">
          <div :class="['indicator', isReady ? 'success' : 'pending']">
            SDK Ready: {{ isReady ? '✅' : '⏳' }}
          </div>
          <div :class="['indicator', extensionAvailable ? 'success' : 'warning']">
            Extension: {{ extensionAvailable ? '✅ Connected' : '⚠️ Not Available' }}
          </div>
          <div :class="['indicator', isLoading ? 'pending' : 'success']">
            Loading: {{ isLoading ? '⏳' : '✅' }}
          </div>
        </div>
        
        <button @click="checkStatus">Check Detailed Status</button>
        
        <div v-if="error" class="error">
          Error: {{ error.message }}
          <button @click="clearError" class="close-btn">×</button>
        </div>

        <div v-if="statusInfo" class="status-details">
          <h4>Detailed Status:</h4>
          <pre>{{ JSON.stringify(statusInfo, null, 2) }}</pre>
        </div>
      </section>

      <!-- Signin Section -->
      <section class="demo-section">
        <h2>QuID Signin</h2>
        <QuIDSigninButton
          @success="handleSigninSuccess"
          @error="handleSigninError"
          button-text="Sign in with QuID"
          :style="{
            width: '300px',
            height: '48px',
            fontSize: '16px'
          }"
          :show-branding="true"
        />
      </section>

      <!-- Manual Authentication -->
      <section class="demo-section">
        <h2>Manual Authentication</h2>
        <button @click="manualAuth" :disabled="isLoading" class="btn-primary">
          Authenticate Manually
        </button>
      </section>

      <!-- Authentication Result -->
      <section v-if="authResult" class="demo-section">
        <h2>Authentication Result</h2>
        <div :class="['result', authResult.success ? 'success' : 'error']">
          <button @click="authResult = null" class="close-btn">×</button>
          <h3>{{ authResult.success ? 'Success!' : 'Failed' }}</h3>
          <pre>{{ JSON.stringify(authResult, null, 2) }}</pre>
        </div>
      </section>

      <!-- Identity Management -->
      <section class="demo-section">
        <h2>Identity Management</h2>
        
        <div class="create-identity">
          <input
            v-model="newIdentityName"
            type="text"
            placeholder="Identity name"
            :disabled="isLoading"
            @keyup.enter="createIdentity"
          />
          <button 
            @click="createIdentity" 
            :disabled="isLoading || !newIdentityName.trim()"
            class="btn-primary"
          >
            Create Identity
          </button>
        </div>

        <button @click="refreshIdentities" :disabled="isLoading">
          Refresh Identities
        </button>

        <div class="identity-list">
          <div v-if="identities.length === 0" class="empty-state">
            <p>No identities found. Create one to get started!</p>
          </div>
          <div 
            v-else
            v-for="identity in identities" 
            :key="identity.id" 
            class="identity-item"
          >
            <h4>{{ identity.name || identity.id }}</h4>
            <p>Security Level: {{ identity.securityLevel }}</p>
            <p>Networks: {{ identity.networks.join(', ') }}</p>
            <p>Status: {{ identity.isActive ? 'Active' : 'Inactive' }}</p>
            <p><small>ID: {{ identity.id }}</small></p>
          </div>
        </div>
      </section>

      <!-- OAuth Example -->
      <section class="demo-section">
        <h2>OAuth Integration</h2>
        <button @click="testOAuth" class="btn-primary">
          Test OAuth Flow
        </button>
        
        <div v-if="oauthResult" class="result success">
          <button @click="oauthResult = null" class="close-btn">×</button>
          <h4>OAuth Configuration Generated:</h4>
          <pre>{{ JSON.stringify(oauthResult, null, 2) }}</pre>
        </div>
      </section>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { QuIDClient, QuIDOAuthClient } from '@quid/sdk';
import QuIDSigninButton from '@quid/sdk/vue';
import type { 
  QuIDIdentity, 
  AuthenticationResponse, 
  QuIDEvent 
} from '@quid/sdk';

// Reactive state
const client = ref<QuIDClient | null>(null);
const isReady = ref(false);
const extensionAvailable = ref(false);
const isLoading = ref(false);
const error = ref<Error | null>(null);
const identities = ref<QuIDIdentity[]>([]);
const authResult = ref<AuthenticationResponse | null>(null);
const statusInfo = ref<any>(null);
const newIdentityName = ref('');
const oauthResult = ref<any>(null);

// Methods
const handleSigninSuccess = (response: AuthenticationResponse) => {
  console.log('Signin successful:', response);
  authResult.value = response;
};

const handleSigninError = (err: Error) => {
  console.error('Signin failed:', err);
  authResult.value = {
    success: false,
    error: err.message
  };
};

const manualAuth = async () => {
  if (!client.value) return;
  
  try {
    isLoading.value = true;
    const response = await client.value.authenticate({
      userVerification: 'preferred'
    });
    authResult.value = response;
  } catch (err) {
    console.error('Manual authentication failed:', err);
    error.value = err instanceof Error ? err : new Error('Authentication failed');
  } finally {
    isLoading.value = false;
  }
};

const checkStatus = async () => {
  if (!client.value) return;
  
  try {
    const status = await client.value.getStatus();
    statusInfo.value = status;
  } catch (err) {
    console.error('Failed to get status:', err);
    error.value = err instanceof Error ? err : new Error('Status check failed');
  }
};

const refreshIdentities = async () => {
  if (!client.value || !extensionAvailable.value) {
    identities.value = [];
    return;
  }

  try {
    isLoading.value = true;
    const identityList = await client.value.getIdentities();
    identities.value = identityList;
  } catch (err) {
    console.warn('Failed to refresh identities:', err);
    identities.value = [];
  } finally {
    isLoading.value = false;
  }
};

const createIdentity = async () => {
  if (!client.value || !newIdentityName.value.trim()) return;

  try {
    isLoading.value = true;
    await client.value.createIdentity({
      name: newIdentityName.value,
      securityLevel: 'Level1',
      networks: ['web']
    });
    newIdentityName.value = '';
    await refreshIdentities();
  } catch (err) {
    console.error('Failed to create identity:', err);
    error.value = err instanceof Error ? err : new Error('Identity creation failed');
  } finally {
    isLoading.value = false;
  }
};

const testOAuth = () => {
  try {
    const oauthClient = new QuIDOAuthClient({
      clientId: 'demo-client-id',
      redirectUri: window.location.origin + '/oauth/callback',
      scopes: ['openid', 'profile', 'email'],
      provider: {
        authorizationEndpoint: 'https://auth.example.com/oauth/authorize',
        tokenEndpoint: 'https://auth.example.com/oauth/token',
        userInfoEndpoint: 'https://auth.example.com/oauth/userinfo'
      }
    }, client.value!);

    const authUrl = oauthClient.generateAuthUrl({
      state: 'demo-state-' + Date.now(),
      nonce: 'demo-nonce-' + Math.random().toString(36)
    });

    oauthResult.value = {
      message: 'OAuth flow configuration generated',
      authUrl: authUrl,
      config: oauthClient.getConfig(),
      note: 'In a real application, you would redirect to the authUrl'
    };
  } catch (err) {
    console.error('OAuth test failed:', err);
    error.value = err instanceof Error ? err : new Error('OAuth test failed');
  }
};

const clearError = () => {
  error.value = null;
};

// Lifecycle
onMounted(() => {
  console.log('Initializing QuID Vue example...');
  
  client.value = new QuIDClient({ debug: true });
  
  const unsubscribe = client.value.on((event: QuIDEvent) => {
    console.log('QuID Event:', event.type);
    
    switch (event.type) {
      case 'ready':
        isReady.value = true;
        extensionAvailable.value = client.value?.extensionAvailable || false;
        if (extensionAvailable.value) {
          refreshIdentities();
        }
        break;
      case 'extension-connected':
        extensionAvailable.value = true;
        refreshIdentities();
        break;
      case 'extension-disconnected':
        extensionAvailable.value = false;
        identities.value = [];
        break;
      case 'error':
        error.value = event.data;
        break;
    }
  });

  // Store unsubscribe function for cleanup
  (client.value as any)._unsubscribe = unsubscribe;
});

onUnmounted(() => {
  if (client.value) {
    if ((client.value as any)._unsubscribe) {
      (client.value as any)._unsubscribe();
    }
    client.value.disconnect();
  }
});
</script>

<style scoped>
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
  flex-wrap: wrap;
}

.indicator {
  padding: 8px 12px;
  border-radius: 4px;
  font-weight: 500;
  font-size: 14px;
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
  position: relative;
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
  padding: 0;
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
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
  font-size: 14px;
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

.identity-item:last-child {
  border-bottom: none;
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

.empty-state {
  padding: 20px;
  text-align: center;
  color: #666;
}

button {
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  margin: 5px;
  transition: all 0.2s;
  background: #6c757d;
  color: white;
}

.btn-primary {
  background: #667eea;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #5a6fd8;
  transform: translateY(-1px);
}

button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none !important;
}

pre {
  background: #f8f9fa;
  padding: 15px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 12px;
  margin: 10px 0;
  line-height: 1.4;
}

.status-details {
  margin-top: 15px;
}

.status-details h4 {
  margin-bottom: 10px;
  color: #333;
}
</style>