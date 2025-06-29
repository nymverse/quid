<template>
  <div>
    <button
      type="button"
      :disabled="disabled || isLoading || !isReady"
      :class="['quid-signin-button', className]"
      :style="buttonStyle"
      @click="handleClick"
    >
      <span v-if="showBranding" style="font-size: 18px">🔐</span>
      <span>{{ isLoading ? 'Authenticating...' : buttonText }}</span>
      <div
        v-if="isLoading"
        class="quid-spinner"
        :style="{
          width: '16px',
          height: '16px',
          border: '2px solid transparent',
          borderTop: '2px solid currentColor',
          borderRadius: '50%',
          animation: 'quid-spin 1s linear infinite'
        }"
      />
    </button>
    
    <div
      v-if="showWarning"
      :style="{
        background: '#fff3cd',
        border: '1px solid #ffeaa7',
        color: '#856404',
        padding: '8px 12px',
        borderRadius: '4px',
        fontSize: '12px',
        marginTop: '4px',
        fontFamily: buttonStyle.fontFamily
      }"
    >
      ⚠️ QuID browser extension not detected.
      <a
        href="https://quid.dev/download"
        target="_blank"
        rel="noopener noreferrer"
        style="color: inherit; text-decoration: underline"
      >
        Install extension
      </a>
      for full functionality.
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';
import { QuIDClient } from '../../core/quid-client';
import type { SigninOptions, AuthenticationResponse, QuIDEvent } from '../../types';

export interface QuIDSigninButtonProps extends Omit<SigninOptions, 'onSuccess' | 'onError'> {
  /** Additional CSS class names */
  className?: string;
  /** Whether the button is disabled */
  disabled?: boolean;
}

const props = withDefaults(defineProps<QuIDSigninButtonProps>(), {
  userVerification: 'preferred',
  timeout: 60000,
  buttonText: 'Sign in with QuID',
  showBranding: true,
  className: '',
  disabled: false,
  style: () => ({})
});

const emit = defineEmits<{
  success: [response: AuthenticationResponse];
  error: [error: Error];
}>();

// Reactive state
const client = ref<QuIDClient | null>(null);
const isLoading = ref(false);
const isReady = ref(false);
const extensionAvailable = ref(false);
const showWarning = ref(false);

// Computed styles
const buttonStyle = computed(() => {
  const defaultStyle = {
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
    cursor: isLoading.value || props.disabled ? 'not-allowed' : 'pointer',
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
    opacity: props.disabled ? 0.6 : 1
  };

  return { ...defaultStyle, ...props.style };
});

// Methods
const generateChallenge = (): string => {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

const handleClick = async () => {
  if (!client.value || isLoading.value || props.disabled) {
    return;
  }

  try {
    isLoading.value = true;

    // Generate challenge if not provided
    const authChallenge = props.challenge || generateChallenge();

    // Authenticate
    const response = await client.value.authenticate({
      challenge: authChallenge,
      userVerification: props.userVerification,
      timeout: props.timeout,
      origin: window.location.origin
    });

    if (response.success) {
      emit('success', response);
    } else {
      emit('error', new Error(response.error || 'Authentication failed'));
    }

  } catch (error) {
    emit('error', error instanceof Error ? error : new Error('Authentication failed'));
  } finally {
    isLoading.value = false;
  }
};

// Lifecycle
onMounted(() => {
  client.value = new QuIDClient();
  
  const unsubscribe = client.value.on((event: QuIDEvent) => {
    switch (event.type) {
      case 'ready':
        isReady.value = true;
        break;
      case 'extension-connected':
        extensionAvailable.value = true;
        break;
      case 'extension-disconnected':
        extensionAvailable.value = false;
        showWarning.value = true;
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

// Watch for extension availability
watch([isReady, extensionAvailable], ([ready, available]) => {
  if (ready && !available) {
    showWarning.value = true;
    // Auto-hide warning after 10 seconds
    setTimeout(() => {
      showWarning.value = false;
    }, 10000);
  }
});

// Expose methods for template refs
defineExpose({
  client,
  isReady,
  extensionAvailable,
  isLoading
});
</script>

<style scoped>
@keyframes quid-spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.quid-signin-button:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
}

.quid-signin-button:active:not(:disabled) {
  transform: translateY(0);
}
</style>