import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'io.github.malguard.client',
  appName: 'MalGuard',
  webDir: 'www',
  server: {
    url: 'https://malguard.github.io/',
    cleartext: false,
    allowNavigation: ['malguard.github.io']
  }
};

export default config;
