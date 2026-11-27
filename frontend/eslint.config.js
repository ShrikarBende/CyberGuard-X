import hooks from 'eslint-plugin-react-hooks';
import refresh from 'eslint-plugin-react-refresh';

const browserGlobals = {
  window: 'readonly', document: 'readonly', navigator: 'readonly', console: 'readonly',
  fetch: 'readonly', FormData: 'readonly', URLSearchParams: 'readonly', WebSocket: 'readonly',
  HTMLElement: 'readonly', Event: 'readonly', CustomEvent: 'readonly', MutationObserver: 'readonly',
  ResizeObserver: 'readonly', performance: 'readonly', File: 'readonly', Blob: 'readonly',
  setTimeout: 'readonly', clearTimeout: 'readonly', setInterval: 'readonly', clearInterval: 'readonly',
  requestAnimationFrame: 'readonly', cancelAnimationFrame: 'readonly', localStorage: 'readonly',
  sessionStorage: 'readonly', Intl: 'readonly', Math: 'readonly', Date: 'readonly', Map: 'readonly',
  Set: 'readonly', Promise: 'readonly', Array: 'readonly', Object: 'readonly', Number: 'readonly',
  String: 'readonly', Boolean: 'readonly', JSON: 'readonly', Error: 'readonly',
};

export default [
  {
    files: ['src/**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: browserGlobals,
    },
    plugins: { 'react-hooks': hooks, 'react-refresh': refresh },
    rules: {
      'no-undef': 'error',
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    },
  },
  {
    files: ['src/**/*.test.{js,jsx}'],
    languageOptions: {
      globals: { describe: 'readonly', expect: 'readonly', it: 'readonly', vi: 'readonly', beforeEach: 'readonly', afterEach: 'readonly' },
    },
  },
];
