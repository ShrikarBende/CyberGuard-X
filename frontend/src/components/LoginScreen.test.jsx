import { describe, expect, it, vi } from 'vitest';
import React, { useState } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LoginScreen from './LoginScreen';

vi.mock('@gsap/react', () => ({ useGSAP: () => {} }));

describe('LoginScreen', () => {
  it('provides labeled credentials and submits the sign-in form', async () => {
    const user = userEvent.setup();
    const handleLogin = vi.fn((event) => event.preventDefault());
    function Harness() {
      const [username, setUsername] = useState('');
      const [password, setPassword] = useState('');
      return <LoginScreen loginName={username} setLoginName={setUsername} loginPassword={password}
        setLoginPassword={setPassword} loginError="" loginPending={false} handleLogin={handleLogin} />;
    }
    render(<Harness />);
    await user.type(screen.getByLabelText('Username'), 'analyst');
    await user.type(screen.getByLabelText('Password'), 'secure-password');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(handleLogin).toHaveBeenCalledOnce();
    expect(screen.getByRole('button', { name: 'Sign in' }).disabled).toBe(false);
  });

  it('announces authentication errors accessibly', () => {
    render(<LoginScreen loginName="" setLoginName={() => {}} loginPassword="" setLoginPassword={() => {}}
      loginError="Invalid analyst credentials." loginPending={false} handleLogin={() => {}} />);
    expect(screen.getByRole('alert').textContent).toContain('Invalid analyst credentials.');
  });
});
