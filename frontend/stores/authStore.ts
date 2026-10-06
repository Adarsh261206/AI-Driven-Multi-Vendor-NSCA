'use client';

import { create } from 'zustand';
import { authAPI, getApiStatus } from '@/lib/api';
import type { User } from '@/types';

interface AuthState {
  user: User | null;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<User>;
  register: (email: string, password: string, fullName?: string) => Promise<User>;
  logout: () => void;
  loadUser: () => Promise<void>;
  clearError: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isLoading: false,
  error: null,

  login: async (email, password) => {
    set({ isLoading: true, error: null });
    try {
      const res = await authAPI.login(email, password);
      localStorage.setItem('access_token', res.data.access_token);
      localStorage.setItem('refresh_token', res.data.refresh_token);
      const me = await authAPI.getMe();
      set({ user: me.data, isLoading: false });
      return me.data;
    } catch (err: unknown) {
      const { getApiError } = await import('@/lib/api');
      const message = getApiError(err, 'Sign in failed');
      set({ isLoading: false, error: message });
      throw new Error(message);
    }
  },

  register: async (email, password, fullName) => {
    set({ isLoading: true, error: null });
    try {
      await authAPI.register(email, password, fullName);
      // Auto sign-in after registration
      const res = await authAPI.login(email, password);
      localStorage.setItem('access_token', res.data.access_token);
      localStorage.setItem('refresh_token', res.data.refresh_token);
      const me = await authAPI.getMe();
      set({ user: me.data, isLoading: false });
      return me.data;
    } catch (err: unknown) {
      const { getApiError } = await import('@/lib/api');
      const message = getApiError(err, 'Registration failed');
      set({ isLoading: false, error: message });
      throw new Error(message);
    }
  },

  logout: () => {
    // Fire-and-forget USER_LOGOUT record; sign-out proceeds regardless.
    void authAPI.logout().catch(() => undefined);
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    set({ user: null, error: null });
  },

  loadUser: async () => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
    if (!token) {
      set({ user: null, isLoading: false });
      return;
    }
    set({ isLoading: true });
    try {
      // getMe goes through the shared axios instance: an expired access
      // token is refreshed + retried transparently by the interceptor.
      const me = await authAPI.getMe();
      set({ user: me.data, isLoading: false });
    } catch (err) {
      // Only true auth failures clear the session (the interceptor already
      // attempted refresh + redirect). Transient network/server errors keep
      // tokens so a retry can succeed without forcing re-login.
      if (getApiStatus(err) === 401 || getApiStatus(err) === 403) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        set({ user: null, isLoading: false });
      } else {
        set({ isLoading: false });
      }
    }
  },

  clearError: () => set({ error: null }),
}));
