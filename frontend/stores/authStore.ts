'use client';

import { create } from 'zustand';
import { authAPI } from '@/lib/api';
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
      const me = await authAPI.getMe();
      set({ user: me.data, isLoading: false });
    } catch {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      set({ user: null, isLoading: false });
    }
  },

  clearError: () => set({ error: null }),
}));
