'use client';

import { useEffect, type ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { useAuthStore } from '@/stores/authStore';
import { PageLoader } from '@/components/ui/Progress';

/**
 * Require authentication before rendering protected content.
 * Redirects to /login when no valid session exists.
 */
export function useRequireAuth() {
  const router = useRouter();
  const { user, isLoading, loadUser } = useAuthStore();

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      router.replace('/login');
      return;
    }
    loadUser();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { user, isLoading, isAuthenticated: !!user };
}

export function AuthGate({ children }: { children: ReactNode }) {
  const { user, isLoading } = useRequireAuth();
  if (isLoading || !user) {
    return <PageLoader label="Authenticating" />;
  }
  return <>{children}</>;
}
