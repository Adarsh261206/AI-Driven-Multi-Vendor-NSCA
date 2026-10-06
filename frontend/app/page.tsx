'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { PageLoader } from '@/components/ui/Progress';

export default function HomePage() {
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    router.replace(token ? '/dashboard' : '/login');
  }, [router]);

  return <PageLoader label="Initializing" />;
}
