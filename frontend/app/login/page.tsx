'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Activity, BookOpenCheck, BrainCircuit } from 'lucide-react';
import { useAuthStore } from '@/stores/authStore';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Field, Input } from '@/components/ui/Field';

export default function LoginPage() {
  const router = useRouter();
  const { login, register, error, isLoading, clearError, user } = useAuthStore();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');

  useEffect(() => {
    if (user) router.replace('/dashboard');
  }, [user, router]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    try {
      if (mode === 'login') {
        await login(email, password);
      } else {
        await register(email, password, fullName || undefined);
      }
      router.replace('/dashboard');
    } catch {
      // error surfaced via store
    }
  };

  return (
    <div className="flex min-h-screen">
      {/* Left panel - product narrative */}
      <div className="hidden w-[46%] flex-col justify-between border-r border-base-700 bg-base-900 p-10 lg:flex">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-accent-500/40 bg-accent-500/10">
            <ShieldCheck className="h-5 w-5 text-accent-400" />
          </div>
          <div>
            <p className="text-base font-semibold text-slate-100">GuardianAudit</p>
            <p className="text-[11px] font-medium uppercase tracking-widest text-slate-500">
              Compliance Operations Console
            </p>
          </div>
        </div>

        <div className="space-y-8">
          <h1 className="max-w-md text-2xl font-semibold leading-snug text-slate-100">
            AI-driven security compliance auditing for multi-vendor networks.
          </h1>
          <div className="space-y-4">
            {[
              {
                icon: <Activity className="h-4 w-4" />,
                title: 'Deterministic benchmark evaluation',
                body: 'CIS benchmark controls evaluated with full evidence chains — PASS / FAIL / REVIEW.',
              },
              {
                icon: <BookOpenCheck className="h-4 w-4" />,
                title: 'Multi-vendor support',
                body: 'Cisco IOS XE and Juniper JUNOS configurations normalized into one security model.',
              },
              {
                icon: <BrainCircuit className="h-4 w-4" />,
                title: 'Adaptive learning',
                body: 'Unknown configuration syntax is interpreted by AI and confirmed by administrators.',
              },
            ].map((f) => (
              <div key={f.title} className="flex gap-3">
                <div className="mt-0.5 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-md border border-base-700 bg-base-850 text-accent-400">
                  {f.icon}
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-200">{f.title}</p>
                  <p className="mt-0.5 text-xs text-slate-500">{f.body}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <p className="text-[11px] text-slate-600">
          SIH 2026 · Problem 26155 · NTRO — Blockchain &amp; Cybersecurity
        </p>
      </div>

      {/* Right panel - auth form */}
      <div className="flex flex-1 items-center justify-center p-6">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent-500/40 bg-accent-500/10">
                <ShieldCheck className="h-4.5 w-4.5 text-accent-400" />
              </div>
              <p className="text-sm font-semibold text-slate-100">GuardianAudit</p>
            </div>
          </div>

          <h2 className="text-lg font-semibold text-slate-100">
            {mode === 'login' ? 'Sign in' : 'Create account'}
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            {mode === 'login'
              ? 'Access the compliance operations console.'
              : 'Register to start auditing network configurations.'}
          </p>

          {error && (
            <div className="mt-4">
              <Alert variant="error" title="Sign in failed" onDismiss={clearError}>
                {error}
              </Alert>
            </div>
          )}

          <form onSubmit={submit} className="mt-6 space-y-4">
            {mode === 'register' && (
              <Field label="Full name">
                <Input
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Alex Rivera"
                  autoComplete="name"
                />
              </Field>
            )}
            <Field label="Email">
              <Input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                autoComplete="email"
              />
            </Field>
            <Field label="Password" hint={mode === 'register' ? 'Minimum 8 characters' : undefined}>
              <Input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              />
            </Field>
            <Button type="submit" className="w-full" size="lg" loading={isLoading}>
              {mode === 'login' ? 'Sign in' : 'Create account'}
            </Button>
          </form>

          <p className="mt-5 text-center text-xs text-slate-500">
            {mode === 'login' ? (
              <>
                No account?{' '}
                <button
                  className="font-medium text-accent-400 hover:text-accent-300"
                  onClick={() => {
                    clearError();
                    setMode('register');
                  }}
                >
                  Register
                </button>
              </>
            ) : (
              <>
                Already registered?{' '}
                <button
                  className="font-medium text-accent-400 hover:text-accent-300"
                  onClick={() => {
                    clearError();
                    setMode('login');
                  }}
                >
                  Sign in
                </button>
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  );
}
