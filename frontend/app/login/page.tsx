'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldCheck, Activity, BookOpenCheck, BrainCircuit, ArrowRight } from 'lucide-react';
import { useAuthStore } from '@/stores/authStore';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Field, Input } from '@/components/ui/Field';

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="flex min-h-screen items-center justify-center text-sm text-black">Loading…</div>}>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const sessionExpired = searchParams.get('session') === 'expired';
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
    } catch {}
  };

  return (
    <div className="flex min-h-screen bg-surface-0">
      {/* Left panel — brand narrative — Odoo generous */}
      <div className="hidden w-[46%] flex-col justify-between bg-white px-12 py-10 lg:flex">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-600 text-white shadow-odoo">
              <ShieldCheck className="h-5 w-5" strokeWidth={2} />
            </div>
            <p className="text-lg font-bold tracking-tight text-black">ConfigShield</p>
          </div>
        </div>

        <div className="space-y-12">
          <div>
            <h1 className="text-4xl font-extrabold leading-tight tracking-tight text-black">
              AI-driven security compliance
              <br />
              for multi-vendor networks.
            </h1>
            <p className="mt-4 max-w-md text-sm leading-relaxed text-black">
              Deterministic benchmarks, normalized security model and Human-in-the-Loop learning — built for enterprise governance.
            </p>
          </div>

          <div className="max-w-md space-y-7">
            {[
              {
                icon: <Activity className="h-4 w-4" strokeWidth={1.75} />,
                title: 'Deterministic benchmark evaluation',
                body: 'CIS benchmark controls evaluated with full evidence chains — PASS / FAIL / REVIEW.',
              },
              {
                icon: <BookOpenCheck className="h-4 w-4" strokeWidth={1.75} />,
                title: 'Multi-vendor normalization',
                body: 'Cisco IOS XE and Juniper JUNOS configurations normalized into one security model.',
              },
              {
                icon: <BrainCircuit className="h-4 w-4" strokeWidth={1.75} />,
                title: 'Adaptive learning engine',
                body: 'Unknown configuration syntax is interpreted by AI and confirmed by administrators.',
              },
            ].map((f) => (
              <div key={f.title} className="flex gap-4">
                <div className="mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                  {f.icon}
                </div>
                <div>
                  <p className="text-sm font-semibold text-black">{f.title}</p>
                  <p className="mt-1.5 text-sm leading-relaxed text-black">{f.body}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <p className="text-xs text-black">
          SIH 2026 · Problem 26155 · NTRO — Blockchain &amp; Cybersecurity
        </p>
      </div>

      {/* Right panel — auth form — Odoo card, generous */}
      <div className="flex flex-1 items-center justify-center bg-surface-50 p-8">
        <div className="w-full max-w-[420px]">
          {/* Mobile logo */}
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-600 text-white shadow-odoo">
              <ShieldCheck className="h-4 w-4" strokeWidth={2} />
            </div>
            <p className="text-sm font-bold tracking-tight text-black">ConfigShield</p>
          </div>

          <div className="card overflow-hidden">
            <div className="px-8 py-8">
              <div>
                <h2 className="text-2xl font-extrabold tracking-tight text-black">
                  {mode === 'login' ? 'Sign in' : 'Create account'}
                </h2>
                <p className="mt-2 text-sm leading-relaxed text-black">
                  {mode === 'login'
                    ? 'Welcome back — access the compliance console.'
                    : 'Register to start auditing network configurations.'}
                </p>
              </div>

              {error && (
                <div className="mt-6">
                  <Alert variant="error" title="Sign in failed" onDismiss={clearError}>
                    {error}
                  </Alert>
                </div>
              )}
              {!error && sessionExpired && (
                <div className="mt-6">
                  <Alert variant="info" title="Session expired">
                    Your session expired after a period of inactivity. Please sign in again —
                    your devices, configurations, and audit history are preserved.
                  </Alert>
                </div>
              )}

              <form onSubmit={submit} className="mt-8 space-y-5">
                {mode === 'register' && (
                  <div>
                    <label className="label !text-black">Full name</label>
                    <input
                      className="input !text-black placeholder:!text-black"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      placeholder="Alex Rivera"
                      autoComplete="name"
                    />
                  </div>
                )}
                <div>
                  <label className="label !text-black">Email address</label>
                  <input
                    className="input !text-black placeholder:!text-black"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    autoComplete="email"
                  />
                </div>
                <div>
                  <label className="label !text-black">Password</label>
                  <input
                    className="input !text-black placeholder:!text-black"
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  />
                  {mode === 'register' && (
                    <p className="mt-2 text-xs text-black">Minimum 8 characters</p>
                  )}
                </div>
                <button type="submit" className="btn-primary w-full py-3" disabled={isLoading}>
                  {isLoading ? (
                    <span className="inline-flex items-center gap-2">
                      <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                      {mode === 'login' ? 'Signing in…' : 'Creating account…'}
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-2">
                      {mode === 'login' ? 'Sign in' : 'Create account'}
                      <ArrowRight className="h-4 w-4" />
                    </span>
                  )}
                </button>
              </form>

              <p className="mt-6 text-center text-sm text-black">
                {mode === 'login' ? (
                  <>
                    No account?{' '}
                    <button
                      className="font-semibold text-black transition-colors hover:text-black hover:underline"
                      onClick={() => { clearError(); setMode('register'); }}
                    >
                      Register
                    </button>
                  </>
                ) : (
                  <>
                    Already registered?{' '}
                    <button
                      className="font-semibold text-black transition-colors hover:text-black hover:underline"
                      onClick={() => { clearError(); setMode('login'); }}
                    >
                      Sign in
                    </button>
                  </>
                )}
              </p>
            </div>
            <div className="border-t border-surface-100 bg-surface-50 px-8 py-4 text-center">
              <p className="text-xs leading-relaxed text-black">Secure by design · Encrypted at rest · Audit-trailed</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
