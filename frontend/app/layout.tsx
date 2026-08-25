import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'GuardianAudit — Network Security Compliance Console',
  description:
    'AI-driven multi-vendor network security compliance auditing. Evidence-backed findings, benchmark evaluation, adaptive learning.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-base-950 text-slate-200 antialiased`}>
        {children}
      </body>
    </html>
  )
}
