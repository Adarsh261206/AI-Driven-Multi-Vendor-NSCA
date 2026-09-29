import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({
  subsets: ['latin'],
  weight: ['300', '400', '500', '600', '700', '800', '900'],
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'ConfigShield — Network Security Compliance Console',
  description:
    'AI-driven multi-vendor network security compliance auditing. Evidence-backed findings, benchmark evaluation, adaptive learning.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={`${inter.className} antialiased`} style={{ background: '#f8f9fa', color: '#1a1a19' }}>
        {children}
      </body>
    </html>
  )
}
