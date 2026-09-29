/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable React Strict Mode for development best practices
  reactStrictMode: true,

  // Configure experimental features
  experimental: {
    // Enable server actions if needed
    serverActions: {
      bodySizeLimit: '10mb',
    },
  },

  // Environment variables exposed to the browser
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  },

  // Webpack configuration if needed
  webpack: (config, { isServer }) => {
    // Fix for certain modules that don't work with SSR
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
      };
    }
    return config;
  },
}

module.exports = nextConfig
