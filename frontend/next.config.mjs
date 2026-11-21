// Local development talks to the FastAPI service on localhost; docker-compose
// overrides this with `BACKEND_URL=http://backend:8000` (see frontend/Dockerfile).
const backend = process.env.BACKEND_URL || "http://127.0.0.1:8000";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async rewrites() {
    // The browser always talks to the Next.js origin; API calls are proxied
    // to the FastAPI service so no CORS / localhost issues exist.
    return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
  },
};

export default nextConfig;
