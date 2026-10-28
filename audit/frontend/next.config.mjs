/** @type {import('next').NextConfig} */
const nextConfig = {
  // Lean, self-contained server bundle for the EC2/Docker deploy (.next/standalone).
  // Vercel ignores this and uses its own adapter, so it stays safe for both targets.
  output: "standalone",
  eslint: {
    // Don't fail production builds on lint warnings.
    ignoreDuringBuilds: true,
  },
  async rewrites() {
    // Dev: proxy /api to a local backend. In the AWS stack the backend is a sibling
    // container, so INTERNAL_API_URL=http://backend:8000 makes server-side proxying
    // work container-to-container. Client calls use NEXT_PUBLIC_API_URL directly.
    const internalApi = process.env.INTERNAL_API_URL || "http://localhost:8000";
    return [
      {
        source: "/api/:path*",
        destination: `${internalApi}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
