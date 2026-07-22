/** @type {import('next').NextConfig} */
const nextConfig = {
  // @paygent/guard is a workspace ESM package; let Next transpile it.
  transpilePackages: ["@paygent/guard"],
  reactStrictMode: true,
};

export default nextConfig;
