# SeQr audit frontend (Next.js 14) — production image for the single-box AWS stack.
#
# Multi-stage: install + build with the full toolchain, then ship only the Next.js
# standalone server (server.js + minimal node_modules) + static assets. Runs behind
# Caddy, which terminates TLS for www.seqrlabs.com and reverse-proxies here.
#
# NEXT_PUBLIC_* are BUILD-TIME in Next.js (inlined into the client bundle), so the
# API/WS URLs are passed as build args, not runtime env. Rebuild if they change.
#
# Build context MUST be the frontend dir (audit/frontend/).
#   docker build -t seqrlabs/seqr-frontend audit/frontend
#
# node:20-alpine has arm64 + amd64 variants → builds on Graviton (t4g) unchanged.
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
# npm ci needs a lockfile; fall back to install if the repo has none committed.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Baked into the client bundle at build time.
ARG NEXT_PUBLIC_API_URL="https://api.seqrlabs.com/api/v1"
ARG NEXT_PUBLIC_WS_URL="wss://api.seqrlabs.com"
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
ENV NEXT_PUBLIC_WS_URL=${NEXT_PUBLIC_WS_URL}
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Non-root runtime user.
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001

# Standalone output ships server.js + the minimal node_modules it actually needs.
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
