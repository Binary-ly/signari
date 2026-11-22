# The Next.js quickstart as a demo application of deploy/docker-compose.yml's `demo`
# profile, at http://localhost:8092/login. Next.js, React and openid-client at the
# versions package.json pins, and everything under them as package-lock.json records
# it, each package checked against the lock's integrity hash by `npm ci`; the base
# pinned by digest, as every image here is (TestEveryBaseImageIsPinnedByDigest).
#
# Built with `next build` here, once. Both routes are force-dynamic, so SIGNARI_ISSUER,
# CLIENT_ID and REDIRECT_URI are read when the container runs, not baked in.
FROM node:24.22.3-trixie-slim@sha256:af02d57b57719b9657a45199a79264a9437940cd55b3c7b3fc99615654f124a0
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund && npm cache clean --force
COPY app ./app
COPY lib ./lib
RUN node_modules/.bin/next build && chown -R 1000:1000 .next
# The image's own `node` user, by number, so runAsNonRoot can check it.
USER 1000:1000
# package.json's start script names port 3000; this takes PORT, on 127.0.0.1 as it does.
CMD ["sh", "-c", "exec node_modules/.bin/next start --hostname 127.0.0.1 --port \"${PORT:-3000}\""]
