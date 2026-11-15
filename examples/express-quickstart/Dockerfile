# The Express quickstart as a demo application of deploy/docker-compose.yml's `demo`
# profile, at http://localhost:8091/login. Express and openid-client at the versions
# package.json pins; the base pinned by digest, as every image here is
# (TestEveryBaseImageIsPinnedByDigest).
FROM node:24.22.3-trixie-slim@sha256:af02d57b57719b9657a45199a79264a9437940cd55b3c7b3fc99615654f124a0
ENV NODE_ENV=production
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY server.js ./
# The image's own `node` user, by number, so runAsNonRoot can check it. It listens on
# the redirect URI's port, on 127.0.0.1.
USER 1000:1000
CMD ["node", "server.js"]
