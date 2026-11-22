# The Express quickstart as a demo application of deploy/docker-compose.yml's `demo`
# profile, at http://localhost:8091/login. Express and openid-client at the versions
# package.json pins, and everything under them as package-lock.json records it, each
# package checked against the lock's integrity hash by `npm ci`; the base pinned by
# digest, as every image here is (TestEveryBaseImageIsPinnedByDigest).
FROM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY server.js ./
# The image's own `node` user, by number, so runAsNonRoot can check it. It listens on
# the redirect URI's port, on 127.0.0.1.
USER 1000:1000
CMD ["node", "server.js"]
