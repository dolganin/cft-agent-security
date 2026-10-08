# Provisioning only: build once with network, then run verification by digest
# with --pull never. No target scripts run on the host.
FROM bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b AS assets
FROM node:24-bookworm@sha256:3d27e5c11e5786e309ec3e03f93ae536eb36e6e5eb3714d5eb3300a36157add0
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/cft
COPY package.json ./
# Juice Shop v20.2.0 has no lockfile. Dependencies are frozen by the resulting
# image digest; provisioning is never part of a verification run.
RUN npm install --ignore-scripts --no-audit --no-fund && npm rebuild esbuild
COPY --from=assets /juice-shop/node_modules/sqlite3 ./node_modules/sqlite3
COPY --from=assets /juice-shop/frontend/dist ./frontend-dist
RUN chmod -R a+rX /opt/cft
USER 1000:1000
ENTRYPOINT ["python3"]
