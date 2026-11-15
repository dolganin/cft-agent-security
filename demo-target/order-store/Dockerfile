FROM node:26.9.0-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server.js ./
COPY routes ./routes
COPY public ./public
USER node
EXPOSE 3000
CMD ["node", "server.js"]
