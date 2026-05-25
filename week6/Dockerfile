FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --omit=dev

COPY . .

# create non-root user (security best practice)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

USER appuser

EXPOSE 8443

CMD ["node", "server.js"]
