FROM node:22-alpine
WORKDIR /app
COPY jwt.js proxy.js make-token.js ./
USER node
EXPOSE 3000
CMD ["node", "proxy.js"]
