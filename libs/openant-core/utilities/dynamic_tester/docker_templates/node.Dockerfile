FROM node:24-slim
WORKDIR /test
COPY package.json .
RUN npm install --production
COPY test_exploit.js .
CMD ["node", "test_exploit.js"]
