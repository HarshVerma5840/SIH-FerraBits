# Build Stage
FROM node:18-alpine AS build
WORKDIR /app

# Copy dependency configs
COPY package.json package-lock.json* ./
RUN npm install

# Copy source files
COPY . .

# Build application
RUN npm run build

# Production Stage
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html

# Expose port 80 for serving static pages
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
