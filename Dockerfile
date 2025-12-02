# Use official Node 24.11.0 image as base (LTS)
FROM node:24-alpine

# Set working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json (if exists)
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy all source files
COPY . .

# Build the project
RUN npm run build

# Expose the port your app listens on (optional, adjust if needed)
EXPOSE 3000

# Run the built app
CMD ["node", "dist/main.js"]
