# ==========================================
# Stage 1: Build React + Vite Dashboard
# ==========================================
FROM node:20-alpine AS ui-builder
WORKDIR /app/ui

COPY ui/package.json ./
RUN npm install

COPY ui/ ./
RUN npm run build

# ==========================================
# Stage 2: Build Go Gateway Binary
# ==========================================
FROM golang:alpine AS go-builder
WORKDIR /app
ENV GOTOOLCHAIN=auto

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
COPY policies/ policies/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/agentshield ./cmd/gateway

# ==========================================
# Stage 3: Minimal Hardened Runtime
# ==========================================
FROM alpine:3.20

RUN apk --no-cache add ca-certificates curl

WORKDIR /app

# Create non-root application user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create sandboxed directory for simulated tool operations
RUN mkdir -p /workspace/data /app/ui/dist && \
    echo '{"system": "operational", "status": "active"}' > /workspace/data/config.json && \
    chown -R appuser:appgroup /app /workspace

# Copy Go binary and assets
COPY --from=go-builder /app/agentshield /app/agentshield
COPY --from=ui-builder /app/ui/dist /app/ui/dist
COPY policies/ /app/policies/

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/app/agentshield"]
