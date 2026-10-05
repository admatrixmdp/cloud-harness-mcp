import { readFileSync } from 'node:fs';

const requireBoundary = (condition, message) => {
  if (!condition) throw new Error(message);
};

const compose = readFileSync('compose.yaml', 'utf8');
const overlay = readFileSync('compose.go.yaml', 'utf8');

requireBoundary(compose.includes('dockerfile: docker/api.Dockerfile'), 'compose.yaml must keep the TypeScript API image');
requireBoundary(compose.includes('dockerfile: docker/runner.Dockerfile'), 'compose.yaml must keep the TypeScript runner image');
requireBoundary(compose.includes('node, /app/deploy/ingress-proxy.mjs') || compose.includes('"node", "/app/deploy/ingress-proxy.mjs"'), 'compose.yaml must keep the TypeScript ingress command');
requireBoundary(!compose.includes('docker/go-api.Dockerfile'), 'compose.yaml must not switch to Go images yet');

requireBoundary(overlay.includes('dockerfile: docker/go-api.Dockerfile'), 'Go overlay must build docker/go-api.Dockerfile');
requireBoundary(overlay.includes('dockerfile: docker/go-runner.Dockerfile'), 'Go overlay must build docker/go-runner.Dockerfile');
requireBoundary(overlay.includes('dockerfile: docker/go-model-gateway.Dockerfile'), 'Go overlay must build docker/go-model-gateway.Dockerfile');
requireBoundary(overlay.includes('command: ["/ingress-proxy"]'), 'Go overlay must run the credential-free ingress binary');
requireBoundary(!/ports:/.test(overlay), 'Go overlay must not publish additional host ports');
requireBoundary(!/docker\.sock/.test(overlay), 'Go overlay must not remount the Docker socket');
requireBoundary(!/TOKEN|SECRET|PASSWORD|GITHUB_APP/.test(overlay), 'Go overlay must not inject secrets onto any service');
requireBoundary(overlay.includes('TypeScript compose.yaml remains the runtime of record'), 'Go overlay must document that TS remains shipped');

console.log('go compose overlay boundaries ok');
