import { readFileSync } from 'node:fs';

const requireBoundary = (condition, message) => {
  if (!condition) throw new Error(message);
};

const compose = readFileSync('compose.yaml', 'utf8');
const overlay = readFileSync('compose.go.yaml', 'utf8');
const production = readFileSync('compose.production.yaml', 'utf8');
const runnerImage = readFileSync('docker/go-runner.Dockerfile', 'utf8');

requireBoundary(compose.includes('dockerfile: docker/go-api.Dockerfile'), 'compose.yaml must ship the Go API image');
requireBoundary(compose.includes('dockerfile: docker/go-runner.Dockerfile'), 'compose.yaml must ship the Go runner image');
requireBoundary(compose.includes('dockerfile: docker/go-executor.Dockerfile'), 'compose.yaml must ship the Go executor image');
requireBoundary(compose.includes('dockerfile: docker/go-agent.Dockerfile'), 'compose.yaml must ship the Go agent image');
requireBoundary(compose.includes('dockerfile: docker/go-network-guard.Dockerfile'), 'compose.yaml must ship the Go network-guard image');
requireBoundary(compose.includes('dockerfile: docker/go-model-gateway.Dockerfile'), 'compose.yaml must ship the Go model-gateway image');
requireBoundary(compose.includes('entrypoint: ["/ingress-proxy"]'), 'compose.yaml must run the credential-free Go ingress binary');
requireBoundary(compose.includes('entrypoint: ["/provisioning-proxy"]'), 'compose.yaml must run the allowlisted Go provisioning-proxy binary');
requireBoundary(compose.includes('test: ["CMD", "/cloud-harness-mcp", "--healthcheck"]'), 'compose.yaml API must use the distroless --healthcheck probe');
requireBoundary(compose.includes('test: ["CMD", "/ingress-proxy", "--healthcheck"]'), 'compose.yaml ingress must use the distroless --healthcheck probe');
requireBoundary(compose.includes('test: ["CMD", "/runner", "--healthcheck"]'), 'compose.yaml runner must use the binary --healthcheck probe');
requireBoundary(compose.includes('test: ["CMD", "/model-gateway", "--healthcheck"]'), 'compose.yaml model-gateway must use the distroless --healthcheck probe');
requireBoundary(compose.includes('test: ["CMD", "/provisioning-proxy", "--healthcheck"]'), 'compose.yaml provisioning-proxy must use the distroless --healthcheck probe');
requireBoundary(!compose.includes('dockerfile: docker/api.Dockerfile'), 'compose.yaml must not ship the TypeScript API image');
requireBoundary(!compose.includes('dockerfile: docker/runner.Dockerfile'), 'compose.yaml must not ship the TypeScript runner image');
requireBoundary(!compose.includes('dockerfile: docker/executor.Dockerfile'), 'compose.yaml must not ship the TypeScript executor image');
requireBoundary(!compose.includes('dockerfile: docker/agent.Dockerfile'), 'compose.yaml must not ship the TypeScript agent image');
requireBoundary(!compose.includes('dockerfile: docker/network-guard.Dockerfile'), 'compose.yaml must not ship the TypeScript network-guard image');
requireBoundary([...compose.matchAll(/node, -e/g)].length === 1, 'only fake-provider may use a node -e healthcheck');
requireBoundary(!compose.includes('node, /app/deploy/ingress-proxy.mjs') && !compose.includes('"node", "/app/deploy/ingress-proxy.mjs"'), 'compose.yaml must not run the TypeScript ingress command');
requireBoundary(!compose.includes('node, /app/deploy/provisioning-proxy.mjs') && !compose.includes('"node", "/app/deploy/provisioning-proxy.mjs"'), 'compose.yaml must not run the TypeScript provisioning-proxy command');
requireBoundary(compose.includes('image: cloud-harness-model-gateway-ts:local'), 'gateway-test must keep a TypeScript model-gateway image');
requireBoundary(compose.includes('dockerfile: docker/model-gateway.Dockerfile'), 'gateway-test must still build the TypeScript model-gateway image');
requireBoundary(compose.includes('command: [node, apps/model-gateway/dist/index.js]'), 'gateway-test must keep the TypeScript model-gateway command');
requireBoundary(compose.includes('command: [node, apps/model-gateway/dist/fake-provider.js]'), 'gateway-test must keep the TypeScript fake-provider command');

requireBoundary(overlay.includes('compose.yaml now ships Go binaries'), 'Go overlay must document that compose.yaml ships Go');
requireBoundary(overlay.includes('services: {}'), 'Go overlay must be a no-op after the Compose cutover');
requireBoundary(!/ports:/.test(overlay), 'Go overlay must not publish additional host ports');
requireBoundary(!/docker\.sock/.test(overlay), 'Go overlay must not remount the Docker socket');
requireBoundary(!/TOKEN|SECRET|PASSWORD|GITHUB_APP/.test(overlay), 'Go overlay must not inject secrets onto any service');

requireBoundary(runnerImage.includes('docker-cli'), 'Go runner image must install docker-cli to talk to the host daemon');
requireBoundary(!/^FROM .*(distroless)/m.test(runnerImage.split('\n').filter((line) => !line.trim().startsWith('#')).join('\n')), 'Go runner image must not be distroless');
requireBoundary(production.includes('command: ["--hold"]'), 'production agent keepalive must use distroless --hold, not sleep');
requireBoundary(!/agent-image-keepalive:[\s\S]*sleep/.test(production), 'agent keepalive must not require a distroless-missing sleep binary');
requireBoundary(/executor-image-keepalive:[\s\S]*command: \["sleep", "infinity"\]/.test(production), 'executor keepalive may keep sleep because the executor image is not distroless');

console.log('go compose overlay boundaries ok');
