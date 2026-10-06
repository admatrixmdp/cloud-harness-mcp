#!/usr/bin/env node
// Compatibility shim for TypeScript runner helpers that still exec
// `node /opt/harness/harness-worker.mjs`. The Go executor image has no
// Node worker; stdin JSON is forwarded to the static harness-worker.
import { spawn } from 'node:child_process';

const child = spawn('/opt/harness/harness-worker', [], {
  stdio: ['inherit', 'inherit', 'inherit']
});
child.on('error', (error) => {
  process.stderr.write(String(error));
  process.exit(1);
});
child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
