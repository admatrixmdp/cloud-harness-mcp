#!/usr/bin/env node
// Unused by the Go executor image. That image must not ship
// harness-worker.mjs: worker-runner.go.sh execs /opt/harness/harness-worker,
// and the TypeScript worker stays in docker/executor.Dockerfile.
// This file only forwards stdin to the static binary if a caller still
// invokes `node` against a copy of it.
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
