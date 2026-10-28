#!/usr/bin/env node
/**
 * @seqr/pqc benchmark — real keygen / encap / decap / sign / verify timings.
 *
 * Runs the genuine FIPS 203/204 operations on THIS machine via the noble backend, plus a
 * classical RSA-2048 baseline via node:crypto. Nothing is looked-up or invented — every
 * row is timed live in-process with process.hrtime.bigint().
 *
 *   node benchmarks/benchmark.js                     # human table
 *   node benchmarks/benchmark.js --iterations 50     # more samples
 *   node benchmarks/benchmark.js --markdown out.md   # + Markdown table
 *   node benchmarks/benchmark.js --quick             # fewer iterations
 */
import crypto from 'node:crypto';
import fs from 'node:fs';

import {
  KeyEncapsulation,
  Signature,
  KEMAlgorithm,
  SignAlgorithm,
  backend,
  version,
} from '../index.js';

const KEM_ALGS = [KEMAlgorithm.ML_KEM_512, KEMAlgorithm.ML_KEM_768, KEMAlgorithm.ML_KEM_1024];
const SIGN_ALGS = [SignAlgorithm.ML_DSA_44, SignAlgorithm.ML_DSA_65, SignAlgorithm.ML_DSA_87];
const MESSAGE = new TextEncoder().encode('pqcmap benchmark message'.repeat(4));

function timeOp(fn, iterations) {
  const samples = [];
  for (let i = 0; i < iterations; i++) {
    const start = process.hrtime.bigint();
    fn();
    samples.push(Number(process.hrtime.bigint() - start) / 1e6); // ms
  }
  return samples;
}

function summarise(backendName, algorithm, operation, samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  return { backend: backendName, algorithm, operation, iterations: samples.length,
    medianMs: median, meanMs: mean, minMs: sorted[0], opsPerSec: median > 0 ? 1000 / median : Infinity };
}

function benchKem(alg, iterations) {
  const kem = new KeyEncapsulation(alg);
  const out = [summarise('noble', alg, 'keygen', timeOp(() => kem.generateKeypair(), iterations))];
  const kp = kem.generateKeypair();
  out.push(summarise('noble', alg, 'encapsulate', timeOp(() => kem.encapsulate(kp.publicKey), iterations)));
  const { ciphertext } = kem.encapsulate(kp.publicKey);
  out.push(summarise('noble', alg, 'decapsulate', timeOp(() => kem.decapsulate(kp.secretKey, ciphertext), iterations)));
  return out;
}

function benchSign(alg, iterations) {
  const sig = new Signature(alg);
  const out = [summarise('noble', alg, 'keygen', timeOp(() => sig.generateKeypair(), iterations))];
  const kp = sig.generateKeypair();
  out.push(summarise('noble', alg, 'sign', timeOp(() => sig.sign(MESSAGE, kp.secretKey), iterations)));
  const signature = sig.sign(MESSAGE, kp.secretKey);
  out.push(summarise('noble', alg, 'verify', timeOp(() => sig.verify(MESSAGE, signature, kp.publicKey), iterations)));
  return out;
}

function benchRsaBaseline(iterations) {
  const kgIters = Math.max(3, Math.floor(iterations / 5));
  const gen = () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const out = [summarise('rsa-2048 (classical)', 'RSA-2048', 'keygen', timeOp(gen, kgIters))];
  const { privateKey, publicKey } = gen();
  const buf = Buffer.from(MESSAGE);
  out.push(summarise('rsa-2048 (classical)', 'RSA-2048', 'sign',
    timeOp(() => crypto.sign('sha256', buf, privateKey), iterations)));
  const signature = crypto.sign('sha256', buf, privateKey);
  out.push(summarise('rsa-2048 (classical)', 'RSA-2048', 'verify',
    timeOp(() => crypto.verify('sha256', buf, publicKey, signature), iterations)));
  return out;
}

function run(iterations, includeRsa) {
  const machine = {
    timestamp: new Date().toISOString(),
    node: process.versions.node,
    v8: process.versions.v8,
    platform: `${process.platform}-${process.arch}`,
    backend: backend(),
    sdkVersion: version,
    iterations,
  };
  const results = [];
  for (const alg of KEM_ALGS) results.push(...benchKem(alg, iterations));
  for (const alg of SIGN_ALGS) results.push(...benchSign(alg, iterations));
  if (includeRsa) results.push(...benchRsaBaseline(iterations));
  return { machine, results };
}

function renderTable(report) {
  const m = report.machine;
  const lines = [
    '='.repeat(78),
    '@seqr/pqc benchmark - real timings on this machine',
    '='.repeat(78),
    `  timestamp : ${m.timestamp}`,
    `  node      : ${m.node} (v8 ${m.v8})`,
    `  platform  : ${m.platform}`,
    `  backend   : ${m.backend}`,
    `  iterations: ${m.iterations} per operation (median reported)`,
    '',
    `  ${'backend'.padEnd(22)} ${'algorithm'.padEnd(12)} ${'operation'.padEnd(12)} ${'median (ms)'.padStart(12)} ${'ops/sec'.padStart(12)}`,
    '  ' + '-'.repeat(72),
  ];
  for (const r of report.results) {
    lines.push(`  ${r.backend.padEnd(22)} ${r.algorithm.padEnd(12)} ${r.operation.padEnd(12)} ${r.medianMs.toFixed(3).padStart(12)} ${r.opsPerSec.toFixed(1).padStart(12)}`);
  }
  lines.push('', '  noble is an audited pure-JS backend; sizes are fixed by the FIPS parameter set.');
  return lines.join('\n');
}

function renderMarkdown(report) {
  const m = report.machine;
  const lines = [
    '<!-- Generated by benchmarks/benchmark.js — do not edit by hand. -->',
    '# @seqr/pqc benchmark results',
    '',
    'Real, live-timed measurements produced by `node benchmarks/benchmark.js` on this machine.',
    '',
    `- **Timestamp:** ${m.timestamp}`,
    `- **Node:** ${m.node} (V8 ${m.v8})`,
    `- **Platform:** ${m.platform}`,
    `- **Backend:** ${m.backend} (@noble/post-quantum)`,
    `- **Iterations:** ${m.iterations} per operation (median reported)`,
    '',
    '| Backend | Algorithm | Operation | Median (ms) | Ops/sec |',
    '|---|---|---|---:|---:|',
  ];
  for (const r of report.results) {
    lines.push(`| ${r.backend} | ${r.algorithm} | ${r.operation} | ${r.medianMs.toFixed(3)} | ${r.opsPerSec.toFixed(1)} |`);
  }
  lines.push('', '> `noble` is a pure-JS FIPS 203/204 implementation. The RSA-2048 rows are a classical',
    '> baseline timed the same way — note PQC keygen is dramatically faster than RSA keygen.');
  return lines.join('\n');
}

function main(argv) {
  const args = new Set(argv);
  let iterations = 20;
  const idx = argv.indexOf('--iterations');
  if (idx >= 0 && argv[idx + 1]) iterations = parseInt(argv[idx + 1], 10);
  if (args.has('--quick')) iterations = 5;
  const includeRsa = !args.has('--no-rsa');

  const report = run(iterations, includeRsa);
  console.log(renderTable(report));

  const jIdx = argv.indexOf('--json');
  if (jIdx >= 0 && argv[jIdx + 1]) {
    fs.writeFileSync(argv[jIdx + 1], JSON.stringify(report, null, 2));
    console.log(`\n  wrote JSON -> ${argv[jIdx + 1]}`);
  }
  const mIdx = argv.indexOf('--markdown');
  if (mIdx >= 0 && argv[mIdx + 1]) {
    fs.writeFileSync(argv[mIdx + 1], renderMarkdown(report));
    console.log(`  wrote Markdown -> ${argv[mIdx + 1]}`);
  }
}

main(process.argv.slice(2));
