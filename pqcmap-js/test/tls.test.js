import assert from 'node:assert/strict';
import { test } from 'node:test';

import * as tls from '../src/tls.js';

test('capabilities() reports an honest runtime probe', () => {
  const caps = tls.capabilities();
  assert.equal(typeof caps.opensslVersion, 'string');
  assert.equal(caps.opensslVersionInfo.length, 3);
  assert.equal(typeof caps.pqcHybridAvailable, 'boolean');
  assert.match(caps.summary(), /PQC-hybrid TLS:/);
  assert.ok(caps.notes.some((n) => /MTU/.test(n)));
});

test('buildClientOptions() never configures an unknown group on old OpenSSL', () => {
  const { options, capabilities: caps } = tls.buildClientOptions();
  assert.equal(options.minVersion, 'TLSv1.2');
  assert.equal(typeof options.ecdhCurve, 'string');
  const info = caps.opensslVersionInfo;
  const openssl35Plus = info[0] > 3 || (info[0] === 3 && info[1] >= 5);
  if (openssl35Plus) {
    assert.match(options.ecdhCurve, /X25519MLKEM768/);
    assert.equal(caps.pqcGroupConfigured, true);
  } else {
    // must NOT put the PQC group on a runtime that would reject it
    assert.doesNotMatch(options.ecdhCurve, /MLKEM/);
    assert.equal(caps.pqcGroupConfigured, false);
  }
});

test('buildClientOptions({ verify: false }) disables cert checks (test-only)', () => {
  const { options } = tls.buildClientOptions({ verify: false });
  assert.equal(options.rejectUnauthorized, false);
});

test('pqcHttpsAgent() returns an agent carrying its capabilities', () => {
  const agent = tls.pqcHttpsAgent();
  assert.ok(agent);
  assert.equal(typeof agent.pqcCapabilities.summary, 'function');
});
