#!/usr/bin/env node
/**
 * Print what PQC-hybrid TLS this Node runtime can actually do, honestly. Run:
 *   node examples/tls_report.js
 */
import * as tls from '../src/tls.js';

const caps = tls.capabilities();
console.log(caps.summary());
console.log(JSON.stringify(caps.asDict(), null, 2));

// An https.Agent you can pass to fetch/https with the best TLS posture this runtime allows:
const agent = tls.pqcHttpsAgent();
console.log('\nagent PQC hybrid available:', agent.pqcCapabilities.pqcHybridAvailable);
