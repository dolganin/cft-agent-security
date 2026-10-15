// Operator-owned reporter, mounted read-only outside the application snapshot.
import { createHash } from 'node:crypto';
export default async function* report(events) {
  const files = new Set(), names = [], skipped = [], assertion_failures = [];
  let summary = null, failures = 0;
  for await (const event of events) {
    if (event.type === 'test:pass' || event.type === 'test:fail') {
      const data = event.data;
      if (data.file?.startsWith('/workspace/target/test/server/')) {
        files.add(data.file.replace('/workspace/target/', ''));
      }
      names.push([event.type, data.name, data.file, data.line, Boolean(data.skip)]);
      if (data.skip) skipped.push({ name: data.name, reason: String(data.skip) });
      if (event.type === 'test:fail' && data.details?.type !== 'suite') {
        const error = data.details?.error?.cause ?? data.details?.error;
        assertion_failures.push({file: data.file?.replace('/workspace/target/', ''),
          name: data.name, line: Number(String(error?.stack).split(data.file + ':')[1]?.split(':')[0]) || null, failure_type: data.details?.error?.failureType,
          code: error?.code, actual: error?.actual, expected: error?.expected});
      }
      if (event.type === 'test:fail' && failures++ < 8) {
        yield `FAIL ${data.name}: ${String(data.details?.error?.cause?.stack ?? data.details?.error).slice(0, 1000)}\n`;
      }
    }
    if (event.type === 'test:summary' && !event.data.file) summary = event.data;
  }
  yield 'C03 TEST REPORT ' + JSON.stringify({summary, assertion_failures, files: [...files].sort(), skipped,
    event_count: names.length, events_sha256: createHash('sha256').update(JSON.stringify(names)).digest('hex')}) + '\n';
}
