// Operator-owned compact Node test reporter. Runner exit status remains authoritative.
export default async function* report(events) {
  let failures = 0;
  for await (const event of events) {
    if (event.type === 'test:pass' && event.data.skip) {
      yield `SKIP ${event.data.name}: ${String(event.data.skip)}\n`;
    }
    if (event.type === 'test:fail' && failures++ < 8) {
      const error = event.data.details?.error;
      yield `FAIL ${event.data.name}: ${String(error?.cause?.stack ?? error?.stack ?? error).slice(0, 1400)}\n`;
    }
    if (event.type === 'test:summary' && !event.data.file) {
      yield `TEST SUMMARY ${JSON.stringify(event.data)}\n`;
    }
  }
}
