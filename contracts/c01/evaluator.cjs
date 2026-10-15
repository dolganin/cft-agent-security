/* C01 independent source-level evaluator. Run ONLY in networkless Docker.
 * This is not the C03 full application/runtime verifier or execution capability.
 * Input is extracted from the actual TypeScript AST by the operator harness.
 */
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { Sequelize } = require('/juice-shop/node_modules/sequelize');
const input = JSON.parse(fs.readFileSync('/input/expressions.json', 'utf8'));
// Operator baseline, never taken from a patched allowlist.
const originalAllowlist = [
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
];
const rows = [
  [1, 'Apple', 'Fresh red fruit', null],
  [2, "Farmer's Pear", 'Green fruit', null],
  [3, 'Deleted Apple', 'removed', '2020-01-01'],
  [4, 'Zebra', 'Apple description', null]
];
const output = {kind: 'source-level-evaluator', tests: [], runtime_verdict: null};
async function check(id, fn) {
  try { await fn(); output.tests.push({id, status: 'passed'}); }
  catch (_) { output.tests.push({id, status: 'failed'}); }
}
async function main() {
  const db = new Sequelize('sqlite::memory:', {logging: false});
  await db.query('CREATE TABLE Products (id INTEGER, name TEXT, description TEXT, deletedAt TEXT)');
  await db.query('CREATE TABLE EvaluatorSentinel (id INTEGER, name TEXT, description TEXT, deletedAt TEXT)');
  await db.query("INSERT INTO EvaluatorSentinel VALUES (999,'private-evaluator-sentinel','not-a-product',NULL)");
  for (const row of rows) await db.query('INSERT INTO Products VALUES (?,?,?,?)', {replacements: row});
  const query = async criteria => {
    // VM timeout is only defense in depth. Docker is the execution boundary.
    let captured;
    const models = {sequelize: {query: (...args) => { captured = args; }}};
    vm.runInNewContext(input.sql, {criteria, models}, {timeout: 1000});
    assert(captured && captured.length >= 1 && captured.length <= 2);
    const [result] = await db.query(...captured);
    return result.map(r => r.id);
  };
  await check('sql-functional-name-description-order', async () => assert.deepEqual(await query('Apple'), [1,4]));
  await check('sql-functional-empty-no-match', async () => {
    assert.deepEqual(await query(''), [1,2,4]); assert.deepEqual(await query('no-such-product'), []);
  });
  await check('sql-functional-literal-apostrophe', async () => assert.deepEqual(await query("Farmer's"), [2]));
  for (const [id, payload] of [
    ['boolean-original', "')) OR 1=1--"],
    ['boolean-independent', "')) OR (2>1)--"],
    ['union-independent', "')) UNION SELECT id,name,description,deletedAt FROM EvaluatorSentinel--"]
  ]) await check('sql-security-' + id, async () => assert.deepEqual(await query(payload), []));
  await db.close();
  const security = vm.runInNewContext(input.redirect + '\n({redirectAllowlist,isRedirectAllowed})',
                                    {URL}, {timeout: 1000});
  const allowed = 'https://github.com/juice-shop/juice-shop';
  await check('redirect-functional-original-allowlist', () => {
    assert.equal(security.redirectAllowlist.size, 8);
    for (const url of originalAllowlist) assert.equal(security.isRedirectAllowed(url), true);
  });
  await check('redirect-functional-unapproved', () => assert.equal(security.isRedirectAllowed('https://unapproved.invalid'), false));
  for (const [id, url] of [
    ['query-original', 'https://unapproved.invalid/?next=' + allowed],
    ['fragment-independent', 'https://unapproved.invalid/#' + allowed],
    ['userinfo-independent', 'https://github.com@unapproved.invalid/juice-shop/juice-shop'],
    ['suffix-independent', allowed + '.unapproved.invalid'],
    ['protocol-relative-independent', '//unapproved.invalid/?next=' + allowed]
  ]) await check('redirect-security-' + id, () => assert.equal(security.isRedirectAllowed(url), false));
  console.log(JSON.stringify(output));
  process.exitCode = output.tests.some(t => t.status !== 'passed') ? 1 : 0;
}
main().catch(() => { console.log(JSON.stringify({...output, error: 'evaluator_failed'})); process.exitCode=2; });
