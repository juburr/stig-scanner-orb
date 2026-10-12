// Usage: node validate.mjs <module-dir> <file.ckl|file.cklb> [rows=N] [results=...] [benchmark=ID] [revision=VnRm] [host=NAME]
//   rows:      the number of rows the generator wrote.
//   results:   e.g. "pass=62,fail=7,notapplicable=366,notchecked=1", the
//              generator's own tally (NotAFinding=pass, Open=fail,
//              Not_Applicable=notapplicable, Not_Reviewed=notchecked).
//   benchmark: the STIG id the generator claimed (e.g. RHEL_9_STIG).
//   revision:  the release it claimed, as STIG Manager spells it (e.g. V2R9).
//   host:      the asset name it wrote (STIG Manager keys assets on it).
// Exits non-zero on a parser exception, any parser-reported error, a missing
// revision, or any parsed value that differs from an expected one given: an
// identity mismatch means the checklist would not merge into the intended
// STIG release even though every row imports.
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
const [modDir, file, ...opts] = process.argv.slice(2)
const want = {}
for (const o of opts) {
  const i = o.indexOf('=')
  if (i < 1 || !['rows', 'results', 'benchmark', 'revision', 'host'].includes(o.slice(0, i))) throw new Error(`bad option: ${o}`)
  want[o.slice(0, i)] = o.slice(i + 1)
}
const lib = await import(pathToFileURL(path.join(modDir, 'index.js')).href)
// unreviewed:'always' + unreviewedCommented:'notchecked' imports every
// Not_Reviewed row as 'notchecked', with or without comments, so the tally
// maps 1:1 onto the four checklist statuses.
const importOptions = { autoStatus: 'saved', unreviewed: 'always', unreviewedCommented: 'notchecked', emptyDetail: 'ignore', emptyComment: 'ignore', allowCustom: true }
const fieldSettings = { detail: { enabled: 'always', required: 'always' }, comment: { enabled: 'findings', required: 'findings' } }
const data = fs.readFileSync(file, 'utf8')
const fn = file.endsWith('.cklb') ? lib.reviewsFromCklb : lib.reviewsFromCkl
const r = fn({ data, importOptions, fieldSettings, allowAccept: false, sourceRef: file })
const cl = r.checklists[0]
const errors = r.errors ?? []
const results = {}
for (const x of r.checklists.flatMap(c => c.reviews)) results[x.result] = (results[x.result] || 0) + 1
console.log(JSON.stringify({ file: path.basename(file), target: r.target.name, checklists: r.checklists.length, benchmarkId: cl.benchmarkId,
  revisionStr: cl.revisionStr, reviews: cl.reviews.length, results, errors,
  sample: cl.reviews.find(x => x.result === 'notapplicable') }, null, 1))
let failed = false
const fail = msg => { console.error(`FAIL: ${msg}`); failed = true }
if (errors.length) fail(`parser reported ${errors.length} error(s)`)
if (!cl.revisionStr) fail('no revisionStr')
if (r.checklists.length !== 1) fail(`${r.checklists.length} checklists, expected 1`)
if (want.benchmark !== undefined && cl.benchmarkId !== want.benchmark) fail(`benchmarkId ${cl.benchmarkId}, expected ${want.benchmark}`)
if (want.revision !== undefined && cl.revisionStr !== want.revision) fail(`revisionStr ${cl.revisionStr}, expected ${want.revision}`)
if (want.host !== undefined && r.target.name !== want.host) fail(`target name ${JSON.stringify(r.target.name)}, expected ${JSON.stringify(want.host)}`)
if (want.rows !== undefined && cl.reviews.length !== Number(want.rows)) fail(`${cl.reviews.length} reviews, expected ${want.rows}`)
if (want.results !== undefined) {
  const tally = Object.fromEntries(want.results.split(',').map(kv => kv.split('=')).map(([k, v]) => [k.trim(), Number(v)]))
  for (const k of new Set([...Object.keys(tally), ...Object.keys(results)])) {
    if ((results[k] || 0) !== (tally[k] || 0)) fail(`${results[k] || 0} '${k}' results, expected ${tally[k] || 0}`)
  }
}
if (failed) process.exit(1)
