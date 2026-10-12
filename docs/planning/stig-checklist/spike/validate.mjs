// Usage: node validate.mjs <module-dir> <file.ckl|file.cklb> [<expected rows> [<expected results>]]
//   <expected results>: e.g. "pass=62,fail=7,notapplicable=366,notchecked=1",
//   the generator's own tally (NotAFinding=pass, Open=fail,
//   Not_Applicable=notapplicable, Not_Reviewed=notchecked).
// Exits non-zero on a parser exception, any parser-reported error, a missing
// revision, a review count that differs from the rows written, or a parsed
// result tally that differs from the expected one.
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
const [modDir, file, expectedRows, expectedResults] = process.argv.slice(2)
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
if (errors.length) { console.error(`FAIL: parser reported ${errors.length} error(s)`); failed = true }
if (!cl.revisionStr) { console.error('FAIL: no revisionStr'); failed = true }
if (expectedRows && cl.reviews.length !== Number(expectedRows)) { console.error(`FAIL: ${cl.reviews.length} reviews, expected ${expectedRows}`); failed = true }
if (expectedResults) {
  const want = Object.fromEntries(expectedResults.split(',').map(kv => kv.split('=')).map(([k, v]) => [k.trim(), Number(v)]))
  for (const k of new Set([...Object.keys(want), ...Object.keys(results)])) {
    if ((results[k] || 0) !== (want[k] || 0)) { console.error(`FAIL: ${results[k] || 0} '${k}' results, expected ${want[k] || 0}`); failed = true }
  }
}
if (failed) process.exit(1)
