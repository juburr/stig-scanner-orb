// Usage: node validate.mjs <module-dir> <file.ckl|file.cklb> [<expected vuln count>]
// Exits non-zero on a parser exception, any parser-reported error, a missing
// revision, or (when given) a review count that differs from the rows written.
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
const [modDir, file, expected] = process.argv.slice(2)
const lib = await import(pathToFileURL(path.join(modDir, 'index.js')).href)
const importOptions = { autoStatus: 'saved', unreviewed: 'always', unreviewedCommented: 'informational', emptyDetail: 'ignore', emptyComment: 'ignore', allowCustom: true }
const fieldSettings = { detail: { enabled: 'always', required: 'always' }, comment: { enabled: 'findings', required: 'findings' } }
const data = fs.readFileSync(file, 'utf8')
const fn = file.endsWith('.cklb') ? lib.reviewsFromCklb : lib.reviewsFromCkl
const r = fn({ data, importOptions, fieldSettings, allowAccept: false, sourceRef: file })
const cl = r.checklists[0]
const errors = r.errors ?? []
const statuses = r.checklists.flatMap(c => c.reviews.map(x => x.status))
console.log(JSON.stringify({ file: path.basename(file), target: r.target.name, checklists: r.checklists.length, benchmarkId: cl.benchmarkId,
  revisionStr: cl.revisionStr, reviews: cl.reviews.length, stats: cl.stats, errors,
  reviewStatus: statuses.reduce((a, s) => (a[s] = (a[s] || 0) + 1, a), {}),
  sample: cl.reviews.find(x => x.result === 'notapplicable') }, null, 1))
let failed = false
if (errors.length) { console.error(`FAIL: parser reported ${errors.length} error(s)`); failed = true }
if (!cl.revisionStr) { console.error('FAIL: no revisionStr'); failed = true }
if (expected && cl.reviews.length !== Number(expected)) { console.error(`FAIL: ${cl.reviews.length} reviews, expected ${expected}`); failed = true }
if (failed) process.exit(1)
