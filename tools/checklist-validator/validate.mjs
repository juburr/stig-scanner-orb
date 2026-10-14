// Validate the artifacts' consumer identity and every review outcome, not just syntax.
import fs from 'node:fs'
import path from 'node:path'
import assert from 'node:assert/strict'
import { reviewsFromCkl, reviewsFromCklb } from '@nuwcdivnpt/stig-manager-client-modules'

const importOptions = { autoStatus: 'saved', unreviewed: 'always', unreviewedCommented: 'notchecked', emptyDetail: 'ignore', emptyComment: 'ignore', allowCustom: true }
const fieldSettings = { detail: { enabled: 'always', required: 'always' }, comment: { enabled: 'findings', required: 'findings' } }
const statusMap = { NotAFinding: 'pass', Open: 'fail', Not_Applicable: 'notapplicable', Not_Reviewed: 'notchecked' }

function validate(dir) {
  const meta = JSON.parse(fs.readFileSync(path.join(dir, 'checklist-meta.json'), 'utf8'))
  assert.equal(meta.outcome, 'generated', `${dir}: expected generated checklist`)
  const release = /^Release: ([0-9]+) Benchmark Date:/.exec(meta.stig.releaseinfo)
  assert(release, 'missing canonical release')
  const expected = Object.fromEntries(Object.entries(statusMap).map(([ckl, result]) => [result, meta.status[ckl] || 0]))
  for (const ext of Object.keys(meta.formats)) {
    const file = path.join(dir, `checklist.${ext}`)
    const parser = ext === 'ckl' ? reviewsFromCkl : reviewsFromCklb
    const parsed = parser({ data: fs.readFileSync(file, 'utf8'), importOptions, fieldSettings, allowAccept: false, sourceRef: file })
    assert.deepEqual(parsed.errors ?? [], [], `${file}: parser errors`)
    assert.equal(parsed.checklists.length, 1, `${file}: checklist count`)
    const checklist = parsed.checklists[0]
    assert.equal(checklist.benchmarkId, meta.stig.benchmark_id, `${file}: STIG identity`)
    assert.equal(checklist.revisionStr, `V${meta.stig.version}R${release[1]}`, `${file}: revision`)
    assert.equal(parsed.target.name, meta.host_name, `${file}: asset identity`)
    assert.equal(checklist.reviews.length, meta.vulns, `${file}: dropped rows`)
    const actual = Object.fromEntries(Object.values(statusMap).map(s => [s, 0]))
    for (const review of checklist.reviews) {
      assert(review.result in actual, `unknown review result: ${review.result}`)
      actual[review.result]++
    }
    assert.deepEqual(actual, expected, `${file}: changed review outcomes`)
    console.log(`${file}: ${checklist.reviews.length} reviews; ${checklist.benchmarkId} ${checklist.revisionStr}; identity and outcomes match`)
  }
}
for (const dir of process.argv.slice(2)) validate(dir)
assert(process.argv.length > 2, 'pass one or more output directories')
