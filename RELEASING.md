# Releasing

Production orb publication is tag-driven. The CircleCI continuation workflow
accepts only `vX.Y.Z` tags, runs the complete integration matrix, and publishes
`juburr/stig-scanner-orb@X.Y.Z` only after every required smoke job passes.

## First release: 1.0.0

1. Merge the v1.0.0 release-preparation pull request and wait for the `main`
   pipeline to pass.
2. Confirm the `orb-publishing` CircleCI context is available to this project
   and that `v1.0.0` does not already exist locally, on GitHub, or in the
   CircleCI orb registry.
3. From an up-to-date, clean `main`, create and push an annotated tag:

   ```sh
   git switch main
   git pull --ff-only
   git tag -a v1.0.0 -m "Release stig-scanner-orb 1.0.0"
   git push origin v1.0.0
   ```

4. In CircleCI, verify that all smoke jobs and `orb-tools/publish` pass. A
   failed smoke job must block publication; do not bypass the dependency list.
5. Verify the immutable published version:

   ```sh
   circleci orb info juburr/stig-scanner-orb@1.0.0
   ```

6. Create the matching GitHub release from `CHANGELOG.md`'s 1.0.0 notes.

Never move or reuse a published tag. Correct a failed or defective release by
fixing forward and incrementing the patch version.
