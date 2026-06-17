<!--
  Title must follow Conventional Commits — release-please derives the version + changelog from it:
    feat: ...        → minor (pre-1.0)
    fix: ...         → patch
    feat!: / BREAKING CHANGE: → minor while pre-1.0
    chore:/docs:/ci:/refactor:/test: → no release
-->

## What & why

<!-- A short description of the change and the motivation. Link any issue: Closes #123 -->

## Type of change

- [ ] `fix` — bug fix (no API change)
- [ ] `feat` — new feature / option (semver-relevant — new knobs are minor)
- [ ] `feat!` / BREAKING CHANGE — changes a public signature or default
- [ ] `docs` / `chore` / `ci` / `refactor` / `test` — no release

## Checklist

- [ ] Conventional-commit PR title (drives release-please)
- [ ] `npm run typecheck` passes
- [ ] `npm run lint` passes
- [ ] `npm test` passes (added/updated tests for the change)
- [ ] `npm run build` succeeds
- [ ] `npm run check:exports` (publint + attw) passes — only if the public API / exports map changed
- [ ] Public API change is reflected in `docs/SPEC.md` and the README
- [ ] No new SDK import outside `src/internal/sdk.ts` (SDK insulation, SPEC §8)
- [ ] No secrets, tokens, or machine-specific paths committed
