# Semantic-release

This package uses [semantic-release](https://www.npmjs.com/package/semantic-release), which enforces the [semantic versioning specification](https://semver.org) in accordance with [Angular's commit message guidelines](https://github.com/angular/angular/blob/main/contributing-docs/commit-message-guidelines.md).

In short, when contributing to this repository all of your commit messages need to be correctly prefixed:

* `fix:` for fixes ("patch"). Increments a version by 0.01.
* `feat:` for new feature releases ("minor"). Increments a version by 0.1.
* `BREAKING CHANGE:` placed in the footer of the commit forces a breaking release ("major"). `!`.
* `chore:`, `docs:`, `ci:`, `test:`, `perf:`, `refactor:` - does not increment the version or trigger a new release at all.

Note that a PR with multiple commits with various prefixes will only trigger a single version incrementation.