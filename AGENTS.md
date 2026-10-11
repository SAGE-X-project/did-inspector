# Commit and pull request rules

- Use Conventional Commits: a concise English `type: description` describing the actual behavior.
- Write all commit messages and pull request titles and descriptions in English.
- Never include emojis or co-author attribution, including Co-authored-by trailers, in human/agent-authored commits and pull requests. Dependabot-authored changes are the sole exception.
- Keep the content focused on the essential change. Describe behavior explicitly; do not use development phase names or task identifiers.
- Apply these rules to squash commit titles and bodies as well.
- Merge pull requests only with squash merge. After merging, delete the work branch locally and remotely, then update local main to match remote main.

# Pull request review requests

- Never request a code review from SAGE Core Team (`SAGE-X-project/sage-core-dev`), manually or automatically, for any pull request.
- Check CODEOWNERS, Dependabot and workflow assignments before PR creation or readiness. Do not add this team as a reviewer or send it review requests.

# Inspector scope

- The inspector judges an implementation against the pinned specification text. It extracts its own statements from the pinned bytes, checks their SHA-256, and never uses the subject's own validation code, registry or verdicts as its oracle.
- The inspector core must not import any subject implementation. Subjects are reached through adapters in separate Go modules.
- Give PASS only for the subject revision, profile, statement and observer that were actually checked. A statement with no case is NOT_RUN, never PASS.
- Every case names the statement ids it checks and has positive and negative inputs where the statement allows both.
- Write all documentation in English.
