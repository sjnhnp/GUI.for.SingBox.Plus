# Sync Upstream (Smart Merge)

This workflow guides the AI to merge upstream changes into the local repository using standard Git merge strategies, avoiding destructive overwrites.

## 1. Preparation

1. **Check Clean State**:
   - Run `git status`.
   - Ensure the working directory is clean. If not, ask the user to commit or stash changes.

2. **Verify Remote**:
   - Run `git remote -v`.
   - Ensure `upstream` points to `https://github.com/GUI-for-Cores/GUI.for.SingBox.git`.
   - If not, run: `git remote add upstream https://github.com/GUI-for-Cores/GUI.for.SingBox.git`.

## 2. Fetch and Merge

1. **Fetch Upstream**:
   // turbo
   - Run `git fetch upstream`.

2. **Merge**:
   - Run `git merge upstream/main`.
   - **Note**: This attempts an automatic merge.
   - If the output says "Already up to date", you are done.
   - If the output says "CONFLICT", **STOP**. Do not proceed to build yet.

## 3. Intelligent Conflict Resolution (If Conflicts Occur)

If the merge step resulted in conflicts, follow these rules for each conflicted file:

1. **Identify Conflicts**: Run `git status` to see unmerged paths.

2. **Resolve**:
   - Open each conflicted file.
   - Look for `<<<<<<< HEAD` (Your changes) vs `>>>>>>> upstream/main` (Their changes).
   - **Goal**: Keep **New Upstream Logic** AND **Your Customizations**.
   - *Example*: If you changed the App Name in a config, keep your name, but accept new config fields around it.
   - *Example*: If upstream added a new Go function, keep it.
   - *Example*: If upstream modified a file you haven't touched, accept their changes.

### ❗ Special Considerations for GUI.for.SingBox.Plus

When merging, you **MUST** ensure the following custom logic is preserved or correctly integrated, as it fixes critical compatibility issues with newer sing-box kernels:

1. **DNS Rule Restoration (`frontend/src/utils/restorer.ts`)**:
   - Ensure that `restoreDnsRules` handles rules where `raw.action` is missing.
   - It **MUST** default to `RuleAction.Route` and correctly map the `server` field from the source JSON, even if `action` is omitted in the input.

2. **DNS Rule Generation (`frontend/src/utils/generator.ts`)**:
   - For DNS rules, the generator **MUST** include an explicit `"action": "route"` field in the output JSON.
   - All "listable" match fields (like `domain_suffix`, `ip_cidr`, etc.) **MUST** be generated as **arrays**, even if they contain only a single value. This is required for strict parsing in modern sing-box kernels.

3. **Mark Resolved**:
   - After editing, run `git add <file>`.

4. **Finalize Merge**:
   - Run `git merge --continue`.
   - Enter a commit message if prompted (or standard default).

## 4. Post-Merge Verification

1. **Frontend Dependencies**:
   - Check if `frontend/package.json` has changed.
   - If yes, run `npm install` inside the `frontend` directory.

2. **Build Test**:
   - If the user has `wails` installed, try `wails build`.
   - Otherwise, ensure `frontend` builds: `npm run build` (inside `frontend`).

## 5. Completion

1. **Push**:
   - Once verified, ask the user if they want to push: `git push origin main`.
