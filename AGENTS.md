<!-- BEGIN TASKA INTEGRATION v5 hash:f517fefb -->
## Task tracking (taska)

This repo tracks work in a local, git-native store (`.taska/`) - drive it through the `ta` CLI, never hand-edit `.taska/` and never `git restore` it out from under in-flight work (either corrupts the append-only log). Field names, statuses, task types, and relationships are defined by `.taska/config.toml` and vary per repo, so run `ta prime` for THIS store's schema and copy-paste-ready examples, and `ta <command> --help` for a command's flags.

```bash
ta list --ready                     # actionable work: not done, all deps done
ta show <id> --full                 # one task - every field, full notes
ta create <id> <field>=<value> ...  # file new work (the status field defaults - don't set it)
ta update <id> <field>=<value> ...  # =, +=, -=  (set / append / remove)
ta dep add <id> <type>=<target>     # link a dependency
ta status                           # counts
```

Working habits:
- File a task for each distinct piece of work, before or as you start it, with `notes` rich enough for someone else to act on: the goal, intended approach/implementation details, and any open or design questions.
- For long or multi-line values, read from stdin (`<field>=@-`) or a file (`<field>=@FILE`) instead of quoting on the command line (`+=`/`-=` accept `@` too).
- Set prerequisites with `ta dep add`, and append progress to related tasks (`<field>+=...`) as things change so the trail stays current.
- Read a task's full, untruncated notes with `ta show <id> --full`.
- Commit the `.taska/` change in the same commit as the code it describes; if the store has pending changes unrelated to what you're starting, commit those first.
<!-- END TASKA INTEGRATION -->
