# Writing style

All prose in this repo uses ASD-STE100 Simplified Technical English (STE). This applies to Markdown files, code comments, and help text. Use `docs/user_guide/architecture.md` as the reference example.

STE gives text that is easy to read, easy to translate, and has one meaning only. This is important for a security tool: a reader must not guess what a rule does.

## Sentences

- Write descriptive sentences of 25 words or fewer.
- Write procedural sentences (instructions) of 20 words or fewer.
- Write one idea in each sentence. If a sentence has "and", "but", or "which" between two ideas, make two sentences.
- Put a maximum of six sentences in a paragraph. Each paragraph has one topic.
- Use a vertical list for three or more items, conditions, or steps.
- Use a table for data that has the same structure in each row.

## Words

- Use the active voice. Write "the gateway drops the packet", not "the packet is dropped".
- Write instructions in the imperative: "Run `make smoke`."
- Use the simple tenses: present, past, and future.
- Do not use contractions. Write "does not", not "doesn't".
- Do not use phrasal verbs. Write "remove", not "take out". Write "disable", not "turn off".
- Do not use the "-ing" form of a verb, except in a technical name ("TLS termination").
- Use articles ("a", "an", "the") before nouns.
- Do not use more than three nouns in a cluster. Write "the key of the CA", not "the CA private key file path".
- Do not use words that only show emotion or emphasis ("simply", "just", "really", "obviously").

## Terms

- Use one term for one thing. Do not use synonyms. For example: always "origin server", never "destination" or "upstream" for the same thing.
- `docs/glossary.md` is the one list of terms and their meanings for the repo. Use those terms. Add a new term there, not in the text.
- Code comments never define a term. Use the term from the glossary as it is.
- A Markdown page can have a short terms table when a new reader needs it. Copy the meaning from the glossary. Pages in `docs/user_guide/` cannot link outside that directory, so they keep their own table.
- Do not define a term again in brackets in each sentence.
- Write the product name as "Pi Fortress" in text, headings and diagram labels. Write `pi-fortress` only where it is an identifier: a path, a URL, a package, a host name, a unit, a log prefix, or a command.
- Technical names and technical verbs stay as they are: TLS, SNI, nftables, sinkhole, terminate, strip, drop, refuse, resolve. Keep code identifiers, file names, flags, and log keys exact.

## Do not change

When you rewrite existing text, keep these exactly as they are:

- Headings and section numbers (for example `§5.2`). Links and other docs point to them.
- Facts, numbers, limits, and conditions. Simple words must not change the meaning. If a sentence has two possible meanings, keep the meaning of the original. Do not guess.
- Code blocks, Mermaid diagrams, commands, and output samples.
- Owner placeholders such as `<WINDOW_START>` and `<DOCS_URL>`.
- Links. In `docs/user_guide/`, a link must stay inside that directory.

## Code comments

- The rules above also apply to comments.
- Write a comment only when the reason is not clear from the code: a hidden constraint, an invariant, or a workaround.
- A Go doc comment starts with the name of the item: "// Strip removes ...".
- Do not change a directive or a comment that a tool reads: `//go:build`, `//go:embed`, `//nolint`, `// Output:`, `#!`, `# shellcheck`, and similar.
- Do not change text in a string literal, a heredoc, or a template. That text is output, not a comment.
