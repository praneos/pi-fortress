# Diagrams — Pi Fortress, drawn

These files have programmatic diagrams (Mermaid). The diagrams show the
structure of the code and the real flow of traffic. GitHub renders them
automatically. To see them on your computer, refer to "Viewing" below.

| File | What it shows |
|---|---|
| [architecture.md](architecture.md) | The structure of the code and the modules: the one binary, the policy pipeline, the data path for each connection, the DNS plane, and the management plane |
| [flows.md](flows.md) | Real-world behaviour: end-to-end request flows. The flows are: an allowed request with an injected credential, a block at each layer, the OAuth refresh harvest, an unknown origin server, the escapes that fail closed, and a plain segment (the desk) |

The companion tutorials explain the concepts behind the arrows:
[../user_guide/tutorials/README.md](../user_guide/tutorials/README.md).

## Viewing

**GitHub / GitLab:** no action is necessary. Each ```` ```mermaid ```` block in
these files renders inline.

**Browser (fastest, no installation):**

- <https://mermaid.live>: paste the block to see the diagram. It can
  export to SVG/PNG.
- VS Code: install the **Markdown Preview Mermaid Support** extension.
  Then use `Ctrl+Shift+V` in one of these files.

**Zed:**

- Zed ≥ 0.225 renders Mermaid blocks natively in the built-in Markdown
  preview. Open the file, then use `cmd|ctrl+shift+p` → `markdown preview`
  (or the preview button in the tab bar).
- You can render diagrams **inline into the source** as SVG. This is
  reversible, and the result shows in all viewers.
  1. Install a dev extension such as `zed-mermaid-preview`
     (<https://github.com/dawsh2/zed-mermaid-preview>). It downloads its
     renderer automatically.
  2. Put the cursor in a block and use the code action
     `Render Mermaid Diagram` (`ctrl+.` → action).

  `Edit Mermaid Source` restores the code.

**CLI (export to a file, for example for docs/PRs):**

```sh
npm install -g @mermaid-js/mermaid-cli
mmdc -i docs/diagrams/flows.md -o /tmp/flows.svg    # renders all blocks
mmdc -i block.mmd -o block.png -b transparent       # single block, PNG
```

## Conventions used here

- Flowcharts (`graph TB/LR`) show structure. Sequence diagrams show
  behaviour.
- Colour has a meaning:
  - <span>red</span> regions are drops and refusals.
  - Amber is review or observation.
  - Green is allowed.
- Each node label names the real code or policy file that it represents.
  Thus a diagram is a map into the tree. It is not a picture that goes
  out of date without notice. If code moves, move the label.
- Read an arrow as "hands to / feeds". Dashed arrows (`-.->`) are
  observation-only paths. They never carry traffic.
