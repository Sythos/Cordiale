# Chat row layout trace

Use the trace to measure a blank band between chat rows in a running build.

## Procedure

1. Set the variable `CORDIALE_LAYOUT_TRACE` to `1`.
2. Start Cordiale from the same terminal.
3. Open the channel that shows the gap.
4. Read the standard error output of the terminal.

Example for a Linux or macOS shell:

```sh
CORDIALE_LAYOUT_TRACE=1 cordiale 2> cordiale-layout.log
```

## Output

Each time the layout changes a row, the trace prints one line:

```text
chat row 12: top 480.0, height 22.0
```

The values are in logical pixels, in the content of the chat pane. The index
is the position of the row in the chat model. A date separator is a row.

When two rows with consecutive indexes are not edge to edge, the trace also
prints the distance between them:

```text
chat row 12: 96.0 pixels to the next row
```

A positive value is a blank band. A negative value is an overlap. The trace
prints nothing for a distance of 0.5 pixels or less. The pane builds only the
rows near the view, so the trace does not compare a row with a missing
neighbour.

## Report a gap

Add these items to the issue:

- The Cordiale version and the operating system.
- The channel and the actions before the gap appears.
- The lines of the trace around the gap.
- A screenshot of the gap, if possible.

Compare the row index of the gap with the message order in the channel.
A row with a large height is a tall row. A large distance between two rows is
a blank band.
