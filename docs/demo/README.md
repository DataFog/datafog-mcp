# README demos

These seven-second looping GIFs show genuine Claude Code interactions recorded on 2026-10-12 with DataFog MCP 1.0.0 and Core 0.4.4. All customer records are synthetic.

- Scan: “Check customers.csv for emails and phone numbers.”
- Transform: “Make a copy with those emails and phone numbers redacted.”

The clips retain the request, DataFog call, and result. Desktop clutter is cropped out and waiting time is cut; responses are unaltered. A DataFog title is added above the recording. Each GIF is 1,260 × 240 pixels, with 10 frames per second and a 96-color palette.

MCP setup and concise response instructions were configured before recording. Both calls explicitly select EMAIL and PHONE; phone detection is opt-in and an explicit selection replaces the defaults. The transform replaces three emails and three phone numbers, preserving the original, CSV structure, names, and purchase information. This example does not demonstrate anonymization.

The sample CSV matches the input shown in both clips. Save it inside your allowed roots to repeat the walkthrough. The sample text file is an additional example, not shown in these clips.
