# Sentinel interface design

## Product goal

A first-time user should understand what Sentinel does without knowing the words gateway, heuristic, payload, or SIEM. The primary task is checking a message before it is sent to an AI. The result should explain what was found and what the user can do next.

## Design choices

A light, blue-grey workspace provides a readable message surface. A deep-blue navigation rail separates checking, chat, history, and help. The main checker uses two distinct surfaces: message entry and the decision. A three-state vocabulary is consistent across the result, history, and chat: Can continue, Needs review, Blocked. Colour supplements readable labels.

The first screen has one primary action. Samples include an explanation and never submit themselves. Each result includes readable findings and matching evidence. Technical IDs and raw decision codes are secondary details. Empty states explain the next action; results are not fabricated before inspection.

System fonts and local assets allow the interface to work without external font services or script CDNs. Icons are vendored from the Lucide project under its ISC license in dashboard/web/icons/LICENSE. The history navigation uses Lucide's clock icon.

## Working integration

FastAPI serves the frontend and API from the same origin. Real history and evaluation endpoints support the interface. Connection keys exist only in JavaScript memory for a tab and are sent with the user's chat request. No browser persistence is used. Provider output and evidence are rendered as text or constructed DOM nodes, never injected HTML.

The desktop layout uses a sidebar and adjacent message/result panels. At smaller widths, navigation becomes a compact top bar and the result follows the editor. Focus indicators, form labels, keyboard shortcuts, native dialogs, status announcements, and reduced-motion preferences support keyboard and assistive-technology access. This is not a claim of a full accessibility audit.
