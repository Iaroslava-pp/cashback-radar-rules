# Cashback Radar — bank MCC rules

Only public bank reference data belongs here. Never upload card details, transaction history, screenshots, credentials, or other personal information.

The Android app ships a complete offline snapshot. `mcc-rules.json` is a versioned update manifest. Each entry in `changes` specifies an immutable JSON delta and its SHA-256 hash. The app accepts HTTPS only and same-host delta files, validates version continuity and rule data, and commits the update atomically. Errors preserve the old snapshot. Local card/category overrides are never uploaded or overwritten.

A delta contains `fromVersion`, `version`, `upsert`, and `deletedIds`. Publish the delta first, then update the manifest. Increment the version only after reviewing the official bank document, its effective date, MCC ranges, original category names, merchant restrictions, and footnotes. Scheduled client checks target 00:01 Europe/Moscow on the first day of the month, with catch-up after offline periods and daily checks for emergency updates.

The initial Android application is still being verified. A published manifest does not certify completeness of every bank tariff; the app's requirement matrix and source review must also pass before release.
