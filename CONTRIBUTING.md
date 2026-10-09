# Contributing to RDAPI

Thanks for your interest! Bug reports, ideas and pull requests are welcome.

## Reporting problems

Use the issue forms: **Bug report** or **Feature request**. Please include the RDAPI
version (footer of the web interface), the RustDesk app version and platform, and the
relevant lines from `docker compose logs rdapi`; remove passwords, tokens and
addresses first. German is fine too.

Security problems go to **Security → Report a vulnerability** instead, see
[SECURITY.md](SECURITY.md).

Problems with connecting to a device (as opposed to signing in, address book, devices or
history) usually come from the ID or relay server, not from the API server; see
[Troubleshooting](docs/en/usage.md#troubleshooting).

## Pull requests

1. Open an issue first for larger changes, so we can agree on the approach.
2. Set up the development environment as described in
   [Development](docs/en/development.md) and make sure `python -m pytest -q`,
   `python -m ruff check` and `python -m ruff format --check` pass.
3. Keep RDAPI small: sign-in, address book, devices and history for a household or
   a small team.
4. The app API must keep behaving the way the RustDesk app expects; see “What the app
   expects” in [Development](docs/en/development.md#api-endpoints). Add a test that
   replays the app's request.
5. Texts in the interface are written in English and translated in `rdapi/locales/`
   (German, French, Spanish, Italian, Dutch); `tests/test_web.py` fails if a translation is
   missing. Please add all five or say which ones you could not do.
6. Update the documentation in `docs/en` and `docs/de` (and the README if needed) and add
   a line to `CHANGELOG.md` if users will notice the change.

The pull request template has a short checklist for this.

## License

By contributing you agree that your contribution is licensed under the
[AGPL-3.0-or-later](LICENSE), like the rest of RDAPI.
