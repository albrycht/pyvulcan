# pyVulcan

Forwards every new message ("Wiadomości") and every new grade ("Oceny") from the
eduVULCAN e-register (`eduvulcan.pl`, Vulcan UONET+) to e-mail or a webhook (Slack). A sibling of
[pylibrus](https://github.com/albrycht/pylibrus), which does the same for Librus.

## Running

* Make sure you have [installed `uv`](https://github.com/astral-sh/uv?tab=readme-ov-file#installation)
* Checkout **pyvulcan** repository
* Verify everything's installed correctly with `uv run src/pyvulcan/pyvulcan.py --help`
* Setup `pyvulcan.ini` according to [`pyvulcan.ini.example`](pyvulcan.ini.example)
* Check notifications with `uv run src/pyvulcan/pyvulcan.py --test-notify`
* Run from cron every few minutes (see [`Procfile`](Procfile) for piku)

Messages are stored in local SQLite (`pyvulcan.sqlite`); session cookies in
`pyvulcan_cookies.json`. Both files contain private data and are gitignored.

### Multiple children

Add one `[user:Name]` section per child. When one eduVULCAN login has access to
several children, use the same `vulcan_user` in every section and set `student=`
to a substring of the child's mailbox name (e.g. first name).

## Grades

Every run reads all tabs of "Oceny": `Okres 1..3`, `Wyniki egzaminów` and
`Wyniki egzaminów zewnętrznych` (partial grades plus proposed/final periodic grades).
New grades are grouped per subject into one notification containing the details of
the new grade(s) (Ocena, Data, Typ, Opis, Waga, Nauczyciel) and, as a separate list,
all grades the student already has in that subject. A grade whose value changes is
reported as a new grade. `max_age_of_sending_msg_days` applies to grades too
(by grade date); `send_message=unread` is ignored for grades. Disable with
`check_grades=false` (or messages with `check_messages=false`).

## Session handling

Login is done once; cookies are persisted and reused. Every run opens the
messages module, which keeps the server-side session alive when run every few
minutes. When the session expires, pyvulcan logs in again with the password
automatically.

## Webhook attachments in S3

Same as pylibrus. In each webhook user section:
- `webhook_attachments_source=vulcan_link` sends links to attachments on Vulcan
- `webhook_attachments_source=s3://<bucket>/<optional-prefix>` uploads attachments to S3 and sends
  7-day pre-signed links; requires `s3_region`, `s3_access_key_id`, `s3_secret_access_key`
  (optional `s3_session_token`, `s3_endpoint_url`). IAM: `s3:PutObject`, `s3:GetObject`.
  Set a bucket lifecycle rule removing objects after 7 days.

## eduVULCAN API notes

Reverse-engineered from the web app (version 26.06) — may change without notice.

1. **Login** – `POST https://eduvulcan.pl/Account/QueryUserInfo` (`UserName`), then `GET /logowanie`
   for `__RequestVerificationToken`, then `POST /logowanie` with `UserName`, `Password`,
   `captcha-response`, `__RequestVerificationToken` → `302` on success. The captcha is a
   proof-of-work (`div.captcha-wrapper` `data-challenge`/`data-difficulty`/`data-rounds`),
   solved in code if the plain login is rejected.
2. **Students** – `GET https://eduvulcan.pl/api/ap` → hidden `<input id="ap">` with JSON; `Tokens[]` are
   JWTs per student, claim `tenant` is the school symbol (e.g. `warszawazoliborz`).
3. **Messages module SSO** – `GET https://wiadomosci.eduvulcan.pl/<tenant>/App` returns WS-Federation
   auto-submit forms (`wa`, `wresult`, `wctx`); POST them until the app page, whose inline script
   contains `antiForgeryToken` (sent as `X-V-RequestVerificationToken`).
4. **API** – `https://wiadomosci.eduvulcan.pl/<tenant>/api/`:
   - `Skrzynki` – mailboxes `[{globalKey, nazwa, typUzytkownika}]`
   - `OdebraneSkrzynka?globalKeySkrzynka=&idLastWiadomosc=0&pageSize=50` – received messages, newest
     first: `apiGlobalKey, id, data, temat, korespondenci, hasZalaczniki, przeczytana, wazna, wycofana`
   - `WiadomoscSzczegoly?apiGlobalKey=` – `nadawca, odbiorcy[], temat, tresc (HTML), data,
     zalaczniki[{url, nazwaPliku, idZalacznik}]`; does **not** mark the message as read
   - `LiczbyNieodczytanych` – unread counters per mailbox
   - expired session → HTTP `409`

5. **Student panel** – entry point is `uri` claim from the student's JWT
   (`https://uczen.eduvulcan.pl/<tenant>/start?profil=...`), same SSO forms, then
   `https://uczen.eduvulcan.pl/<tenant>/api/`:
   - `Context` – `uczniowie[{key, uczen, idDziennik, oddzial, globalKeySkrzynka, ...}]`
   - `OkresyKlasyfikacyjne?key=&idDziennik=` – `[{id, numerOkresu, dataOd, dataDo}]`
   - `Oceny?key=&idOkresKlasyfikacyjny=` – `ocenyPrzedmioty[{przedmiotNazwa, kolumnyOcenyCzastkowe[{oceny[{wpis,
     dataOceny, kategoriaKolumny, nazwaKolumny, waga, nauczyciel, zmienionaOdOstatniegoLogowania}]}], srednia,
     proponowanaOcenaOkresowa, ocenaOkresowa}]`
   - `Egzaminy?key=`, `EgzaminyZewnetrzne?key=` – exam result tabs (item format not seen yet)
   - errors are HTTP 200 with `{"success": false, "feedback": {"Message": ...}}`

Attachment download (`zalaczniki[].url`) is not yet verified against a real message with attachments.

## Potential improvements

* announcements, homework, timetable, attendance
* switch to the mobile "Hebe" API (device certificate, no web session) if web sessions prove fragile
