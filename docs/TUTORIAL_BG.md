# LLM Attack Lab GUI – бърз tutorial

- **Targets**: избираш connector (API или Web UI), добавяш auth/cookie, оставяш TLS ignore за self-signed вътрешни системи.
- **Burp Bridge**: ingest от Burp -> create target -> replay baseline/attacked + diff + JSON diff + stream meta.
- **Discovery / WebChat**: offline fingerprint на endpoint и Playwright probe за selector discovery при чат UI без API.
- **Auth / JWT**: негативни тестове по saved target или direct URL с TLS ignore checkbox.

Силен demo flow за портфолио:
1) OpenAI-compatible API
2) Internal chat-router (Custom HTTP JSON + session cookie)
3) Web UI chat без API (Playwright probe + WebChat connector)

## Ново в тази версия (TLS / Proxy / HAR wizard)

### 1) Global TLS профил (Network/TLS таб)
- **Enterprise** – за корпоративна среда, internal CA / proxy, използва verify + може да подадеш CA bundle (.pem).
- **Strict** – стриктен TLS (без trust_env proxy по подразбиране).
- **Insecure** – за lab/test среди със self-signed или broken TLS (само за тестове).

Може да добавиш:
- **CA bundle path** (ако имаш вътрешен root/intermediate CA)
- **Pin host** (SNI override, ако DNS/host е специфичен)
- **Pin SHA256** (certificate fingerprint pinning check)

### 2) Cert pinning test checks
В **Network/TLS** таба има бутон **Run Cert Pinning Check** (има и бутон в Auth/JWT таба).
- Проверява сертификата на URL-а
- Показва SHA256 fingerprint
- Валидира срещу въведения pin (ако има)

### 3) Proxy support (вкл. corporate)
В **Network/TLS** таба и в **Targets** има Proxy настройки:
- `none`
- `system` (ползва системни/ENV proxy настройки)
- `basic` (proxy URL + user/pass)
- `custom_url`
- `ntlm`
- `cntlm`

> Практически съвет: за корпоративен NTLM proxy често е най-стабилно да ползваш **CNTLM** (локален helper) и в GUI да зададеш `http://127.0.0.1:3128`.

### 4) HAR → Target onboarding wizard
В **Burp/Bridge** таба има бутон **HAR → Target Wizard**.
- Импортира Burp/HAR JSON
- Оценява най-вероятните chat/API заявки
- Автоматично попълва Burp raw request полетата
- Опитва да infer-не target connector + headers
- Прилага и global TLS/Proxy настройки към target формата

### 5) Targets могат да наследяват global transport
В **Targets** таба има checkbox: **Inherit global TLS/proxy from Network/TLS tab**.
- Удобно за bug bounty / enterprise среди
- Не е нужно да въвеждаш едни и същи proxy/TLS настройки за всеки target


## Troubleshooting за internal chat-router (когато дава грешки)

### Най-чести причини
1. **Session URL mismatch** – ако paste-неш пълен URL (`.../session/<uuid>/message`), не добавяй втори path.
2. **Липсващи SSO/CSRF headers** – добави `Cookie`, `X-CSRF-Token`, custom `x-*` headers.
3. **TLS / internal CA** – ползвай Global TLS = Enterprise + CA bundle (`.pem`), Insecure само за lab.
4. **Proxy / корпоративна мрежа** – за NTLM често е най-стабилно с CNTLM helper.
5. **Грешен body shape** – HAR → Target Wizard и преглед на `_http_connector` (`prompt_field`, `body_template`, `response_text_paths`).

### Полезен debug flow
- Test Connection (връща по-богата диагностика)
- HAR Wizard → Apply target
- Cert Pinning Check
- Auth/JWT negative tests (за 401/403 поведение)

## Supply Chain / Skills Scanner (defensive)
В **Discovery / WebChat** таба има секция **Supply Chain / Skills Scanner**:
- **Scan Python dir**: статичен анализ на .py (plugins/skills) за рискови импорти и извиквания (os/subprocess/pickle/eval/exec и т.н.).
- **Scan Dockerfile**: търси prompt-injection подобни инструкции в LABEL/коментари.
- **Scan JSON**: сканира tool schemas / manifests / docs за “ignore previous instructions” и подобни фрази.

Използвай това в статията като реален “defense-in-depth” компонент (supply-chain hygiene).

## Internal APIs: session bootstrap (по избор)
Някои вътрешни chat-router-и изискват **първо създаване на session**, после POST към `/session/{id}/message`.

Custom HTTP JSON connector вече поддържа **bootstrap** (best-effort). Добави в `extra_headers._http_connector`:
```json
{
  "bootstrap": {
    "enabled": true,
    "method": "POST",
    "path": "/chat-router/chat/v1/session",
    "body_template": {"mode": "chat"},
    "extract": {"session_id": "data.session_id"}
  }
}
```
Ако не знаеш bootstrap endpoint-а: най-сигурно е да го хванеш в **Burp/HAR** и да го добавиш.
