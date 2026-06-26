# Network Scan CLI (Русская документация)

Основной README проекта: [README.md](README.md).  
Этот файл — дополнительная русская версия с практическими рекомендациями по эксплуатации.

## Назначение

Решение выполняет контейнеризированный пайплайн для больших сетей:
- вход: `CIDR + IP + FQDN`
- этапы: `resolve -> discovery -> fast ports -> Nmap NSE (версии сервисов/ОС + уязвимости/CVE)`
- выход: `JSON/JSONL/CSV` + сводка `Markdown/HTML`

## Быстрый старт

### 1) Сборка

```bash
docker compose build
```

### 2) Подготовка входов

Заполните:
- `scanner/inputs/ranges.txt`
- `scanner/inputs/domains.txt`
- при необходимости `scanner/inputs/ports.txt`

### 3) Запуск

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced
```

### 4) Возобновление после прерывания

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced --resume
```

С включённым `per_run_output` (по умолчанию) resume продолжает последний прогон из
`scanner/state/latest_run.json` или явный id:

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced \
  --resume --run-id 20260626T104530Z
```

## Валидация конфигурации

YAML проверяется при старте через **Pydantic** (`scanner/pipeline/config_schema.py`):
неверные ключи, ссылки на несуществующие профили, выход за диапазоны — ошибка с кодом `2`.

## Каталоги на каждый прогон

При `runtime.per_run_output: true` (по умолчанию):

- `scanner/output/runs/<run_id>/` — артефакты и `run_meta.json`
- `scanner/state/runs/<run_id>/` — checkpoint
- `scanner/state/latest_run.json` — указатель на последний `run_id`

`run_id` — UTC-метка времени или `--run-id`. `per_run_output: false` — плоская схема как раньше.

## Коды выхода

| Код | Значение |
|-----|----------|
| `0` | Успех |
| `1` | Неожиданная внутренняя ошибка |
| `2` | Ошибка валидации конфигурации |
| `3` | Нет валидных целей после проверки входа |
| `4` | Сбой внешнего инструмента после ретраев |
| `130` | Прерывание (Ctrl+C) |

## Логирование и лимиты

- Ротация логов: `pipeline.log` с `log_max_bytes` / `log_backup_count` в `runtime:`.
- `docker-compose.yml`: `mem_limit: 4g`, `cpus: "4.0"`, ulimits `nproc`/`nofile`.

## Рекомендации по профилям и rate-limit

Ниже стартовые значения для `discover_rate` / `port_rate`.  
Увеличивайте постепенно, контролируя нагрузку, потери и срабатывания IDS/IPS.

| Размер цели | Режим | Рекомендованный стартовый rate |
|---|---|---|
| `/24` | `safe` | `500-1000` pps |
| `/16` | `balanced` | `2000-4000` pps |
| `/16` (агрессивно) | `fast` | `5000-8000` pps |
| `>/16` (батчами) | `balanced/fast` | `3000-7000` pps на воркер |

Практика:
- Для первой разведки используйте `top-100` или `top-1000`, а не полный `1-65535`.
- Запускайте NSE только по найденным `host:port`, не по всей подсети.
- Делите большие диапазоны на части и запускайте контролируемо (batch/window).

## Рекомендованный процесс для больших сетей

1. **Нормализация целей**: валидация `CIDR/IP/FQDN`.
2. **Resolve**: FQDN -> IP через `dnsx`.
3. **Discovery**: определение живых хостов (побатчево).
4. **Fast ports**: быстрый проход по `top-ports`/custom ports (побатчево).
5. **NSE/Nmap**: углубление только для найденных открытых портов — определение версий сервисов, **версии ОС (`-O`)** и **уязвимостей (NSE-категория `vuln` + `vulners`/`vulscan` → CVE)**. Этап выполняется параллельно пулом процессов nmap.
6. **Отчеты**: экспорт JSON/CSV + сводка, включая найденные ОС и потенциальные уязвимости.

## Батчинг и возобновление (resume)

Большие диапазоны разбиваются на независимые батчи, чтобы единый запуск `naabu`/`nmap`
не упирался в глобальный таймаут, сбой одного батча не валил весь скан, а `--resume`
переделывал только незавершённое.

- IPv4-сети крупнее `batching.ipv4_prefix` дробятся на батчи `/ipv4_prefix`
  (например, `/16` → 16 × `/20`). Одиночные IP, IPv6 и мелкие сети группируются по
  `batching.max_targets_per_batch`.
- Discovery и port-scan идут **побатчево** (опционально **параллельно** через
  `runtime.discover_concurrency` / `runtime.ports_concurrency`); живые хосты и открытые
  порты инкрементально агрегируются в `alive_ips.txt` / `open_ports.txt`. Каждый
  параллельный naabu использует `discover_rate` / `port_rate` профиля — суммарный
  сетевой шум ≈ `rate × concurrency`.
- Этап NSE/OS чекпойнтится **по хостам** — `--resume` пропускает уже отсканированные.
- Прогресс — в `scanner/state/checkpoint.json` (флаги стадий + множества элементов:
  id батчей `discover`/`ports`, хосты `nse`). Запись потокобезопасна и атомарна по элементу.

Настройка/отключение — секция `batching:` в `scanner/config/default.yaml`
(`enabled`, `ipv4_prefix`, `max_targets_per_batch`). Меньший `ipv4_prefix` — более
дробный resume ценой большего числа запусков инструментов.

## Параллелизм и таймауты NSE

- `runtime.discover_concurrency` / `runtime.ports_concurrency` — число параллельных
  батчей naabu на этапах discovery и port-scan (по умолчанию `4`). `1` — строго
  последовательно. Эффективный pps ≈ `rate × concurrency`.
- `runtime.nse_concurrency` / `profiles.<name>.nse_concurrency` — число одновременно запускаемых процессов nmap. Увеличивайте под мощность хоста и допустимый сетевой шум.
- `runtime.nse_max_rate` / `profiles.<name>.nse_max_rate` — глобальный бюджет пакетов/сек на этап NSE/OS. Делится между параллельными процессами nmap (каждый получает `nse_max_rate / nse_concurrency` через `nmap --max-rate`). `0` — без ограничения (полагаемся на тайминг-шаблон). Так совокупный шум скана остаётся ограниченным независимо от уровня параллелизма.
- `runtime.nse_timeout_seconds` — таймаут nmap на один хост (отдельно от глобального `timeout_seconds`; максимум **600** с / 10 мин).
- `nse_profiles.<name>.os_detection: true` включает `nmap -O --osscan-guess`. Требует raw-сокетов (`NET_RAW`/`NET_ADMIN`, уже выданы в `docker-compose.yml`).

Артефакты по ОС и уязвимостям: `scanner/output/os_findings.json`, `scanner/output/script_findings.json`, `scanner/output/vulnerabilities.json`, `scanner/output/vulnerabilities.csv`.

## Проверка уязвимостей

Этап NSE выполняет проверку уязвимостей в зависимости от профиля `nse_profiles`:

- `vuln` — категория Nmap `vuln` **+ `vulners`**: сопоставление версий сервисов (`-sV`) с CVE через API vulners.com. Привязан к `balanced`/`fast`. **Требует исходящего доступа в интернет**.
- `vuln-offline` — категория `vuln` **+ `vulscan`**: офлайн-сопоставление CVE по локальным базам (интернет не нужен).
- `baseline` — только неинтрузивные `default,safe` (используется в `safe`).

Скрипты `nmap-vulners` и `vulscan` ставятся в образ на этапе сборки (`Dockerfile`, версии пинуются через build-args `NMAP_VULNERS_REF` / `VULSCAN_REF`).

Находки структурируются: для каждого `CVE` извлекается `cvss` и вычисляется `severity` (`critical >= 9.0`, `high >= 7.0`, `medium >= 4.0`, `low > 0`, иначе `unknown`). Скрипты со `State: VULNERABLE` без CVE тоже фиксируются (severity `unknown`). Список отсортирован по убыванию критичности.

## Когда выбирать `safe` / `balanced` / `fast`

- `safe`: чувствительная среда, есть риск деградации сети.
- `balanced`: рабочий режим по умолчанию для регулярных прогонов.
- `fast`: допустим повышенный шум и нужно сократить общее время скана.

## Полезные проверки

- Smoke-тест:

```bash
./scripts/smoke.sh
```

- Быстрый нагрузочный прогон по **вашей сети** (вне CI):

```bash
./scripts/load-test.sh 10.0.0.0/16
```

- **Синтетический load test** в docker (как в CI) — N контейнеров-мишеней, без интернета:

```bash
docker build -t network-scan-cli:ci .
tests/load/run.sh network-scan-cli:ci --hosts 16
tests/load/run.sh network-scan-cli:ci --hosts 64 --config tests/load/config-heavy.yaml \
  --run-id local-heavy --resume-test
```

В CI на каждый PR — 16 мишеней (`tests/load/config.yaml`). Тяжёлый прогон (64+ хостов,
checkpoint resume) — workflow `.github/workflows/load-test.yml` (вручную или по cron раз в неделю).

- Модульные тесты чистых функций и парсеров (валидация входа, группировка портов,
  разбор `host:port` с IPv6, деление rate-budget, сборка команды nmap, извлечение
  сервисов/ОС/CVE с CVSS и severity из отчётов nmap):

```bash
pip install -r requirements-dev.txt
python -m pytest -q
ruff check scanner tests
```

## Контейнерный образ (GHCR) и CI

- CI (`.github/workflows/ci.yml`) на каждый push в `master` и PR гоняет `ruff`, `pytest`
  (Python 3.11/3.12) и job `image`: сборка, smoke-проверка инструментов, **end-to-end скан**
  против тестового контейнера, **синтетический load test** (16 мишеней), **сканирование образа Trivy**
  и генерация **SBOM**.
- E2E (`tests/e2e/run.sh`): поднимает целевой контейнер (`nginx:alpine`) в приватной docker-сети,
  запускает сканер с минимальным офлайн-конфигом и проверяет, что хост жив, порт `80` открыт,
  сервис определён и отчёты сформированы.
- Trivy: неблокирующий отчёт (CRITICAL/HIGH/MEDIUM) + гейт, падающий только на **устранимые
  CRITICAL**. SBOM (SPDX) выгружается артефактом; при публикации к образу прикрепляются
  аттестации **SBOM + SLSA provenance**.
- Публикация (`.github/workflows/docker-publish.yml`) собирает мультиарх-образ
  (`linux/amd64`, `linux/arm64`) и пушит его в GHCR по тегу `v*`, при релизе или вручную.
- Готовый образ: `ghcr.io/onixus/octo-man` (теги `latest`, `vX.Y.Z`, `sha-<...>`).

```bash
docker pull ghcr.io/onixus/octo-man:latest
```

Подробности и пример запуска — в [README.md](README.md#container-image-ghcr).

### Воспроизводимые сборки (пины)

Образ запинен сквозно — пересборка байт-в-байт и защита от подмены апстрима/MITM:

- **Базовый образ** — по мультиарх **index digest** (`python:3.12-slim@sha256:...`).
- **dnsx / naabu** — по версии **и** по **sha256** на каждую арку (build-args
  `*_SHA256_AMD64/ARM64`); архив проверяется через `sha256sum -c` при сборке.
- **nmap-vulners / vulscan** — по конкретным **коммитам** (`NMAP_VULNERS_REF`, `VULSCAN_REF`).

Обновление пина: возьмите новый digest (`docker manifest inspect`), sha256 из checksum-файла
релиза и коммит (`git ls-remote ... HEAD`), затем обновите соответствующие `FROM @sha256` /
`ARG` в `Dockerfile`. Digest заморожен, поэтому периодически переустанавливайте его, чтобы
получать обновления безопасности базового образа.

## Эксплуатационные замечания

- Сканируйте только сети, где есть официальное разрешение.
- Высокий PPS может влиять на стабильность сети и вызывать алерты SIEM/IDS.
- Если Docker недоступен (`docker.sock`), запустите Docker Desktop/daemon.
- Для production желательно сохранять историю `scanner/output/summary.json` и сравнивать тренды по запускам.

## Лицензии

Собственный код проекта (пакет `scanner/`, `scripts/`, конфиги и документация)
**пока без лицензии**. До добавления лицензии действует копирайт по умолчанию, и права на
распространение у третьих лиц отсутствуют — добавьте лицензию (например, `MIT` или
`Apache-2.0`) в корень репозитория перед публикацией.

Образ контейнера **включает сторонние инструменты**, каждый под своей лицензией. Python-код
лишь вызывает их как отдельные исполняемые файлы / NSE-скрипты («простое объединение»),
поэтому не является производной работой от них. Однако **распространение собранного образа**
должно соответствовать всем перечисленным ниже лицензиям.

### Инструменты времени выполнения (внутри образа)

| Компонент | Версия | Лицензия | Примечание |
|---|---|---|---|
| Nmap | пакет Debian | Nmap Public Source License (NPSL) v0.95 | кастомная, производная GPLv2, с ограничениями на коммерческое/OEM-распространение — см. <https://nmap.org/npsl/> |
| naabu | `2.6.1` | MIT | ProjectDiscovery |
| dnsx | `1.2.3` | MIT | ProjectDiscovery |
| nmap-vulners | `NMAP_VULNERS_REF` | GPL-3.0 | NSE-скрипт поиска CVE |
| vulscan | `VULSCAN_REF` | GPL-3.0 | NSE-скрипт + локальные базы CVE |

### Базовый образ и пакеты ОС (`python:3.12-slim`, Debian)

| Компонент | Лицензия |
|---|---|
| Python (CPython) | PSF License Agreement |
| ca-certificates (набор CA Mozilla) | MPL-2.0 |
| curl | curl license (в стиле MIT/X11) |
| git | GPL-2.0 |
| jq | MIT |
| unzip (только на этапе сборки, удаляется из финального образа) | Info-ZIP License |

### Python-зависимости

| Пакет | Лицензия | Назначение |
|---|---|---|
| PyYAML | MIT | runtime |
| pytest | MIT | dev/тесты |
| ruff | MIT | dev/линт |

### Замечания по соответствию

- В образе присутствуют компоненты под **GPL-3.0** (`nmap-vulners`, `vulscan`) и Nmap под **NPSL**.
  При распространении образа предоставляйте соответствующий исходный код или письменное
  предложение по требованиям GPL и соблюдайте условия NPSL (в частности, ограничения на
  коммерческое/OEM-распространение; для таких случаев у Nmap Project есть отдельная OEM-лицензия).
- Сканер управляет инструментами через subprocess / NSE и не линкуется с ними статически,
  поэтому ваш собственный код может использовать другую лицензию.
- Эта сводка носит информационный характер и **не является юридической консультацией**;
  перед распространением сверяйтесь с полными текстами лицензий каждого компонента.
