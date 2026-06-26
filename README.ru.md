# Network Scan CLI (Русская документация)

Основной README проекта: [README.md](README.md).  
Этот файл — дополнительная русская версия с практическими рекомендациями по эксплуатации.

## Назначение

Решение выполняет контейнеризированный пайплайн для больших сетей:
- вход: `CIDR + IP + FQDN`
- этапы: `resolve -> discovery -> fast ports -> Nmap NSE`
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
3. **Discovery**: определение живых хостов.
4. **Fast ports**: быстрый проход по `top-ports`/custom ports.
5. **NSE/Nmap**: углубление только для найденных открытых портов — определение версий сервисов, **версии ОС (`-O`)** и **уязвимостей (NSE-категория `vuln`)**. Этап выполняется параллельно пулом процессов nmap.
6. **Отчеты**: экспорт JSON/CSV + сводка, включая найденные ОС и потенциальные уязвимости.

## Параллелизм и таймауты NSE

- `runtime.nse_concurrency` / `profiles.<name>.nse_concurrency` — число одновременно запускаемых процессов nmap. Увеличивайте под мощность хоста и допустимый сетевой шум.
- `runtime.nse_max_rate` / `profiles.<name>.nse_max_rate` — глобальный бюджет пакетов/сек на этап NSE/OS. Делится между параллельными процессами nmap (каждый получает `nse_max_rate / nse_concurrency` через `nmap --max-rate`). `0` — без ограничения (полагаемся на тайминг-шаблон). Так совокупный шум скана остаётся ограниченным независимо от уровня параллелизма.
- `runtime.nse_timeout_seconds` — таймаут nmap на один хост (отдельно от глобального `timeout_seconds`).
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

- Быстрый нагрузочный прогон:

```bash
./scripts/load-test.sh 10.0.0.0/16
```

- Модульные тесты чистых функций:

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Эксплуатационные замечания

- Сканируйте только сети, где есть официальное разрешение.
- Высокий PPS может влиять на стабильность сети и вызывать алерты SIEM/IDS.
- Если Docker недоступен (`docker.sock`), запустите Docker Desktop/daemon.
- Для production желательно сохранять историю `scanner/output/summary.json` и сравнивать тренды по запускам.
