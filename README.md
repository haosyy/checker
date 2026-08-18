# Anti-Cheat Checker

Добровольный Windows-чекер для ручной проверки игрового окружения.

## Компоненты

- `client/AntiCheat.Client` — .NET-клиент: выполняет правила из `rules.json`, формирует `result.json` и отправляет отчёт relay API.
- `discord-relay` — Cloudflare Worker: принимает отчёт и публикует краткий результат в Discord.

## Проверки v1.1

- точные имена процессов и ключевые слова в именах/путях процессов;
- существование точно заданных папок;
- записи Windows Run/RunOnce;
- совпадения ключевых слов в выводе Task Scheduler;
- совпадения доменов в `HOSTS`;
- имена файлов и двойные расширения в явно заданных папках;
- SHA-256 только для файлов игры, явно указанных в `expectedGameFiles`.

Программа не читает содержимое личных документов, не собирает пароли, cookies или токены браузера, не устанавливает драйверы и не удаляет пользовательские файлы. Совпадения являются основанием для ручной оценки, а не автоматическим доказательством нарушения.

## Настройка правил

Отредактируйте `client/AntiCheat.Client/rules.json`:

- `blockedProcessNames` — точные имена процессов без `.exe`;
- `suspiciousKeywords` — ключевые слова для слабых совпадений;
- `suspiciousDirectories` — точные пути, допустимы `%APPDATA%` и другие переменные среды;
- `hostBlockedDomains` — игровые домены для проверки `HOSTS`;
- `scanRoots` — явно заданные папки для проверки имён файлов;
- `expectedGameFiles` — объекты `{"relativePath":"...","sha256":"..."}` для проверки конкретных игровых файлов.

## Локальный запуск

```powershell
cd client/AntiCheat.Client
dotnet run
```

## Публикация EXE

```powershell
cd client/AntiCheat.Client
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

## Деплой relay

```powershell
cd discord-relay
npx wrangler deploy
```

Установите `DISCORD_WEBHOOK` и `REPORT_API_TOKEN` как secrets Cloudflare Worker; webhook не должен попадать в клиент.