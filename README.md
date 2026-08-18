# Anti-Cheat Checker

Добровольный Windows-чекер для ручной проверки игрового окружения.

## Компоненты

- `client/AntiCheat.Client` — .NET-клиент, который формирует локальный JSON-отчёт и отправляет его на relay API.
- `discord-relay` — Cloudflare Worker: принимает отчёт и публикует краткий результат в Discord.

## Что проверяет клиент

Только правила из `rules.json`: заданные процессы, совпадения по ключевым словам в именах процессов, точные директории, а также список игровых процессов. В следующих версиях в отдельные модули будут добавлены HOSTS, автозапуск, планировщик задач и сверка SHA-256 явно заданных игровых файлов.

Клиент не читает содержимое личных документов, не собирает пароли или браузерные данные и не удаляет пользовательские файлы. Совпадения по именам — повод для ручного просмотра, а не автоматическое доказательство нарушения.

## Настройка

1. В `client/AntiCheat.Client/rules.json` задайте URL Worker в `reportApiUrl` и правила.
2. В Cloudflare Worker установите секреты `DISCORD_WEBHOOK` и `REPORT_API_TOKEN`.
3. Перед запуском передайте `REPORT_API_TOKEN` через окружение; не добавляйте Discord webhook в клиент.

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

Готовые файлы находятся в `bin/Release/net8.0-windows/win-x64/publish/`.

## Деплой relay

```powershell
cd discord-relay
npx wrangler deploy
```

Результаты Discord требуют ручной оценки.
