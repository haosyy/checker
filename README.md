# Anti-Cheat Checker

Добровольный Windows-чекер для ручной проверки игрового окружения.

## Компоненты

- `client/AntiCheat.Client` — .NET-клиент: выполняет правила из `rules.json` и `indicators.json`, формирует `result.json` и отправляет отчёт relay API.
- `discord-relay` — Cloudflare Worker: принимает отчёт и публикует краткий результат в Discord.

## Проверки

- точные имена процессов и ключевые слова в именах/путях процессов;
- существование точно заданных папок;
- записи Windows Run/RunOnce;
- совпадения ключевых слов в данных Task Scheduler;
- совпадения доменов в `HOSTS`;
- имена файлов и двойные расширения в явно заданных папках;
- SHA-256 только для файлов игры, явно указанных в `expectedGameFiles`.

Программа не читает содержимое личных документов, не собирает пароли, cookies или токены браузера, не устанавливает драйверы и не удаляет пользовательские файлы. Совпадения являются основанием для ручной оценки, а не автоматическим доказательством нарушения.

## База indicators.json

`indicators.json` содержит версионируемые правила. Поддерживаемые типы:

- `process` — точное имя процесса без `.exe`;
- `directory` — точный путь к папке, допустимы `%APPDATA%` и другие переменные среды;
- `keyword` — ключевое слово для слабых совпадений в именах процессов, путях, автозапуске и именах файлов.

Пример:

```json
{
  "version": "1.0.0",
  "indicators": [
    {
      "id": "example-process",
      "type": "process",
      "value": "example_process",
      "severity": "high",
      "source": "Проверенный источник",
      "reason": "Точное правило"
    }
  ]
}
```

Не добавляйте неподтверждённые правила: совпадения по ключевым словам должны рассматриваться вручную.

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
