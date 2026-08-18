const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=UTF-8" } });

function text(value, limit = 1024) {
  return String(value ?? "").replace(/[\r\n]+/g, " ").replace(/`/g, "'").trim().slice(0, limit);
}

function code(value, fallback = "—") {
  const safe = text(value, 160);
  return safe ? `\`${safe}\`` : fallback;
}

function statusView(status) {
  if (status === "clean") return { title: "✅ Проверка завершена", label: "Чисто", color: 0x57f287, description: "Совпадений с настроенными правилами не найдено." };
  if (status === "review") return { title: "⚠️ Проверка требует просмотра", label: "Нужна проверка", color: 0xfee75c, description: "Найдены косвенные признаки. Это не является автоматическим доказательством нарушения." };
  return { title: "🚨 Найдены подозрительные совпадения", label: "Подозрительно", color: 0xed4245, description: "Найдены совпадения с правилами. Проверьте результаты вручную перед любым решением." };
}

function findingLine(item) {
  const icon = ({ high: "🔴", medium: "🟠", low: "🟡" })[item.severity] ?? "⚪";
  const type = text(item.type, 30) || "unknown";
  const name = text(item.name, 100) || "unknown";
  const location = text(item.location, 160);
  return `${icon} **${type}** — \`${name}\`${location ? `\n> ${location}` : ""}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/report") return json({ error: "Not found" }, 404);
    if (!env.REPORT_API_TOKEN || request.headers.get("authorization") !== `Bearer ${env.REPORT_API_TOKEN}`) return json({ error: "Unauthorized" }, 401);
    if (Number(request.headers.get("content-length") || 0) > 131072) return json({ error: "Report is too large" }, 413);

    let report;
    try { report = await request.json(); } catch { return json({ error: "Expected a JSON report" }, 400); }
    if (!report || !["clean", "review", "suspicious"].includes(report.status)) return json({ error: "Invalid report" }, 400);

    const view = statusView(report.status);
    const findings = Array.isArray(report.found) ? report.found.slice(0, 8) : [];
    const findingText = findings.length ? findings.map(findingLine).join("\n") : "✅ Совпадений с правилами не найдено.";
    const scanErrors = Array.isArray(report.scan_errors) ? report.scan_errors : [];

    const fields = [
      { name: "Статус", value: `**${view.label}**`, inline: true },
      { name: "Пользователь", value: code(report.user, "Не указан"), inline: true },
      { name: "Компьютер", value: code(report.computer, "Не указан"), inline: true },
      { name: "Игра", value: report.game_running ? "🟢 Запущена" : "⚪ Не запущена", inline: true },
      { name: "Совпадений", value: String(findings.length), inline: true },
      { name: "Проверка", value: report.check_id ? code(report.check_id) : "—", inline: true },
      { name: "Найденные признаки", value: findingText.slice(0, 1024) }
    ];

    if (scanErrors.length) fields.push({ name: `⚠️ Ошибки сканирования: ${scanErrors.length}`, value: scanErrors.slice(0, 3).map(item => `• ${text(item, 250)}`).join("\n").slice(0, 1024) });

    const discordResponse = await fetch(env.DISCORD_WEBHOOK, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "Anti-Cheat", embeds: [{ title: view.title, description: view.description, color: view.color, fields, footer: { text: "Anti-Cheat • Результат требует ручной оценки" }, timestamp: typeof report.time === "string" ? report.time : new Date().toISOString() }] })
    });

    if (!discordResponse.ok) return json({ error: "Discord delivery failed", discord_status: discordResponse.status }, 502);
    return json({ delivered: true, status: report.status, findings: findings.length });
  }
};
