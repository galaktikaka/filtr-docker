const healthBadge = document.getElementById("healthBadge");
const scanForm = document.getElementById("scanForm");
const imageInput = document.getElementById("imageInput");
const scanButton = document.getElementById("scanButton");
const historyBody = document.getElementById("historyBody");
const details = document.getElementById("details");

const kpiTotal = document.getElementById("kpiTotal");
const kpiFailed = document.getElementById("kpiFailed");
const kpiCritical = document.getElementById("kpiCritical");
const kpiWarning = document.getElementById("kpiWarning");

let state = {
  items: [],
};

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "-";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function formatDate(iso) {
  if (!iso) return "-";
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return iso;
  return dt.toLocaleString("ru-RU");
}

function renderKpi(items) {
  const total = items.length;
  const failed = items.filter((x) => x.status !== "PASSED").length;
  const critical = items.reduce((acc, x) => acc + Number(x.critical_count || 0), 0);
  const warning = items.reduce((acc, x) => acc + Number(x.warning_count || 0), 0);
  kpiTotal.textContent = String(total);
  kpiFailed.textContent = String(failed);
  kpiCritical.textContent = String(critical);
  kpiWarning.textContent = String(warning);
}

function renderHistory(items) {
  if (!items.length) {
    historyBody.innerHTML =
      '<tr><td colspan="7" class="empty">История пока пустая</td></tr>';
    return;
  }

  historyBody.innerHTML = items
    .map(
      (item) => `
      <tr>
        <td>${formatDate(item.started_at)}</td>
        <td><code>${escapeHtml(item.image)}</code></td>
        <td><span class="status ${item.status}">${item.status}</span></td>
        <td>${item.critical_count ?? 0}</td>
        <td>${item.warning_count ?? 0}</td>
        <td>${formatDuration(item.duration_ms)}</td>
        <td><button data-scan-id="${item.id}" class="details-btn">Открыть</button></td>
      </tr>
    `
    )
    .join("");
}

function renderDetails(item) {
  const findings = Array.isArray(item.findings) ? item.findings : [];
  const remediation = item.remediation || {};
  const dutyPhrases = Array.isArray(remediation.duty_phrases)
    ? remediation.duty_phrases
    : [];

  const findingsHtml = findings.length
    ? findings
        .map(
          (f) => {
            const lineInfo =
              Number.isInteger(f.line_no) && f.line_no > 0
                ? `Строка: ${escapeHtml(f.line_no)}`
                : "Строка: н/д (срабатывание по имени/пути файла)";
            return `
      <article class="finding ${escapeHtml(f.level)}">
        <strong>[${escapeHtml(f.level)}] ${escapeHtml(f.path)}${
            f.line_no ? `:${escapeHtml(f.line_no)}` : ""
          }</strong><br/>
        <span>${escapeHtml(f.message)}</span>
        <div class="line-meta">${lineInfo}</div>
        ${
          f.snippet
            ? `<pre class="line-snippet">${escapeHtml(f.snippet)}</pre>`
            : ""
        }
      </article>
    `;
          }
        )
        .join("")
    : '<p class="empty">Нарушений нет.</p>';

  const dutyHtml = dutyPhrases.length
    ? `<ul>${dutyPhrases.map((p) => `<li>${escapeHtml(p)}</li>`).join("")}</ul>`
    : "<p class='empty'>Рекомендации отсутствуют.</p>";

  details.innerHTML = `
    <h3>${escapeHtml(item.image)} <span class="status ${item.status}">${item.status}</span></h3>
    <p>
      Exit code: <code>${item.exit_code}</code>,
      Critical: <code>${item.critical_count}</code>,
      Warning: <code>${item.warning_count}</code>,
      Длительность: <code>${formatDuration(item.duration_ms)}</code>
    </p>
    <h4>Findings</h4>
    <div class="findings">${findingsHtml}</div>
    <h4>Рекомендации</h4>
    ${dutyHtml}
    <h4>stdout / stderr</h4>
    <pre>${escapeHtml((item.stdout || "") + "\n" + (item.stderr || ""))}</pre>
  `;
}

async function refreshHealth() {
  try {
    const res = await fetch("/api/health");
    const data = await res.json();
    if (data.scan_running) {
      healthBadge.textContent = "Идёт сканирование...";
      scanButton.disabled = true;
    } else {
      healthBadge.textContent = "Сервер активен";
      scanButton.disabled = false;
    }
  } catch (err) {
    healthBadge.textContent = "Сервер недоступен";
    scanButton.disabled = true;
  }
}

async function refreshHistory() {
  const res = await fetch("/api/scans");
  const data = await res.json();
  state.items = Array.isArray(data.items) ? data.items : [];
  renderKpi(state.items);
  renderHistory(state.items);
}

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const image = imageInput.value.trim();
  if (!image) return;

  scanButton.disabled = true;
  scanButton.textContent = "Запуск...";

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ image }),
    });
    const data = await res.json();
    if (!res.ok) {
      alert(data.error || "Не удалось запустить скан");
      return;
    }
    await refreshHistory();
    if (data.item) {
      renderDetails(data.item);
    }
  } catch (err) {
    alert("Ошибка сети при запуске скана");
  } finally {
    scanButton.textContent = "Запустить проверку";
    await refreshHealth();
  }
});

historyBody.addEventListener("click", async (event) => {
  const target = event.target;
  if (!target || !target.matches(".details-btn")) return;
  const scanId = target.getAttribute("data-scan-id");
  if (!scanId) return;

  const res = await fetch(`/api/scans/${scanId}`);
  const data = await res.json();
  if (res.ok && data.item) {
    renderDetails(data.item);
  }
});

async function init() {
  await refreshHealth();
  await refreshHistory();
}

setInterval(refreshHealth, 3000);
setInterval(refreshHistory, 8000);
init();
