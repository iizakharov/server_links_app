<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import { api, errorText, inTauri, pickFile as pickNative, readClipboard } from "../lib/api";
  import { app, refreshView } from "../lib/store.svelte";

  let text = $state("");
  let name = $state("");
  let error = $state("");
  let busy = $state(false);
  let fileInput: HTMLInputElement;

  async function paste() {
    error = "";
    try { text = (await readClipboard()).trim(); } catch { text = ""; }
    // no text: maybe a screenshot of a QR code
    if (!text) {
      try { text = await api.qrFromClipboard(); } catch (e) { error = "В буфере нет ни ключа, ни QR-кода: " + errorText(e); }
    }
  }
  async function qrImage() {
    error = "";
    const path = await pickNative([{ name: "Картинка с QR-кодом", extensions: ["png", "jpg", "jpeg", "webp"] }]);
    if (!path) return;
    try { text = await api.qrFromFile(path); } catch (e) { error = errorText(e); }
  }
  async function pickFile(e: Event) {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (!f) return;
    text = await f.text();
    if (!name) name = f.name.replace(/\.(conf|txt)$/i, "");
  }
  async function add() {
    busy = true; error = "";
    try {
      await api.importText(text, name.trim() || undefined);
      await refreshView();
      text = ""; name = "";
      app.tab = "home";
    } catch (e) { error = errorText(e); } finally { busy = false; }
  }
</script>

<section class="screen">
  <header class="row">
    <button class="back" onclick={() => (app.tab = "servers")} aria-label="Назад"><Icon name="back" /></button>
    <h1 class="grow">Добавить сервер</h1>
  </header>

  <div class="card col">
    <h2>Ключ или конфиг</h2>
    <textarea bind:value={text} placeholder="vpn://… или содержимое файла .conf" spellcheck="false"></textarea>
    <div class="row">
      <button class="btn grow" onclick={paste}><Icon name="paste" size={18} /> Из буфера</button>
      <button class="btn grow" onclick={() => fileInput.click()}><Icon name="file" size={18} /> Файл .conf</button>
      <button class="btn grow" onclick={qrImage} disabled={!inTauri}><Icon name="qr" size={18} /> QR-код</button>
      <input type="file" accept=".conf,.txt,text/plain" bind:this={fileInput} onchange={pickFile} hidden />
    </div>
    <input bind:value={name} placeholder="Название (необязательно)" />
    {#if error}<p class="error">{error}</p>{/if}
    <button class="btn primary wide" onclick={add} disabled={!text.trim() || busy}>{busy ? "Проверяю…" : "Добавить"}</button>
  </div>

  <div class="card col muted small">
    <p><b class="text">Свой сервер по SSH</b></p>
    <p>Установка AmneziaWG на ваш сервер, каскады и выдача ключей — в следующей версии приложения. Пока это делает консольная утилита <span class="mono">amz</span>.</p>
  </div>
</section>

<style>
  .col { display: flex; flex-direction: column; gap: 12px; }
  .back { color: var(--text); padding: 4px; margin-left: -4px; }
  .text { color: var(--text); }
</style>
