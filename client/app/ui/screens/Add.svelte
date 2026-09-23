<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import { onMount } from "svelte";
  import { api, errorText, inTauri, isWindows, manage, onManageLog, pickFile as pickNative, readClipboard, secretStore } from "../lib/api";
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
  // your own server over SSH
  let own = $state({ host: "", user: "root", password: "", ssh_port: 22, instance: "v3", device: isWindows ? "Этот ПК" : "Этот Mac" });
  let ownLog = $state<string[]>([]);
  let ownBusy = $state(false);
  let ownError = $state("");
  onMount(() => {
    let stop = () => {};
    onManageLog((line) => { if (ownBusy) ownLog.push(line); }).then((s) => (stop = s));
    return () => stop();
  });
  async function setupOwn() {
    ownBusy = true; ownError = ""; ownLog = [];
    try {
      app.view = await manage.setupOwn({ id: null, name: "", host: own.host.trim(), ssh_port: Number(own.ssh_port) || 22,
                                          user: own.user, password: own.password, key_path: "" }, own.instance, own.device);
      own.password = "";
      app.tab = "home";
    } catch (e) { ownError = errorText(e); } finally { ownBusy = false; }
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
      <button class="btn grow" onclick={paste}><Icon name="paste" size={18} /> Вставить</button>
      <button class="btn grow" onclick={() => fileInput.click()}><Icon name="file" size={18} /> Файл</button>
      <button class="btn grow" onclick={qrImage} disabled={!inTauri}><Icon name="qr" size={18} /> QR-код</button>
      <input type="file" accept=".conf,.txt,text/plain" bind:this={fileInput} onchange={pickFile} hidden />
    </div>
    <input bind:value={name} placeholder="Название (необязательно)" />
    {#if error}<p class="error">{error}</p>{/if}
    <button class="btn primary wide" onclick={add} disabled={!text.trim() || busy}>{busy ? "Проверяю…" : "Добавить"}</button>
  </div>

  <div class="card col">
    <h2>Свой сервер по SSH</h2>
    <p class="small muted">Приложение поставит AmneziaWG на ваш VPS (Ubuntu / Debian), выпустит ключ для этого устройства и добавит подключение. Уже установленный AmneziaWG и его клиенты не затрагиваются.</p>
    <input bind:value={own.host} placeholder="IP-адрес или имя сервера" autocomplete="off" spellcheck="false" />
    <div class="row">
      <input class="grow" bind:value={own.user} placeholder="Пользователь" autocomplete="off" />
      <input class="port" type="number" bind:value={own.ssh_port} placeholder="Порт" />
    </div>
    <input type="password" bind:value={own.password} placeholder="Пароль (или пусто — ключ из ~/.ssh)" autocomplete="off" />
    <div class="segmented">
      {#each [["v3", "AWG 3.x"], ["v2", "2.0"], ["legacy", "1.0"]] as [id, label]}
        <button class:on={own.instance === id} onclick={() => (own.instance = id)}>{label}</button>
      {/each}
    </div>
    <input bind:value={own.device} placeholder="Имя этого устройства в списке клиентов" />
    {#if ownLog.length}<pre class="log small">{ownLog.join("\n")}</pre>{/if}
    {#if ownError}<p class="error">{ownError}</p>{/if}
    <button class="btn primary wide" onclick={setupOwn} disabled={!own.host.trim() || ownBusy || !inTauri}>
      {ownBusy ? "Установка… (несколько минут)" : "Установить и подключить"}
    </button>
    <p class="small muted">Сервер появится во вкладке «Управление»: там можно выдать ключи другим людям и следить за трафиком. Пароль хранится в {secretStore}.</p>
  </div>
</section>

<style>
  .col { display: flex; flex-direction: column; gap: 12px; }
  .back { color: var(--text); padding: 4px; margin-left: -4px; }
  .port { width: 88px; }
  .row .btn { white-space: nowrap; }
  .log { max-height: 160px; overflow: auto; white-space: pre-wrap; background: var(--surface-2); border-radius: 10px; padding: 8px 10px; margin: 0; }
</style>
