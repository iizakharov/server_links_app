<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import { api, pickFile, type SplitMode } from "../lib/api";
  import { app, saveSettings } from "../lib/store.svelte";
  import { mergeSplitEntries } from "../lib/split-import";

  const s = $derived(app.view.settings.split);
  let text = $state(app.view.settings.split.entries.join("\n"));
  let saved = $state(false);
  let importing = $state(false);
  let message = $state("");
  let error = $state("");

  async function importFile() {
    importing = true;
    message = "";
    error = "";
    try {
      const path = await pickFile([{ name: "Список сайтов JSON", extensions: ["json"] }]);
      if (!path) return;
      const imported = await api.splitImportFile(path);
      const merged = mergeSplitEntries(entries, imported);
      if (imported.length) text = merged.entries.join("\n");
      saved = false;
      message = `Добавлено записей: ${merged.added}.`;
    } catch (e) {
      error = String(e);
    } finally {
      importing = false;
    }
  }

  const modes: [SplitMode, string, string][] = [
    ["all", "Всё через VPN", "Раздельное туннелирование выключено"],
    ["only", "Только эти сайты", "Через VPN идут только сайты из списка, остальное — напрямую"],
    ["except", "Все, кроме этих", "Сайты из списка открываются напрямую, остальное — через VPN"],
  ];
  const entries = $derived(text.split(/[\s,]+/).map((e) => e.trim()).filter(Boolean));
  const dirty = $derived(entries.join("\n") !== s.entries.join("\n"));

  async function setMode(mode: SplitMode) {
    await saveSettings({ split: { mode, entries: s.entries }, ...(mode !== "all" ? { kill_switch: false } : {}) });
  }
  async function save() {
    error = "";
    try {
      await saveSettings({ split: { mode: s.mode, entries } });
      saved = true;
      setTimeout(() => (saved = false), 1500);
    } catch (e) {
      error = String(e);
    }
  }
</script>

<section class="screen">
  <header class="row">
    <button class="back" onclick={() => (app.tab = "settings")} aria-label="Назад"><Icon name="back" /></button>
    <h1 class="grow">Раздельное туннелирование</h1>
  </header>

  <div class="card col">
    {#each modes as [id, label, hint]}
      <button class="mode row" class:on={s.mode === id} onclick={() => setMode(id)}>
        <span class="radio" class:on={s.mode === id}>{#if s.mode === id}<Icon name="check" size={14} />{/if}</span>
        <span class="grow"><span class="label">{label}</span><span class="small muted">{hint}</span></span>
      </button>
    {/each}
  </div>

  {#if s.mode !== "all"}
    <div class="card col">
      <h2>Сайты и адреса</h2>
      <button class="btn wide" onclick={importFile} disabled={importing}>{importing ? "Импорт…" : "Импортировать JSON"}</button>
      {#if message}<p class="small muted" role="status">{message}</p>{/if}
      {#if error}<p class="small" role="alert">{error}</p>{/if}
      <textarea bind:value={text} spellcheck="false" placeholder={"youtube.com\nkinopoisk.ru\n10.0.0.0/8"}></textarea>
      <p class="small muted">По одному в строке: домен, IP-адрес или сеть. Адреса доменов определяются при подключении — сайты, которые часто меняют адреса (CDN), могут иногда идти мимо.</p>
      <button class="btn primary wide" onclick={save} disabled={!dirty || importing}>{saved ? "Сохранено" : "Сохранить"}</button>
    </div>
  {/if}
  {#if app.status?.connected}<p class="small muted">Изменения вступят в силу при следующем подключении.</p>{/if}
</section>

<style>
  .col { display: flex; flex-direction: column; gap: 10px; }
  .back { color: var(--text); padding: 4px; margin-left: -4px; }
  .mode { text-align: left; color: var(--text); padding: 6px 0; }
  .label { display: block; font-weight: 560; }
  .mode .small { display: block; }
  .radio { width: 22px; height: 22px; border-radius: 50%; border: 2px solid var(--border); display: grid; place-items: center; flex: none; }
  .radio.on { background: var(--accent-grad); border-color: transparent; color: var(--on-accent); }
  textarea { min-height: 160px; }
</style>
