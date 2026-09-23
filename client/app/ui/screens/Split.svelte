<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import type { SplitMode } from "../lib/api";
  import { app, saveSettings } from "../lib/store.svelte";

  const s = $derived(app.view.settings.split);
  let text = $state(app.view.settings.split.entries.join("\n"));
  let saved = $state(false);

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
    await saveSettings({ split: { mode: s.mode, entries } });
    saved = true;
    setTimeout(() => (saved = false), 1500);
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
      <textarea bind:value={text} spellcheck="false" placeholder={"youtube.com\nkinopoisk.ru\n10.0.0.0/8"}></textarea>
      <p class="small muted">По одному в строке: домен, IP-адрес или сеть. Адреса доменов определяются при подключении — сайты, которые часто меняют адреса (CDN), могут иногда идти мимо.</p>
      <button class="btn primary wide" onclick={save} disabled={!dirty}>{saved ? "Сохранено" : "Сохранить"}</button>
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
