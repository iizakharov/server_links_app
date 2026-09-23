<script lang="ts">
  import { onMount } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import { bytes } from "../lib/api";
  import { app, selectedProfile, toggleConnection } from "../lib/store.svelte";

  let now = $state(Math.floor(Date.now() / 1000));
  onMount(() => {
    const t = setInterval(() => (now = Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  });

  const profile = $derived(selectedProfile());
  const connected = $derived(!!app.status?.connected);
  const phase = $derived(app.busy ? "busy" : connected ? "on" : "off");
  const label = $derived(
    app.busy === "connecting" ? "Подключение…" : app.busy === "disconnecting" ? "Отключение…"
      : connected ? "Подключено" : "Отключено");

  function duration(since: number) {
    const s = Math.max(0, now - since);
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`;
  }
  const handshakeOld = $derived(connected && app.status!.stats.handshake > 0 && now - app.status!.stats.handshake > 180);
  const noHandshake = $derived(connected && app.status!.stats.handshake === 0 && now - app.status!.since > 10);
</script>

<section class="screen home">
  <header class="row">
    <img src="/logo.svg" alt="" width="28" height="28" />
    <h1 class="grow">АМнеЗинуVPN</h1>
  </header>

  {#if app.status?.blocked}
    <div class="card banner row">
      <div class="grow">
        <p><b>Интернет заблокирован</b></p>
        <p class="small muted">Подключение оборвалось, kill switch не выпускает трафик мимо VPN.</p>
      </div>
      <button class="btn" onclick={toggleConnection}>Снять</button>
    </div>
  {:else if app.helper.running && app.helper.outdated}
    <div class="card banner row">
      <div class="grow">
        <p><b>Доступно обновление службы</b></p>
        <p class="small muted">Новые функции заработают после обновления.</p>
      </div>
      <button class="btn primary" onclick={() => (app.tab = "settings")}>Обновить</button>
    </div>
  {/if}

  {#if !app.helper.running}
    <div class="card banner row">
      <div class="grow">
        <p><b>Служба VPN не запущена</b></p>
        <p class="small muted">Без неё приложение не может создать подключение.</p>
      </div>
      <button class="btn primary" onclick={() => (app.tab = "settings")}>Установить</button>
    </div>
  {/if}

  <div class="center">
    <button class="power {phase}" onclick={toggleConnection}
            disabled={!!app.busy || !profile || !app.helper.running}
            aria-label={connected ? "Отключить" : "Подключить"}>
      <span class="ring"></span>
      <Icon name="power" size={64} />
    </button>
    <p class="state" class:ok={connected}>{label}</p>
    {#if connected}
      <p class="muted mono">{duration(app.status!.since)}</p>
      {#if app.status!.kill_switch || app.view.settings.split.mode !== "all"}
        <p class="row modes">
          {#if app.status!.kill_switch}<span class="tag">Kill switch</span>{/if}
          {#if app.view.settings.split.mode === "only"}<span class="tag">Только выбранные сайты</span>{/if}
          {#if app.view.settings.split.mode === "except"}<span class="tag">Кроме выбранных сайтов</span>{/if}
        </p>
      {/if}
      <div class="traffic row">
        <span class="row"><Icon name="down" size={16} /> {bytes(app.status!.stats.rx)}</span>
        <span class="row"><Icon name="up" size={16} /> {bytes(app.status!.stats.tx)}</span>
      </div>
      {#if noHandshake || handshakeOld}
        <p class="small warn">Сервер не отвечает — проверьте, что ключ действующий и сервер доступен.</p>
      {/if}
    {/if}
    {#if app.error}<p class="error">{app.error}</p>{/if}
  </div>

  <button class="card server row" onclick={() => (app.tab = "servers")}>
    {#if profile}
      <span class="badge"><Icon name="shield" size={20} /></span>
      <span class="grow">
        <span class="name ellipsis">{profile.name}</span>
        <span class="small muted ellipsis">AmneziaWG {profile.awg_version} · {profile.endpoint}</span>
      </span>
    {:else}
      <span class="badge"><Icon name="plus" size={20} /></span>
      <span class="grow">
        <span class="name">Добавьте сервер</span>
        <span class="small muted">Ключ vpn:// или конфиг .conf</span>
      </span>
    {/if}
    <Icon name="chevron" size={18} />
  </button>
</section>

<style>
  .home { gap: 20px; }
  .banner { border-color: var(--accent); }
  .center { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; padding: 12px 0; }
  .power {
    position: relative; width: 184px; height: 184px; border-radius: 50%;
    display: grid; place-items: center; color: var(--muted);
    background: var(--surface); border: 1px solid var(--border);
    transition: color .3s, box-shadow .3s, background .3s;
  }
  .power:disabled { opacity: 1; cursor: default; }
  .power .ring { position: absolute; inset: -10px; border-radius: 50%; border: 3px solid var(--border); }
  .power.on { color: var(--on-accent); background: var(--accent-grad); box-shadow: var(--shadow-glow); border-color: transparent; }
  .power.on .ring { border-color: var(--accent); opacity: .5; }
  .power.busy { color: var(--accent); }
  .power.busy .ring { border-color: transparent; border-top-color: var(--accent); animation: spin 1s linear infinite; }
  .power.off:not(:disabled):hover { color: var(--text); }
  @keyframes spin { to { transform: rotate(360deg); } }
  .state { font-size: 20px; font-weight: 650; margin-top: 14px; }
  .state.ok { color: var(--accent); }
  .modes { gap: 6px; }
  .traffic { gap: 20px; color: var(--muted); font-size: 14px; }
  .traffic .row { gap: 4px; }
  .warn { color: var(--accent); text-align: center; max-width: 300px; }
  .error { text-align: center; max-width: 320px; }
  .server { width: 100%; text-align: left; }
  .server .name { display: block; font-weight: 600; }
  .server span.small { display: block; }
  .badge { width: 40px; height: 40px; border-radius: 12px; display: grid; place-items: center; background: var(--surface-2); color: var(--accent); flex: none; }
</style>
