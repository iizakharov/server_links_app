<script lang="ts">
  import { onMount } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import { bytes } from "../lib/api";
  import { app, installUpdate, selectedProfile, switchExit, toggleConnection } from "../lib/store.svelte";

  let now = $state(Math.floor(Date.now() / 1000));
  onMount(() => {
    const t = setInterval(() => (now = Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  });

  const profile = $derived(selectedProfile());
  const exits = $derived(profile?.group ? app.view.profiles.filter((p) => p.group === profile.group) : []);
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
    <h1 class="grow">AMneZinu</h1>
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

  {#if app.update?.version}
    <div class="card banner row">
      <div class="grow">
        <p><b>Доступна версия {app.update.version}</b></p>
        <p class="small muted">{app.updating === "installing" ? `Загрузка… ${app.updateProgress}` : app.updateError || "Приложение перезапустится, VPN не прервётся."}</p>
      </div>
      <button class="btn primary" disabled={!!app.updating} onclick={installUpdate}>Обновить</button>
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
            aria-label={connected ? "Отключить" : "Подключить"}
            aria-pressed={connected} aria-busy={!!app.busy}>
      <img class="bust bust-off" src="/vpn-button-off.webp" alt="" draggable="false" />
      <img class="bust bust-on" src="/vpn-button-on.webp" alt="" draggable="false" />
      <span class="activity" aria-hidden="true"></span>
    </button>
    <p class="state" class:ok={connected} role="status">{label}</p>
    <!-- fixed height, so the button doesn't move when these lines appear -->
    <div class="details">
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
    </div>
    {#if app.error}<p class="error">{app.error}</p>{/if}
  </div>

  <button class="card server row" onclick={() => (app.tab = "servers")}>
    {#if profile}
      <span class="badge"><Icon name="shield" size={20} /></span>
      <span class="grow">
        <span class="name ellipsis">{profile.name}</span>
        <span class="small muted ellipsis">{profile.exit ? `Выход: ${profile.exit} · ` : ""}AmneziaWG {profile.awg_version}</span>
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

  {#if exits.length > 1}
    <div class="exits">
      <p class="small muted">Выход в интернет</p>
      <div class="segmented">
        {#each exits as x (x.id)}
          <button class:on={x.id === profile?.id} disabled={!!app.busy} onclick={() => x.id !== profile?.id && switchExit(x.id)}>{x.exit}</button>
        {/each}
      </div>
    </div>
  {/if}
</section>

<style>
  .home { gap: 20px; }
  .exits { display: flex; flex-direction: column; gap: 6px; margin-top: -8px; }
  .banner { border-color: var(--accent); }
  .center { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; padding: 12px 0; }
  .power {
    position: relative; width: clamp(144px, 24vh, 192px); aspect-ratio: 4 / 5;
    flex: none; padding: 0; border-radius: 24px; background: transparent;
    -webkit-tap-highlight-color: transparent;
    transition: transform .18s ease, filter .25s ease;
  }
  .power:disabled { opacity: .5; cursor: default; }
  .power.busy:disabled { opacity: 1; }
  .power:focus-visible { outline: 3px solid var(--accent); outline-offset: 5px; }
  .power:not(:disabled):hover { filter: brightness(1.12); }
  .power:not(:disabled):active { transform: translateY(3px) scale(.96); }
  .bust { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: contain; pointer-events: none; transition: opacity .4s ease; }
  .bust-on { opacity: 0; }
  .power.on .bust-off { opacity: 0; }
  .power.on .bust-on { opacity: 1; }
  .power.busy .bust-on { animation: pulse 1.2s ease-in-out infinite; }
  .activity { position: absolute; left: calc(50% - 9px); bottom: -8px; width: 18px; height: 18px; border: 2px solid transparent; border-radius: 50%; opacity: 0; }
  .power.busy .activity { opacity: 1; border-color: var(--border); border-top-color: var(--accent); animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes pulse { 0%, 100% { opacity: .2; } 50% { opacity: .85; } }
  @media (prefers-reduced-motion: reduce) {
    .power, .bust { transition: none; }
    .power.busy .bust-on { animation: none; opacity: .5; }
    .power.busy .activity { animation: none; }
    .power:not(:disabled):active { transform: none; }
  }
  .details { height: 132px; display: flex; flex-direction: column; align-items: center; gap: 10px; text-align: center; }
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
