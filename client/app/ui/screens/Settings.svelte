<script lang="ts">
  import { onMount } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import Toggle from "../lib/Toggle.svelte";
  import { api, autostart, errorText, inTauri, isWindows, secretStore } from "../lib/api";
  import { app, checkUpdate, installUpdate, saveSettings } from "../lib/store.svelte";

  let busy = $state(false);
  let error = $state("");
  let atLogin = $state(false);
  const s = $derived(app.view.settings);
  const connected = $derived(!!app.status?.connected);

  onMount(() => { autostart().then((v) => (atLogin = v)).catch(() => {}); });

  async function helper(action: "install" | "uninstall") {
    busy = true; error = "";
    try {
      app.helper = action === "install" ? await api.installHelper() : await api.uninstallHelper();
    } catch (e) { error = errorText(e); } finally { busy = false; }
  }
  async function setAtLogin(v: boolean) {
    try { atLogin = await autostart(v); } catch (e) { error = errorText(e); }
  }
  const splitLabel = $derived(
    s.split.mode === "all" ? "Выключено" : `${s.split.mode === "only" ? "Только" : "Кроме"}: ${s.split.entries.length} сайт(ов)`);
  const helperText = $derived(
    !app.helper.running ? (app.helper.installed ? "Установлена, но не отвечает" : "Не установлена")
      : app.helper.outdated ? "Работает, есть обновление" : "Работает");
</script>

<section class="screen">
  <h1>Настройки</h1>

  <div class="card col">
    <h2>Подключение</h2>
    <Toggle checked={s.kill_switch} label="Kill switch" disabled={s.split.mode !== "all"}
            hint={s.split.mode !== "all" ? "Недоступно при раздельном туннелировании" : "Блокировать интернет, если VPN отключится сам"}
            onchange={(v) => saveSettings({ kill_switch: v })} />
    {#if s.kill_switch && s.split.mode === "all"}
      <Toggle checked={s.allow_lan} label="Разрешить локальную сеть" hint="Принтеры, роутер, NAS доступны при kill switch"
              onchange={(v) => saveSettings({ allow_lan: v })} />
    {/if}
    <Toggle checked={s.autoconnect} label="Подключаться при запуске" hint="К выбранному серверу"
            onchange={(v) => saveSettings({ autoconnect: v })} />
    <Toggle checked={atLogin} label="Запускать при входе в систему" hint={isWindows ? "Приложение стартует в области уведомлений" : "Приложение стартует в строке меню"}
            disabled={!inTauri} onchange={setAtLogin} />
    <button class="link row" onclick={() => (app.tab = "split")}>
      <span class="grow"><span class="label">Раздельное туннелирование</span><span class="small muted">{splitLabel}</span></span>
      <Icon name="chevron" size={18} />
    </button>
    {#if connected}<p class="small muted">Изменения вступят в силу при следующем подключении.</p>{/if}
  </div>

  <div class="card col">
    <h2>Служба VPN</h2>
    <div class="row">
      <span class="dot" class:ok={app.helper.running && !app.helper.outdated} class:warn={app.helper.outdated}></span>
      <p class="grow">{helperText}</p>
    </div>
    <p class="small muted">Служба создаёт сетевой интерфейс, маршруты и DNS — для этого нужны права администратора. {isWindows ? "Windows попросит подтверждение." : "Пароль спросит macOS."}</p>
    <div class="row">
      <button class="btn primary grow" disabled={busy || connected} onclick={() => helper("install")}>
        {busy ? "Подождите…" : !app.helper.installed ? "Установить службу" : app.helper.outdated ? "Обновить службу" : "Переустановить"}
      </button>
      {#if app.helper.installed}
        <button class="btn danger" disabled={busy || connected} onclick={() => helper("uninstall")}>Удалить</button>
      {/if}
    </div>
    {#if connected}<p class="small muted">Чтобы обновить или удалить службу, сначала отключитесь.</p>{/if}
    {#if error}<p class="error">{error}</p>{/if}
  </div>

  <div class="card col">
    <h2>Обновления</h2>
    <p class="grow">
      {#if app.update?.version}Доступна версия {app.update.version} (сейчас {app.update.current})
      {:else if app.update}Установлена последняя версия {app.update.current}
      {:else}Новые версии проверяются при запуске и раз в 6 часов{/if}
    </p>
    {#if app.update?.notes}<p class="small muted notes">{app.update.notes}</p>{/if}
    {#if app.update?.version}
      <button class="btn primary" disabled={!!app.updating} onclick={installUpdate}>
        {app.updating === "installing" ? `Загрузка… ${app.updateProgress}` : "Обновить и перезапустить"}
      </button>
    {:else}
      <button class="btn" disabled={!!app.updating || !inTauri} onclick={() => checkUpdate(true)}>
        {app.updating === "checking" ? "Проверяю…" : "Проверить обновления"}
      </button>
    {/if}
    {#if app.updateError}<p class="error">{app.updateError}</p>{/if}
  </div>

  <div class="card col">
    <h2>Оформление</h2>
    <div class="segmented">
      {#each [["system", "Авто"], ["dark", "Тёмное"], ["light", "Светлое"]] as [id, label]}
        <button class:on={s.theme === id} onclick={() => saveSettings({ theme: id })}>{label}</button>
      {/each}
    </div>
  </div>

  <div class="card col small">
    <h2>О приложении</h2>
    <p>AMneZinu {app.update?.current ?? "0.1.5"}{inTauri ? "" : " (просмотр в браузере)"}</p>
    <p class="muted">Совместимо с серверами AmneziaWG 1.0, 2.0 и 3.x и ключами vpn:// из AmneziaVPN. Туннель — amneziawg-go 3.1.20260828 (MIT). Ключи хранятся в {secretStore}.</p>
  </div>
</section>

<style>
  .notes { white-space: pre-line; max-height: 8em; overflow: auto; }
  .col { display: flex; flex-direction: column; gap: 14px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--danger); flex: none; }
  .dot.ok { background: var(--ok); }
  .dot.warn { background: var(--accent); }
  .link { text-align: left; color: var(--text); padding: 0; }
  .label { display: block; font-weight: 560; }
  .link .small { display: block; margin-top: 2px; }
</style>
