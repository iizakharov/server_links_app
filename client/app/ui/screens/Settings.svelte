<script lang="ts">
  import { api, errorText, inTauri } from "../lib/api";
  import { app, refreshView } from "../lib/store.svelte";

  let busy = $state(false);
  let error = $state("");

  async function helper(action: "install" | "uninstall") {
    busy = true; error = "";
    try {
      app.helper = action === "install" ? await api.installHelper() : await api.uninstallHelper();
    } catch (e) { error = errorText(e); } finally { busy = false; }
  }
  async function theme(t: string) {
    await api.setTheme(t);
    await refreshView();
  }
</script>

<section class="screen">
  <h1>Настройки</h1>

  <div class="card col">
    <h2>Служба VPN</h2>
    <div class="row">
      <span class="dot" class:ok={app.helper.running}></span>
      <p class="grow">{app.helper.running ? "Работает" : app.helper.installed ? "Установлена, но не отвечает" : "Не установлена"}</p>
    </div>
    <p class="small muted">Служба создаёт сетевой интерфейс, маршруты и DNS — для этого нужны права администратора. Пароль спросит macOS.</p>
    <div class="row">
      <button class="btn primary grow" disabled={busy} onclick={() => helper("install")}>
        {busy ? "Подождите…" : app.helper.installed ? "Переустановить" : "Установить службу"}
      </button>
      {#if app.helper.installed}
        <button class="btn danger" disabled={busy || !!app.status?.connected} onclick={() => helper("uninstall")}>Удалить</button>
      {/if}
    </div>
    {#if error}<p class="error">{error}</p>{/if}
  </div>

  <div class="card col">
    <h2>Оформление</h2>
    <div class="segmented">
      {#each [["system", "Авто"], ["dark", "Тёмное"], ["light", "Светлое"]] as [id, label]}
        <button class:on={app.view.settings.theme === id} onclick={() => theme(id)}>{label}</button>
      {/each}
    </div>
  </div>

  <div class="card col small">
    <h2>О приложении</h2>
    <p>АМнеЗинуVPN 0.1.0{inTauri ? "" : " (просмотр в браузере)"}</p>
    <p class="muted">Совместимо с серверами AmneziaWG 1.0, 2.0 и 3.x и ключами vpn:// из AmneziaVPN. Туннель — amneziawg-go 3.1.20260828 (MIT).</p>
  </div>
</section>

<style>
  .col { display: flex; flex-direction: column; gap: 12px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--danger); flex: none; }
  .dot.ok { background: var(--ok); }
</style>
