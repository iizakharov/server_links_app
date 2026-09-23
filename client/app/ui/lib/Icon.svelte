<script lang="ts">
  // Small line icons (own drawings, 24x24 grid)
  let { name, size = 22 }: { name: string; size?: number } = $props();
  const paths: Record<string, string> = {
    power: "M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0",
    home: "M4 11l8-7 8 7v9h-5v-6H9v6H4z",
    servers: "M4 5h16v5H4zM4 14h16v5H4zM8 7.5h.01M8 16.5h.01",
    share: "M12 15V3M7 8l5-5 5 5M5 13v7h14v-7",
    settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 13a7.6 7.6 0 0 0 0-2l2-1.6-2-3.4-2.4 1a7.7 7.7 0 0 0-1.7-1L15 3.5h-4L10.7 6a7.7 7.7 0 0 0-1.7 1l-2.4-1-2 3.4 2 1.6a7.6 7.6 0 0 0 0 2l-2 1.6 2 3.4 2.4-1a7.7 7.7 0 0 0 1.7 1l.3 2.5h4l.3-2.5a7.7 7.7 0 0 0 1.7-1l2.4 1 2-3.4z",
    plus: "M12 5v14M5 12h14",
    back: "M15 5l-7 7 7 7",
    chevron: "M9 5l7 7-7 7",
    copy: "M9 9h11v11H9zM5 15H4V4h11v1",
    download: "M12 4v11M7 10l5 5 5-5M5 20h14",
    trash: "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13",
    edit: "M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4",
    check: "M5 12l5 5 9-10",
    down: "M12 5v14M6 13l6 6 6-6",
    up: "M12 19V5M6 11l6-6 6 6",
    shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
    paste: "M9 4h6v3H9zM7 5H5v16h14V5h-2",
    file: "M6 3h8l4 4v14H6zM14 3v4h4",
  };
</script>

<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
     stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  <path d={paths[name]} />
</svg>
