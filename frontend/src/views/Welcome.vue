<template>
  <div class="text-slate-500">
    <h1 class="view-title text-white">Welcome to {{ $store.state.settings.website.name }}</h1>

    <p class="py-2 text-white">Safely download Ren'Py games, FAST.</p>
    If you're new here, welcome! Here's a crash course.<br>
    <u><a href="https://rpdl.net/docs/what-is-bittorrrent/" target="_blank">What is bittorrent</a></u>?<br>
    <u><a href="https://rpdl.net/docs/using-our-torrents/" target="_blank">How to use our torrents</a></u>.<br>
    <u><a href="https://rpdl.net/docs/best-practices/" target="_blank">Best practices</a></u> and <u><a href="https://rpdl.net/docs/recommended-clients/" target="_blank">Recommended torrent clients</a></u>.<br>
    Here's our <u><a href="https://rpdl.net/docs/faq/" target="_blank">FAQ</a></u> and if you've questions or feedback, or just wanna chat - join <u><a href="https://rpdl.net/discord" target="_blank">our Discord</a></u>!
  </div>
</template>

<script>

export default {
  name: "Welcome"
}
</script>

<style scoped>
.category-tile {
  @apply bg-cover !important;
  @apply w-full rounded-3xl shadow-lg text-center py-16 relative;
}

.details {
  @apply inline-flex;
}
</style>
