<template>
  <!-- This example requires Tailwind CSS v2.0+ -->
  <div class="py-6 flex items-center justify-between">
    <div class="flex-1 flex items-center sm:justify-between justify-end">
      <div class="hidden sm:block">
        <p class="text-sm text-white">
          Showing
          <span class="font-medium">{{ (currentPage * pageSize) - pageSize }}</span>
          to
          <span class="font-medium">{{ Math.min(currentPage * pageSize, totalResults) }}</span>
          of
          <span class="font-medium">{{ totalResults }}</span>
          results
        </p>
      </div>
      <div>
        <nav class="relative z-0 inline-flex -space-x-px" aria-label="Pagination">
          <a @click="goToFirstPage"
             class="page-button rounded-l-lg">
            <span class="sr-only">Previous</span>
            <!-- Heroicon name: solid/chevron-double-left -->
            <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
              <path fill-rule="evenodd"
                    d="M15.707 15.707a1 1 0 01-1.414 0l-5-5a1 1 0 010-1.414l5-5a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 010 1.414zm-6 0a1 1 0 01-1.414 0l-5-5a1 1 0 010-1.414l5-5a1 1 0 011.414 1.414L5.414 10l4.293 4.293a1 1 0 010 1.414z"
                    clip-rule="evenodd"></path>
            </svg>
          </a>
          <button
              @click="goToPrevPage"
              class="page-button">
            <span class="sr-only">Previous</span>
            <!-- Heroicon name: solid/chevron-left -->
            <svg class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"
                 aria-hidden="true">
              <path fill-rule="evenodd"
                    d="M12.707 5.293a1 1 0 010 1.414L9.414 10l3.293 3.293a1 1 0 01-1.414 1.414l-4-4a1 1 0 010-1.414l4-4a1 1 0 011.414 0z"
                    clip-rule="evenodd"/>
            </svg>
          </button>

          <button @click="goToFirstPage"
              class="page-button"
              :disabled="currentPage === 1">
            1
          </button>

          <template v-if="totalPages < 7">
            <button v-for="i in Math.max(totalPages - 2,0)" :key="i"
                  @click="goToPage(i + 1)"
                  :disabled="i + 1 === currentPage"
                  class="page-button">
                  {{ i + 1 }}
            </button>
          </template>

          <template v-else-if="currentPage <= 4">
            <button v-for="i in 5" :key="i + 1"
                  @click="goToPage(i + 1)"
                  :disabled="i + 1 === currentPage"
                  class="page-button">
                  {{ i + 1 }}
            </button>
            <span v-if="totalPages > 7"
                class="page-button">
              ...
            </span>
          </template>

          <template v-else-if="currentPage > totalPages - 4">
            <span v-if="totalPages > 7"
              class="page-button">
              ...
            </span>
            <button v-for="i in 5" :key="totalPages - 6 + i"
                  @click="goToPage(totalPages - 6 + i)"
                  :disabled="totalPages - 6 + i === currentPage"
                  class="page-button">
                  {{ totalPages - 6 + i }}
            </button>
          </template>

          <template v-else>
            <span class="page-button">
              ...
            </span>
            <button v-for="i in 2" :key="currentPage - 3 + i"
                    @click="goToPage(currentPage - 3 + i)"
                    class="page-button">
              {{ currentPage - 3 + i }}
            </button>
            <button disabled
                class="page-button">
              {{ currentPage }}
            </button>
            <button v-for="i in 2" :key="currentPage + i"
                    @click="goToPage(currentPage + i)"
                    class="page-button">
              {{ currentPage + i }}
            </button>
            <span class="page-button">
              ...
            </span>
          </template>

          <button v-if="totalPages > 1"
              @click="goToLastPage"
              :disabled="totalPages === currentPage"
              class="page-button">
            {{ totalPages }}
          </button>

          <button
              @click="goToNextPage()"
              class="page-button">
            <span class="sr-only">Next</span>
            <!-- Heroicon name: solid/chevron-right -->
            <svg class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"
                 aria-hidden="true">
              <path fill-rule="evenodd"
                    d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z"
                    clip-rule="evenodd"/>
            </svg>
          </button>
          <button
              @click="goToLastPage"
              class="page-button rounded-r-lg">
            <span class="sr-only">Next</span>
            <!-- Heroicon name: solid/chevron-double-right -->
            <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
              <path fill-rule="evenodd"
                    d="M10.293 15.707a1 1 0 010-1.414L14.586 10l-4.293-4.293a1 1 0 111.414-1.414l5 5a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0z"
                    clip-rule="evenodd"></path>
              <path fill-rule="evenodd"
                    d="M4.293 15.707a1 1 0 010-1.414L8.586 10 4.293 5.707a1 1 0 011.414-1.414l5 5a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0z"
                    clip-rule="evenodd"></path>
            </svg>
          </button>
        </nav>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "Pagination",
  props: {
    currentPage: {
      default: 1,
      required: true,
    },
    pageSize: {
      default: 20,
      required: true,
    },
    totalPages: {
      default: 10,
      required: true
    },
    totalResults: {
      default: 0,
      required: true
    },
  },
  methods: {
    goToFirstPage() {
      this.goToPage(1);
    },
    goToLastPage() {
      this.goToPage(this.totalPages);
    },
    goToPrevPage() {
      this.goToPage(this.currentPage-1);
    },
    goToNextPage() {
      this.goToPage(this.currentPage+1);
    },
    goToPage(pageNum) {
      if(pageNum > this.totalPages || pageNum < 1) {
        return;
      }

      this.$emit('update:currentPage', pageNum);
    },
  }
}
</script>

<style scoped>

.page-button {
  @apply relative inline-flex items-center px-4 py-2 text-sm font-medium text-white hover:text-white outline-none;
}

.page-button[disabled] {
  @apply text-sky-500;
}
</style>
