<template>
  <div class="mt-10">
    <div v-if="search" class="mb-2 flex flex-row">
      <h2 class="text-white">Search results for '{{ this.search }}'</h2>
      <button @click="clearSearch" class="px-2 py-1 ml-2 text-sm rounded-md bg-red-500 bg-opacity-10 text-red-400 hover:text-red-500 transition duration-200">Clear search</button>
    </div>
    <div class="flex flex-row">
      <FilterCategory />
      <ChangePageSize :update-page-size="updatePageSize" />
    </div>

    <TorrentList id="TorrentList" class="mt-4" v-if="torrents.results.length > 0" :torrents="torrents.results" :sorting="sorting" :update-sorting="updateSorting"/>
    <Pagination v-if="torrents.results.length > 0" :current-page.sync="currentPage" :total-pages="totalPages" :total-results="torrents.total" :page-size="pageSize" />
    <div v-else class="py-6 text-white">This category has no results.</div>
  </div>
</template>

<script>
import TorrentList from "../components/TorrentList.vue";
import Pagination from "../components/Pagination.vue";
import HttpService from "@/common/http-service";
import {mapState} from "vuex";
import Breadcrumb from "../components/Breadcrumb.vue";
import { AdjustmentsIcon, FilterIcon } from "@vue-hero-icons/outline";
import FilterCategory from "../components/FilterCategory.vue";
import ChangePageSize from "../components/PageSize.vue";

export default {
  name: "Torrents",
  components: {FilterCategory, Pagination, TorrentList, Breadcrumb, AdjustmentsIcon, FilterIcon, ChangePageSize},
  data: () => ({
    sorting: {
      name: 'uploaded',
      direction: 'DESC',
    },
    search: '',
    torrents: {
      total: 0,
      results: []
    },
    currentPage: 1,
    pageSize: 50,
  }),
  methods: {
    loadTorrents(page) {
      HttpService.get(`/torrents?page_size=${this.pageSize}&page=${page-1}&sort=${this.sorting.name}_${this.sorting.direction}&categories=${this.categoryFilters.join(',')}&search=${this.search.replaceAll(/[\s\'\"]/g, "")}`, (res) => {
        this.torrents = res.data.data;
      }).catch(() => {
      });
    },
    updateSortFromRoute() {
      if (this.$route.params.sorting) {
        let sort = this.$route.params.sorting;
        switch (sort) {
          case 'popular':
            this.sorting.name = 'seeders';
            this.sorting.direction = 'DESC';
            break;
          case 'recent':
            this.sorting.name = 'uploaded';
            this.sorting.direction = 'DESC';
            break;
          default:
            this.sorting.name = sort;
        }
      }
    },
    clearSearch() {
      this.$router.replace({ query: {...this.$route.query, search: ''}})
    },
    updateSorting(sorting) {
      this.sorting = sorting;
      this.loadTorrents(this.currentPage);
    },
    updatePageSize(pageSize) {
      this.currentPage = Math.floor((this.currentPage - 1) * this.pageSize / pageSize) + 1;
      this.pageSize = pageSize;
      this.loadTorrents(this.currentPage);
    },
  },
  computed: {
    ...mapState(['categoryFilters']),
    totalPages() {
      return Math.ceil(this.torrents.total / this.pageSize);
    },
  },
  watch: {
    '$route.query.search': function (search) {
      search ? this.search = search : this.search = '';
      this.currentPage = 1;
      this.loadTorrents(this.currentPage, this.sorting);
    },
    '$route.params.sorting': function () {
      this.updateSortFromRoute();
      this.loadTorrents(this.currentPage, this.sorting);
    },
    filters() {
      this.loadTorrents(this.currentPage, this.sorting);
    },
    currentPage(newPage) {
      this.loadTorrents(newPage, this.sorting);
      document.getElementById("TorrentList").scrollIntoView({behavior: "smooth"});
    },
    categoryFilters() {
      this.currentPage = 1;
      this.loadTorrents(this.currentPage, this.sorting);
    }
  },
  mounted() {
    this.$route.query.search ? this.search = this.$route.query.search : this.search = '';
    this.updateSortFromRoute();
    this.loadTorrents(this.currentPage, this.sorting);
  }
}
</script>

<style scoped>
.filter {
  @apply px-3 py-1.5 text-white text-sm font-semibold border border-slate-800 rounded-md flex items-center relative cursor-pointer transition duration-200 hover:text-white hover:border-slate-200;
}
</style>
