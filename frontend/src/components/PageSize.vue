<template>
  <div class="relative inline-block text-left" v-click-outside="() => (dropdownOpened = false)">
    <button class="filter relative" @click="dropdownOpened = !dropdownOpened">
      <AdjustmentsIcon size="16" class="mr-1 opacity-50" />
      Page Size
    </button>
    <div class="origin-top-left absolute left-0 mt-2 z-10" :class="{hidden: !dropdownOpened}">
      <div class="py-2 px-2 w-48 flex flex-col bg-cod-gray-900 text-sm rounded-md shadow-lg">
        <ul v-if="$route.name === 'Browse Torrents'" id="category-filters" class="">
          <li v-for="size in pageSizes"
              @click="updateSize(size)"
              class="cursor-pointer text-white hover:text-white"
              :key="size">
            <span class="">{{ size }}</span>
          </li>
        </ul>
      </div>
    </div>
  </div>
</template>

<script>
import {UserIcon} from "@vue-hero-icons/outline";
import { AdjustmentsIcon } from '@vue-hero-icons/solid'
import {mapState} from "vuex";

export default {
  name: "ChangePageSize",
  components: {UserIcon, AdjustmentsIcon},
  props: {
      updatePageSize: Function
  },
  data: () => ({
    dropdownOpened: false,
    pageSizes: [25,50,100,200]
  }),
  computed: {
    ...mapState({
      user: state => state.auth.user
    })
  },
  methods: {
      updateSize(size) {
          this.updatePageSize(size);
          this.dropdownOpened = false;
      }
  }
}
</script>

<style scoped>
.filter {
  @apply px-3 py-1.5 text-white text-sm border border-slate-800 rounded-md flex items-center relative cursor-pointer transition duration-200 hover:text-white hover:border-slate-200;
}

.regular-checkbox {
  @apply text-sky-400;
  -webkit-appearance: none;
  background-color: rgba(0, 0, 0, .1);
  border: none;
  box-shadow: 0 1px 2px rgba(0,0,0,0.05), inset 0px -15px 10px -12px rgba(0,0,0,0.05);
  padding: 9px;
  border-radius: 3px;
  display: inline-block;
  position: relative;
}

#category-filters li {
  @apply px-2 py-1 flex flex-row justify-between;
}

#category-filters li input {
  @apply text-left
}
</style>
