module.exports = {
  content: ["./index.html", "./src/App.vue", "./src/**/*.{vue,js,ts,jsx,tsx}", "./src/**/**/*.{vue,js,ts,jsx,tsx}"],
  theme: {
    fontFamily: {
      display: ['Inter', 'system-ui', 'sans-serif'],
      body: ['Inter', 'system-ui', 'sans-serif'],
    },
    extend: {
      colors: {
        'cod-gray': {
          '50': '#f6f6f6',
          '100': '#e7e7e7',
          '200': '#d1d1d1',
          '300': '#b0b0b0',
          '400': '#888888',
          '500': '#6d6d6d',
          '600': '#5d5d5d',
          '700': '#4f4f4f',
          '800': '#454545',
          '900': '#242629',
          '950': '#111111',
        }
      },
    },
  },
  plugins: [],
}
