import { createApp } from "vue";
import PrimeVue from "primevue/config";
import Aura from "@primeuix/themes/aura";
import "./styles.css";
import App from "./App.vue";

document.documentElement.classList.add("app-dark");

createApp(App)
  .use(PrimeVue, {
    theme: {
      preset: Aura,
      options: {
        darkModeSelector: ".app-dark"
      }
    }
  })
  .mount("#app");
