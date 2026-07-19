export const COLOR_THEME_STORAGE_KEY = "ppaass-color-theme";

export const colorThemes = [
  { value: "midnight", label: "午夜霓虹", mode: "dark" },
  { value: "ocean", label: "深海蓝", mode: "dark" },
  { value: "forest", label: "森林绿", mode: "dark" },
  { value: "sunset", label: "日落橙", mode: "dark" },
  { value: "violet", label: "星云紫", mode: "dark" },
  { value: "porcelain", label: "暖瓷白", mode: "light" },
  { value: "sky", label: "晴空白", mode: "light" },
  { value: "mint", label: "薄荷白", mode: "light" },
  { value: "rose", label: "樱花白", mode: "light" }
] as const;

export type ColorTheme = (typeof colorThemes)[number]["value"];

export function isColorTheme(value: string | null): value is ColorTheme {
  return colorThemes.some((theme) => theme.value === value);
}

export function loadColorTheme(): ColorTheme {
  const stored = localStorage.getItem(COLOR_THEME_STORAGE_KEY);
  return isColorTheme(stored) ? stored : "midnight";
}

export function applyColorTheme(theme: ColorTheme): void {
  const root = document.documentElement;
  const selected = colorThemes.find((option) => option.value === theme) ?? colorThemes[0];
  root.classList.toggle("app-dark", selected.mode === "dark");
  root.classList.toggle("app-light", selected.mode === "light");
  for (const option of colorThemes) {
    root.classList.toggle(`app-theme-${option.value}`, option.value === theme);
  }
  root.dataset.colorTheme = theme;
  localStorage.setItem(COLOR_THEME_STORAGE_KEY, theme);
}
