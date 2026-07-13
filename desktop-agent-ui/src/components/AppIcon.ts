import { defineComponent, h, type PropType } from "vue";
import {
  Activity,
  Asterisk,
  Building2,
  ChartNoAxesCombined,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  CirclePlus,
  Clock3,
  Cloud,
  Code2,
  Compass,
  Cpu,
  Database,
  Ellipsis,
  Globe2,
  Hash,
  HeartPulse,
  Info,
  KeyRound,
  LayoutDashboard,
  LoaderCircle,
  MapPin,
  Monitor,
  Move,
  Network,
  Package,
  PanelsTopLeft,
  Play,
  Plus,
  RadioTower,
  RefreshCw,
  RotateCcw,
  Route,
  Save,
  ScrollText,
  Send,
  Server,
  Settings2,
  Share2,
  ShieldCheck,
  Square,
  Timer,
  TriangleAlert,
  UserRound,
  Waypoints,
  Zap,
  type IconNode
} from "lucide";

const svgBaseAttributes = {
  xmlns: "http://www.w3.org/2000/svg",
  width: 24,
  height: 24,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  "stroke-width": 2,
  "stroke-linecap": "round",
  "stroke-linejoin": "round"
} as const;

export const appIconNodes = {
  activity: Activity,
  "alert-circle": CircleAlert,
  asterisk: Asterisk,
  building: Building2,
  chart: ChartNoAxesCombined,
  "check-circle": CircleCheck,
  "chevron-left": ChevronLeft,
  "chevron-right": ChevronRight,
  "circle-plus": CirclePlus,
  clock: Clock3,
  cloud: Cloud,
  code: Code2,
  compass: Compass,
  cpu: Cpu,
  database: Database,
  ellipsis: Ellipsis,
  globe: Globe2,
  hash: Hash,
  "heart-pulse": HeartPulse,
  info: Info,
  key: KeyRound,
  "layout-dashboard": LayoutDashboard,
  loader: LoaderCircle,
  "map-pin": MapPin,
  monitor: Monitor,
  move: Move,
  network: Network,
  package: Package,
  panels: PanelsTopLeft,
  play: Play,
  plus: Plus,
  "radio-tower": RadioTower,
  refresh: RefreshCw,
  restore: RotateCcw,
  route: Route,
  save: Save,
  "scroll-text": ScrollText,
  send: Send,
  server: Server,
  settings: Settings2,
  share: Share2,
  "shield-check": ShieldCheck,
  stop: Square,
  timer: Timer,
  "triangle-alert": TriangleAlert,
  user: UserRound,
  waypoints: Waypoints,
  zap: Zap
} as const satisfies Record<string, IconNode>;

export type AppIconName = keyof typeof appIconNodes;

type AppIconTone = "violet" | "rose" | "mint" | "amber" | "sky";

const appIconTones: Record<AppIconName, AppIconTone> = {
  activity: "sky",
  "alert-circle": "rose",
  asterisk: "amber",
  building: "mint",
  chart: "rose",
  "check-circle": "mint",
  "chevron-left": "violet",
  "chevron-right": "violet",
  "circle-plus": "violet",
  clock: "amber",
  cloud: "sky",
  code: "mint",
  compass: "mint",
  cpu: "amber",
  database: "sky",
  ellipsis: "violet",
  globe: "sky",
  hash: "amber",
  "heart-pulse": "rose",
  info: "sky",
  key: "amber",
  "layout-dashboard": "violet",
  loader: "violet",
  "map-pin": "rose",
  monitor: "violet",
  move: "violet",
  network: "rose",
  package: "violet",
  panels: "sky",
  play: "mint",
  plus: "violet",
  "radio-tower": "sky",
  refresh: "sky",
  restore: "amber",
  route: "mint",
  save: "violet",
  "scroll-text": "rose",
  send: "mint",
  server: "sky",
  settings: "amber",
  share: "rose",
  "shield-check": "mint",
  stop: "rose",
  timer: "amber",
  "triangle-alert": "amber",
  user: "rose",
  waypoints: "mint",
  zap: "amber"
};

export default defineComponent({
  name: "AppIcon",
  inheritAttrs: false,
  props: {
    name: {
      type: String as PropType<AppIconName>,
      required: true
    },
    title: {
      type: String,
      default: ""
    }
  },
  setup(props, { attrs }) {
    return () => {
      const [, , children = []] = appIconNodes[props.name];
      const accessibleAttributes = props.title
        ? { role: "img", "aria-label": props.title }
        : { "aria-hidden": "true" };

      return h(
        "span",
        {
          ...accessibleAttributes,
          ...attrs,
          class: ["app-icon", attrs.class],
          "data-icon": props.name,
          "data-tone": appIconTones[props.name]
        },
        [
          h(
            "svg",
            {
              ...svgBaseAttributes,
              class: "app-icon-glyph",
              "aria-hidden": "true",
              focusable: "false"
            },
            [
              props.title ? h("title", props.title) : null,
              ...children.map(([tag, attributes], index) => h(tag, { ...attributes, key: index }))
            ]
          )
        ]
      );
    };
  }
});
