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
  Zap
} from "lucide";

type IconAttributes = Readonly<Record<string, string | number>>;
type IconChild = readonly [tag: string, attributes: IconAttributes];
type IconNode = readonly [tag: string, attributes: IconAttributes, children?: readonly IconChild[]];

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
      const [, baseAttributes, children = []] = appIconNodes[props.name];
      const accessibleAttributes = props.title
        ? { role: "img", "aria-label": props.title }
        : { "aria-hidden": "true" };

      return h(
        "svg",
        {
          ...baseAttributes,
          ...accessibleAttributes,
          ...attrs,
          class: ["app-icon", attrs.class]
        },
        [
          props.title ? h("title", props.title) : null,
          ...children.map(([tag, attributes], index) => h(tag, { ...attributes, key: index }))
        ]
      );
    };
  }
});
