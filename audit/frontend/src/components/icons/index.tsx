// SeQr icon set. Drawn on a 20px grid, 1.5px stroke, square caps, miter joins,
// currentColor. Shapes stay rectilinear to match the instrument-of-record look.
import type { SVGProps } from "react";

export type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 20, children, ...rest }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="square"
      strokeLinejoin="miter"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconOverview = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 3.75h14M3 16.25h14" />
    <path d="M5.5 13V9.5M10 13V6.5M14.5 13v-2" />
  </Svg>
);
export const IconAssets = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h13.5v4.5H3.25zM3.25 12.25h13.5v4.5H3.25z" />
    <path d="M6 5.5h1M6 14.5h1" />
  </Svg>
);
export const IconGraph = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 4h4v4H3zM13 3h4v4h-4zM9 13h4v4H9z" />
    <path d="M7 6h6M15 7v3.5h-4V13M5 8v7h4" />
  </Svg>
);
export const IconCbom = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4.25 2.75h8.5l3 3v11.5H4.25z" />
    <path d="M7 8.5h6M7 11.5h6M7 14.5h3.5" />
  </Svg>
);
export const IconRemediation = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 16.5h14" />
    <path d="M3.5 14c3-1 4.5-4 6.5-7s4-3.5 6.5-3.5" />
    <path d="M13.5 3.5h3v3" />
  </Svg>
);
export const IconConnections = (p: IconProps) => (
  <Svg {...p}>
    <path d="M2.75 10h4.5M12.75 10h4.5" />
    <path d="M7.25 6.75h5.5v6.5h-5.5z" />
    <path d="M10 3v3.75M10 13.25V17" />
  </Svg>
);
export const IconReports = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4.25 2.75h11.5v14.5H4.25z" />
    <path d="M7 6.5h6M7 9.5h6M7 12.5h3" />
  </Svg>
);
export const IconSettings = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 5.5h8M15 5.5h2M3 14.5h2M9 14.5h8" />
    <path d="M11 3.5h4v4h-4zM5 12.5h4v4H5z" />
  </Svg>
);
export const IconSearch = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h9.5v9.5h-9.5z" />
    <path d="M12.75 12.75l4 4" />
  </Svg>
);
export const IconBell = (p: IconProps) => (
  <Svg {...p}>
    <path d="M5 13.75V8.5a5 5 0 0110 0v5.25l1.25 1.5H3.75z" />
    <path d="M8.25 17.25h3.5" />
  </Svg>
);
export const IconLogout = (p: IconProps) => (
  <Svg {...p}>
    <path d="M11.5 3.25H3.75v13.5h7.75" />
    <path d="M8 10h9M14 7l3 3-3 3" />
  </Svg>
);
export const IconCollapse = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h13.5v13.5H3.25zM7.75 3.25v13.5" />
    <path d="M13 8l-2 2 2 2" />
  </Svg>
);
export const IconExpand = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h13.5v13.5H3.25zM7.75 3.25v13.5" />
    <path d="M11 8l2 2-2 2" />
  </Svg>
);
export const IconMenu = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 5.5h14M3 10h14M3 14.5h14" />
  </Svg>
);
export const IconPlus = (p: IconProps) => (
  <Svg {...p}>
    <path d="M10 3.5v13M3.5 10h13" />
  </Svg>
);
export const IconMinus = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.5 10h13" />
  </Svg>
);
export const IconScan = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 7V3h4M13 3h4v4M17 13v4h-4M7 17H3v-4" />
    <path d="M3 10h14" />
  </Svg>
);
export const IconTrash = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 5.25h14M7.5 5.25V3h5v2.25" />
    <path d="M5 5.25l.75 11.5h8.5L15 5.25" />
  </Svg>
);
export const IconDownload = (p: IconProps) => (
  <Svg {...p}>
    <path d="M10 3v9.5M6 8.5l4 4 4-4" />
    <path d="M3.5 16.75h13" />
  </Svg>
);
export const IconUpload = (p: IconProps) => (
  <Svg {...p}>
    <path d="M10 13V3.5M6 7.5l4-4 4 4" />
    <path d="M3.5 16.75h13" />
  </Svg>
);
export const IconCopy = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6.75 6.75h10v10h-10z" />
    <path d="M13.25 6.75v-3.5h-10v10h3.5" />
  </Svg>
);
export const IconExternal = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8.5 3.5H3.5v13h13v-5" />
    <path d="M11.5 3.5h5v5M16.5 3.5L9 11" />
  </Svg>
);
export const IconClose = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4.5 4.5l11 11M15.5 4.5l-11 11" />
  </Svg>
);
export const IconChevronRight = (p: IconProps) => (
  <Svg {...p}>
    <path d="M7.5 4.5L13 10l-5.5 5.5" />
  </Svg>
);
export const IconChevronDown = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4.5 7.5L10 13l5.5-5.5" />
  </Svg>
);
export const IconChevronLeft = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12.5 4.5L7 10l5.5 5.5" />
  </Svg>
);
export const IconArrowRight = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 10h13M12 6l4 4-4 4" />
  </Svg>
);
export const IconArrowLeft = (p: IconProps) => (
  <Svg {...p}>
    <path d="M17 10H4M8 6l-4 4 4 4" />
  </Svg>
);
export const IconFilter = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 4.25h14l-5.25 6.5v5l-3.5 1.5v-6.5z" />
  </Svg>
);
export const IconZoomIn = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h9.5v9.5h-9.5zM12.75 12.75l4 4M8 5.5v5M5.5 8h5" />
  </Svg>
);
export const IconZoomOut = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h9.5v9.5h-9.5zM12.75 12.75l4 4M5.5 8h5" />
  </Svg>
);
export const IconFit = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 7V3h4M13 3h4v4M17 13v4h-4M7 17H3v-4" />
    <path d="M7 7h6v6H7z" />
  </Svg>
);
export const IconKey = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 7.25h6.5v5.5h-6.5z" />
    <path d="M9.75 10h7M14.5 10v3M16.75 10v2" />
  </Svg>
);
export const IconShield = (p: IconProps) => (
  <Svg {...p}>
    <path d="M10 2.75l6.25 2.5v4.5c0 3.75-2.75 6.25-6.25 7.5-3.5-1.25-6.25-3.75-6.25-7.5v-4.5z" />
  </Svg>
);
export const IconLock = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4.25 9h11.5v8.25H4.25z" />
    <path d="M6.75 9V6.25a3.25 3.25 0 016.5 0V9M10 12v2" />
  </Svg>
);
export const IconCertificate = (p: IconProps) => (
  <Svg {...p}>
    <path d="M2.75 3.75h14.5v9.5h-6" />
    <path d="M5.5 7h9M5.5 10h4" />
    <path d="M5.25 13.25h3.5v3.5l-1.75-1-1.75 1z" />
  </Svg>
);
export const IconServer = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h13.5v6.25H3.25zM3.25 9.5h13.5v7.25H3.25z" />
    <path d="M6 6.5h1.5M6 13h1.5" />
  </Svg>
);
export const IconDatabase = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4 4.5c0-1 2.7-1.75 6-1.75s6 .75 6 1.75v11c0 1-2.7 1.75-6 1.75s-6-.75-6-1.75z" />
    <path d="M4 4.5c0 1 2.7 1.75 6 1.75s6-.75 6-1.75M4 10c0 1 2.7 1.75 6 1.75s6-.75 6-1.75" />
  </Svg>
);
export const IconMail = (p: IconProps) => (
  <Svg {...p}>
    <path d="M2.75 4.75h14.5v10.5H2.75z" />
    <path d="M2.75 5l7.25 6 7.25-6" />
  </Svg>
);
export const IconCli = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.5 6l4 4-4 4M10 14.5h6.5" />
  </Svg>
);
export const IconGlobe = (p: IconProps) => (
  <Svg {...p}>
    <path d="M10 2.75a7.25 7.25 0 100 14.5 7.25 7.25 0 000-14.5z" />
    <path d="M2.75 10h14.5M10 2.75c2 2 3 4.5 3 7.25s-1 5.25-3 7.25c-2-2-3-4.5-3-7.25s1-5.25 3-7.25z" />
  </Svg>
);
export const IconAgent = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4.25 6.25h11.5v9.5H4.25z" />
    <path d="M10 3v3.25M7.5 10.5h1M11.5 10.5h1M7.5 13.25h5" />
  </Svg>
);
export const IconPlay = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6 4l9 6-9 6z" />
  </Svg>
);
export const IconVerify = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h13.5v13.5H3.25z" />
    <path d="M6.5 10l2.5 2.5 4.5-5" />
  </Svg>
);
export const IconSignature = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 16.75h14" />
    <path d="M3.5 13c1.5-4 3-8 4.5-8s-1 7 1 7 2-3 3-3 1 2 2 2h2.5" />
  </Svg>
);
export const IconWarning = (p: IconProps) => (
  <Svg {...p}>
    <path d="M10 2.75l7.5 14H2.5z" />
    <path d="M10 7.75v4M10 13.75v.5" />
  </Svg>
);
export const IconInfo = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h13.5v13.5H3.25z" />
    <path d="M10 9v4.5M10 6.25v.5" />
  </Svg>
);
export const IconSortAsc = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6 15V4.5M3 7.5l3-3 3 3M11.5 6h5.5M11.5 10h4M11.5 14h2.5" />
  </Svg>
);
export const IconSortDesc = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6 5v10.5M3 12.5l3 3 3-3M11.5 6h2.5M11.5 10h4M11.5 14h5.5" />
  </Svg>
);
export const IconCheck = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4 10.5l4 4 8-9" />
  </Svg>
);
export const IconEye = (p: IconProps) => (
  <Svg {...p}>
    <path d="M2 10c2-3.75 4.75-5.75 8-5.75s6 2 8 5.75c-2 3.75-4.75 5.75-8 5.75S4 13.75 2 10z" />
    <path d="M8 8h4v4H8z" />
  </Svg>
);
export const IconEyeOff = (p: IconProps) => (
  <Svg {...p}>
    <path d="M2 10c2-3.75 4.75-5.75 8-5.75s6 2 8 5.75c-2 3.75-4.75 5.75-8 5.75S4 13.75 2 10z" />
    <path d="M3.5 3.5l13 13" />
  </Svg>
);
export const IconTheme = (p: IconProps) => (
  <Svg {...p}>
    <path d="M10 2.75a7.25 7.25 0 100 14.5z" fill="currentColor" stroke="none" />
    <path d="M10 2.75a7.25 7.25 0 110 14.5 7.25 7.25 0 010-14.5z" />
  </Svg>
);
export const IconUser = (p: IconProps) => (
  <Svg {...p}>
    <path d="M7 3.75h6v6H7zM3.5 17c.75-3.25 3.25-5 6.5-5s5.75 1.75 6.5 5" />
  </Svg>
);
export const IconUsers = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4.5 4.5h5v5h-5zM1.75 16.75c.5-2.75 2.5-4.25 5.25-4.25s4.75 1.5 5.25 4.25" />
    <path d="M12.5 4.5h4v4M13.5 12.75c2 .25 3.5 1.75 4 4" />
  </Svg>
);
export const IconLog = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 4.5h1.5M3 10h1.5M3 15.5h1.5M7.5 4.5H17M7.5 10H17M7.5 15.5H14" />
  </Svg>
);
export const IconPalette = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h6.25v6.25H3.25zM10.5 10.5h6.25v6.25H10.5z" />
    <path d="M10.5 3.25h6.25v6.25M3.25 10.5v6.25H9.5" />
  </Svg>
);
export const IconBuilding = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4.25 2.75h7.5v14.5h-7.5zM11.75 7.75h4v9.5h-4" />
    <path d="M6.75 6h2.5M6.75 9h2.5M6.75 12h2.5M2.5 17.25h15" />
  </Svg>
);
export const IconPackage = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 6l7-3.25L17 6v8L10 17.25 3 14z" />
    <path d="M3 6l7 3.25L17 6M10 9.25v8" />
  </Svg>
);
export const IconEdit = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12.5 3.5l4 4-9 9h-4v-4z" />
    <path d="M10.5 5.5l4 4" />
  </Svg>
);
export const IconLinkedIn = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.25 3.25h13.5v13.5H3.25z" />
    <path d="M6.5 9v5M6.5 6.5v.25M9.5 14V9M9.5 11.25c0-1.5.9-2.25 2-2.25s2 .75 2 2.25V14" />
  </Svg>
);
export const IconGitHub = (p: IconProps) => (
  <Svg {...p}>
    <path d="M7.5 16.5c-3 .9-3-1.6-4.25-1.9M12.5 17.25v-2.9c0-.8.1-1.15-.35-1.6 2.1-.25 4.35-1 4.35-4.75a3.7 3.7 0 00-1-2.55 3.45 3.45 0 00-.1-2.55s-.8-.25-2.6 1a9 9 0 00-4.7 0C6.3 2.65 5.5 2.9 5.5 2.9a3.45 3.45 0 00-.1 2.55 3.7 3.7 0 00-1 2.55c0 3.75 2.25 4.5 4.35 4.75-.45.45-.45.9-.35 1.6v2.9" />
  </Svg>
);
