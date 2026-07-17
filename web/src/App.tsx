import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table"
import { createBrowserSdk } from "auth-mini/sdk/browser"
import {
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom"
import {
  ActivityIcon,
  ArrowDownUpIcon,
  BoxesIcon,
  CheckCircle2Icon,
  ChevronLeftIcon,
  ChevronRightIcon,
  CircleGaugeIcon,
  ClipboardIcon,
  KeyRoundIcon,
  LanguagesIcon,
  LogInIcon,
  LogOutIcon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  ScrollTextIcon,
  SettingsIcon,
  ShieldAlertIcon,
  SlidersHorizontalIcon,
  Trash2Icon,
  UserRoundCogIcon,
  XCircleIcon,
} from "lucide-react"
import { toast } from "sonner"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { api, type AuthSdk } from "@/lib/api"
import {
  clearAuthMiniSetupDraft,
  normalizeAuthMiniIssuer,
  readAuthMiniSetupDraft,
  startAuthMiniLogin,
  type SetupDraft,
} from "@/lib/auth-redirect"

type Locale = "zh" | "en"
type Page =
  | "dashboard"
  | "providers"
  | "consumers"
  | "usage"
  | "audit"
  | "request-detail"
  | "users"
  | "settings"
type NavPage = Exclude<Page, "request-detail">
type Role = "root" | "admin" | "user"
type User = { id: string; email?: string; name?: string; role: Role }
type ManagedUser = {
  id: string
  email?: string
  display_name?: string
  role: Role
  provider_access: boolean
  created_at: number
}
type PublicConfig = { setup_required: boolean; auth_issuer?: string }
type Consumer = {
  id: string
  name: string
  prefix: string
  created_at: number
  last_used_at?: number
  revoked_at?: number
}
type Provider = {
  id: string
  name: string
  account_id: string
  status: string
  manual_disabled: number
  cooldown_until?: number
  rate_limit_json?: string
  last_error?: string
  inflight: number
  updated_at: number
}
type ProviderTokens = { access_key: string; refresh_key: string }
type UsageWindow = {
  used_percent?: number
  reset_at?: number
  reset_after_seconds?: number
}
type ProviderUsage = {
  email?: string
  account_email?: string
  account?: { email?: string }
  plan_type?: string
  rate_limit?: { primary_window?: UsageWindow; secondary_window?: UsageWindow }
  credits?: { balance?: number | string | null; unlimited?: boolean }
  [key: string]: unknown
}
type ProviderUsageEntry = { usage?: ProviderUsage; error?: string }
type ProviderUsageResponse = { providers: Record<string, ProviderUsageEntry> }
type ProviderTokenDialogState = {
  provider: Provider
  loading: boolean
  tokens?: ProviderTokens
  error?: string
}
type ProviderTestState = {
  provider: Provider
  status: "loading" | "success" | "error"
  usage?: ProviderUsage
  error?: string
}
type UsagePeriod = "24h" | "7d"
type UsageRow = {
  user_id: string
  user_email?: string
  user_name?: string
  consumer_id: string
  consumer_name: string
  consumer_prefix: string
  model: string
  date: string
  requests: number
  input_tokens: number
  cached_tokens: number
  output_tokens: number
}
type UsageResponse = { period: UsagePeriod; since: number; rows: UsageRow[] }
type PivotCell = Pick<
  UsageRow,
  "input_tokens" | "cached_tokens" | "output_tokens"
>
type PivotTableRow = {
  id: string
  values: UsageRow
  cells: Record<string, PivotCell>
}
type PivotColumn = { id: string; label: string }
type Audit = {
  id: string
  request_id: string
  user_id: string
  consumer_name: string
  provider_id?: string
  provider_name?: string
  path: string
  model?: string
  status: number
  latency_ms: number
  input_tokens: number
  output_tokens: number
  cached_tokens: number
  error?: string
  created_at: number
}
type AuditNavigation = { id: string; request_id: string; created_at: number }
type AuditDetail = Audit & {
  method: string
  client_ip?: string
  affinity_hash?: string
  affinity_source?: string
  archive_available: boolean
  request_headers?: string
  request_body?: string
  request_body_truncated: boolean
  response_headers?: string
  response_body?: string
  response_body_truncated: boolean
  previous?: AuditNavigation
  next?: AuditNavigation
}
type AdminAudit = {
  id: string
  admin_user_id: string
  admin_email?: string
  action: string
  target_id?: string
  client_ip?: string
  created_at: number
}
type SettingsData = {
  auth_issuer?: string
  upstream_base: string
  image_host_model: string
  oauth_authorize_url: string
  oauth_token_url: string
  oauth_redirect_uri: string
  oauth_client_id: string
  response_body_limit: number
  image_body_limit: number
  audio_body_limit: number
  affinity_ttl_seconds: number
  request_archive_retention_days: number
}

const copy = {
  zh: {
    dashboard: "总览",
    providers: "上游提供商",
    consumers: "下游消费者",
    usage: "用量",
    audit: "审计",
    users: "用户",
    settings: "设置",
    signout: "退出登录",
    title: "OpenAI-LB",
    subtitle: "CodeX OAuth 负载均衡器",
    console: "控制台",
    english: "English",
    roleLoading: "加载中",
    loginDescription: "使用 Auth Mini 登录运维控制台",
    email: "邮箱",
    authRedirectTitle: "在 Auth Mini 完成身份验证",
    authRedirectHelp:
      "邮箱验证码、Passkey 和 ED25519 登录均在 Auth Mini 页面完成；成功后会自动返回 OpenAI-LB。",
    continueAuthMini: "前往 Auth Mini 登录",
    loading: "正在加载 OpenAI-LB…",
    pageDashboard: "查看上游提供商容量与当前租户的 24 小时运行摘要。",
    pageProviders: "注册、刷新、停用并观察 CodeX OAuth 上游提供商。",
    pageConsumers: "按 AI App 隔离下游消费者，分别跟踪调用量并独立吊销凭据。",
    pageUsage: "按消费者核算请求、Token、错误和延迟。",
    pageAudit: "逐次追踪请求、上游提供商、结果与用量；诊断内容按配置期限保留。",
    pageRequestDetail: "查看调用上下文、消息结构与同一亲和链的相邻请求。",
    pageUsers: "由 root 管理本地授权角色；用户身份仍由 Auth Mini 提供。",
    pageSettings: "确认身份边界、上游与部署限制。",
    operationalStatus: "运行状态",
    operationalDescription: "当前租户与上游提供商池的可行动摘要",
    availableProviders: "可用上游提供商",
    activeConsumers: "有效消费者",
    calls24h: "24 小时调用",
    errors24h: "24 小时错误",
    providerPool: "OAuth 上游提供商池",
    providerDescription:
      "Token 以明文保存在 SQLite；管理员读取与变更会进入操作审计。",
    addProvider: "添加上游提供商",
    noProviders: "尚无上游提供商",
    noProvidersDescription:
      "添加 access_key 与 refresh_key，或开始 PKCE OAuth。",
    name: "名称",
    account: "账户",
    status: "状态",
    recoveryReason: "恢复 / 原因",
    actions: "操作",
    refresh: "刷新",
    providerUpdated: "上游提供商已更新",
    providerAdded: "上游提供商已添加",
    oauthProviderAdded: "OAuth 上游提供商已添加",
    addProviderTitle: "添加 CodeX OAuth 上游提供商",
    addProviderDescription:
      "直接导入凭据，或用 PKCE 授权后粘贴回调中的 code。Token 将以明文保存在 SQLite，并可由管理员再次读取和编辑。",
    accessClaimHelp: "必须是包含 CodeX account_id claim 的 JWT。",
    oauthCode: "OAuth code",
    oauthStateHelp: "State 已在服务器中一次性保存，有效期 10 分钟。",
    startOauth: "开始 OAuth",
    completeOauth: "完成 OAuth",
    importCredentials: "导入凭据",
    editProvider: "编辑",
    tokenTitle: "编辑上游提供商",
    tokenDescription:
      "编辑上游提供商名称和 SQLite 明文存储的 Token。保存时三项会原子更新。",
    loadingTokens: "正在读取 Token…",
    saveTokens: "保存",
    tokensSaved: "上游提供商已保存",
    deleteProvider: "删除",
    deleteProviderTitle: "删除 OAuth 上游提供商？",
    deleteProviderDescription:
      "此操作会永久删除该上游提供商及 Token；依赖该上游提供商的亲和记录也会一并删除。",
    confirmDeleteProvider: "确认删除",
    providerDeleted: "上游提供商已删除",
    testProvider: "测试",
    testingProvider: "正在获取上游提供商 Usage…",
    testTitle: "上游提供商 Usage 测试",
    testDescription:
      "服务端使用该上游提供商 OAuth Token 调用 Usage API，Token 不会随测试结果返回浏览器。",
    testSucceeded: "上游提供商测试成功",
    usageEmail: "邮箱",
    usagePlan: "套餐",
    quotaRemaining: "剩余额度",
    resetsIn: "重置倒计时",
    quotaUnavailable: "未返回额度",
    credits: "Credits",
    rawUsage: "Usage 原始字段",
    usageUnavailable: "Usage API 未返回可识别的额度字段，请查看原始字段。",
    consumersTitle: "租户消费者",
    consumersDescription:
      "每个 AI App 建议使用一个独立消费者；这样用量、错误和吊销都能按 App 隔离。消费者凭据只在创建后显示一次。",
    create: "创建",
    noConsumers: "尚无消费者",
    noConsumersDescription: "为每个 AI App 创建一个独立消费者，再开始调用代理。",
    prefix: "前缀",
    createdAt: "创建时间",
    lastUsed: "最近使用",
    revoked: "已吊销",
    active: "有效",
    revoke: "吊销",
    editConsumer: "编辑",
    saveConsumer: "保存",
    consumerUpdated: "消费者已更新",
    revokeTitle: "吊销消费者？",
    revokeDescription: "此操作不可撤销；使用该消费者的所有调用将立即失败。",
    cancel: "取消",
    confirmRevoke: "确认吊销",
    consumerAppHelp:
      "请为每个 AI App 单独创建一个消费者，并用 App 名称命名，便于隔离用量、排障和吊销。",
    saveConsumerTitle: "立即保存消费者",
    saveConsumerDescription:
      "关闭后无法再次查看。不要将它写入浏览器代码、日志或聊天记录。",
    savedConsumer: "我已安全保存",
    copied: "已复制",
    consumerRevoked: "消费者已吊销",
    usageTitle: "用量透视",
    usageDescription:
      "按用户、脱敏 API Token、模型和日期交叉汇总请求 Token；调整行、列和聚合数据以定位用量。",
    noUsage: "暂无用量",
    noUsageDescription: "在所选时间段发起 API 调用后，这里会按维度汇总 Token。",
    requests: "请求",
    errors: "错误",
    averageLatency: "平均延迟",
    last24Hours: "最近 24 小时",
    last7Days: "最近 7 天",
    allUsers: "全部用户",
    allConsumers: "全部消费者",
    allModels: "全部模型",
    model: "模型",
    consumerLabel: "消费者",
    date: "日期",
    rows: "行",
    columns: "列",
    data: "数据",
    hidden: "隐藏",
    inputTokens: "输入 Token",
    cachedInputTokens: "缓存输入 Token",
    outputTokens: "输出 Token",
    usageRows: "条聚合记录",
    sortColumn: "排序",
    total: "总计",
    clearFilters: "清除筛选",
    pivotFields: "透视字段",
    groupOrder: "分组顺序",
    sum: "求和",
    auditTitle: "逐调用审计",
    auditDescription:
      "请求/响应诊断预览保存在 SQLite；不记录 Authorization 或 OAuth 凭据。",
    noAudit: "暂无审计事件",
    noAuditDescription: "每次代理调用结束后都会写入基础审计记录。",
    time: "时间",
    requestId: "请求 ID",
    provider: "上游提供商",
    endpointModel: "接口 / 模型",
    latency: "延迟",
    cachedInput: "缓存输入",
    details: "详情",
    requestDetail: "请求详情",
    backToAudit: "返回审计",
    auditDetailDescription:
      "展示已保留的请求与响应诊断预览；敏感凭据不会记录。",
    requestHeaders: "请求头",
    requestBody: "请求正文",
    responseHeaders: "响应头",
    responseBody: "响应正文",
    previewTruncated: "预览已截断",
    auditArchiveUnavailable: "此请求的诊断记录已过期或不可用。",
    affinitySource: "亲和来源",
    affinityRequestId: "亲和请求 ID",
    affinityHash: "亲和哈希",
    previousRequest: "上一个请求",
    nextRequest: "下一个请求",
    messages: "消息结构",
    requestSettings: "请求参数",
    instructions: "Instructions",
    tools: "工具",
    rawRequest: "原始请求",
    identityPermissions: "身份与权限",
    identityDescription: "浏览器会话由 Auth Mini 管理；后端只验证 access JWT。",
    proxyBoundary: "代理边界",
    proxyDescription: "仅 OpenAI / CodeX 能力，不提供其他厂商兼容协议。",
    unableLoad: "无法加载",
    unknownError: "未知错误",
    close: "关闭",
    inflight: "处理中",
    accessKey: "Access key",
    refreshKey: "Refresh key",
    consumer: "消费者",
    input: "输入",
    output: "输出",
    userId: "用户 ID",
    role: "角色",
    authIssuer: "认证签发方",
    upstream: "上游",
    bodyLimit: "请求体限制",
    affinityTtl: "亲和 TTL",
    statusActive: "可用",
    statusCooldown: "冷却中",
    statusAuthError: "认证错误",
    statusDisabled: "已禁用",
    statusUnknown: "未知",
    roleRoot: "超级管理员",
    roleAdmin: "管理员",
    roleUser: "租户用户",
    loginUnknown: "认证失败，请重试。",
    adminAuditTitle: "管理员操作审计",
    adminAuditDescription:
      "记录上游提供商与 OAuth 管理操作、失败尝试、来源 IP 和目标。",
    administrator: "管理员",
    action: "操作",
    target: "目标",
    clientIp: "客户端 IP",
    setupTitle: "初始化 OpenAI-LB",
    setupDescription: "连接品牌 Auth Mini，并将首个已验证用户绑定为唯一 root。",
    setupIssuer: "Auth Mini issuer",
    setupIssuerHelp:
      "填写品牌提供的 Auth Mini HTTPS 地址。OpenAI-LB 只连接该实例，不会部署或管理它。",
    setupAudience: "JWT audience（可选）",
    connectAuth: "连接 Auth Mini",
    changeAuth: "更换实例",
    setupLogin: "验证 root 身份",
    setupLoginHelp:
      "登录成功后，当前 Auth Mini user_id 将成为 OpenAI-LB root。",
    finishSetup: "绑定 root 并完成初始化",
    finishingSetup: "正在完成初始化",
    setupStepConnect: "连接认证实例",
    setupStepLogin: "验证首个用户",
    setupStepFinish: "绑定 root",
    setupConnected: "已连接",
    setupWaiting: "待完成",
    setupAuthenticated: "身份已验证",
    setupSecurity:
      "Setup 完成后初始化入口会立即关闭；后续登录用户默认为 user。",
    usersTitle: "用户与上游提供商权限",
    usersDescription:
      "新租户用户默认不能使用上游提供商；管理员可单独授权。管理员和 root 始终允许使用上游提供商。",
    noUsers: "暂无用户",
    noUsersDescription: "用户首次通过 Auth Mini 登录后会自动出现在这里。",
    displayName: "显示名称",
    roleUpdated: "用户角色已更新",
    providerAccess: "上游提供商访问",
    providerAccessUpdated: "上游提供商访问权限已更新",
    alwaysAllowed: "管理员始终允许",
    runtimeSettings: "运行配置",
    runtimeSettingsDescription:
      "这些值保存在 SQLite app_meta 中；地址与模型立即生效，请求体上限重启后生效。",
    saveSettings: "保存配置",
    settingsSaved: "配置已保存",
    imageHostModel: "图像宿主模型",
    oauthAuthorizeUrl: "OAuth 授权地址",
    oauthTokenUrl: "OAuth Token 地址",
    oauthRedirectUri: "OAuth 回调地址",
    oauthClientId: "OAuth Client ID",
    responseLimit: "Responses 限制",
    imageLimit: "图像请求限制",
    audioLimit: "音频请求限制",
  },
  en: {
    dashboard: "Overview",
    providers: "Providers",
    consumers: "Consumers",
    usage: "Usage",
    audit: "Audit",
    users: "Users",
    settings: "Settings",
    signout: "Sign out",
    title: "OpenAI-LB",
    subtitle: "CodeX OAuth load balancer",
    console: "Console",
    english: "简体中文",
    roleLoading: "Loading",
    loginDescription: "Sign in to the operations console with Auth Mini",
    email: "Email",
    authRedirectTitle: "Verify your identity in Auth Mini",
    authRedirectHelp:
      "Email codes, passkeys, and ED25519 sign-in stay on the Auth Mini page. You will return to OpenAI-LB after signing in.",
    continueAuthMini: "Continue to Auth Mini",
    loading: "Loading OpenAI-LB…",
    pageDashboard:
      "Review provider capacity and the tenant's 24-hour operating summary.",
    pageProviders:
      "Register, refresh, disable, and observe CodeX OAuth providers.",
    pageConsumers:
      "Give each AI app its own downstream Consumer so usage, errors, and revocation stay isolated.",
    pageUsage:
      "Attribute requests, tokens, errors, and latency to each Consumer.",
    pageAudit:
      "Trace each request, provider, result, and usage; diagnostic content follows the configured retention.",
    pageRequestDetail:
      "Review call context, message structure, and adjacent requests in the same affinity chain.",
    pageUsers:
      "Root manages local authorization roles while Auth Mini remains the identity provider.",
    pageSettings:
      "Confirm identity boundaries, upstream, and deployment limits.",
    operationalStatus: "Operational status",
    operationalDescription: "Actionable tenant and provider-pool summary",
    availableProviders: "Available providers",
    activeConsumers: "Active Consumers",
    calls24h: "Calls in 24h",
    errors24h: "Errors in 24h",
    providerPool: "OAuth provider pool",
    providerDescription:
      "Tokens are stored as plaintext in SQLite; administrator reads and changes are audited.",
    addProvider: "Add provider",
    noProviders: "No providers",
    noProvidersDescription:
      "Add access_key and refresh_key, or start PKCE OAuth.",
    name: "Name",
    account: "Account",
    status: "Status",
    recoveryReason: "Recovery / reason",
    actions: "Actions",
    refresh: "Refresh",
    providerUpdated: "Provider updated",
    providerAdded: "Provider added",
    oauthProviderAdded: "OAuth provider added",
    addProviderTitle: "Add CodeX OAuth provider",
    addProviderDescription:
      "Import credentials directly, or authorize with PKCE and paste the callback code. Tokens are stored as plaintext in SQLite and can be read and edited by administrators.",
    accessClaimHelp: "Must be a JWT containing the CodeX account_id claim.",
    oauthCode: "OAuth code",
    oauthStateHelp:
      "State is stored once on the server and expires in 10 minutes.",
    startOauth: "Start OAuth",
    completeOauth: "Complete OAuth",
    importCredentials: "Import credentials",
    editProvider: "Edit",
    tokenTitle: "Edit provider",
    tokenDescription:
      "Edit the provider name and plaintext SQLite Tokens. Saving updates all three atomically.",
    loadingTokens: "Loading Tokens…",
    saveTokens: "Save",
    tokensSaved: "Provider saved",
    deleteProvider: "Delete",
    deleteProviderTitle: "Delete OAuth provider?",
    deleteProviderDescription:
      "This permanently deletes the provider and its Tokens. Affinity records that depend on it are deleted too.",
    confirmDeleteProvider: "Delete provider",
    providerDeleted: "Provider deleted",
    testProvider: "Test",
    testingProvider: "Fetching provider Usage…",
    testTitle: "Provider Usage test",
    testDescription:
      "The server calls the Usage API with this provider's OAuth Token. The Token is not returned with the test result.",
    testSucceeded: "Provider test succeeded",
    usageEmail: "Email",
    usagePlan: "Plan",
    quotaRemaining: "Quota remaining",
    resetsIn: "Resets in",
    quotaUnavailable: "Quota unavailable",
    credits: "Credits",
    rawUsage: "Raw Usage fields",
    usageUnavailable:
      "The Usage API returned no recognized quota fields. Review the raw fields below.",
    consumersTitle: "Tenant Consumers",
    consumersDescription:
      "Create one downstream Consumer per AI app so usage, errors, and revocation remain isolated. Secrets are shown once.",
    create: "Create",
    noConsumers: "No Consumers",
    noConsumersDescription:
      "Create a separate Consumer for each AI app before calling the proxy.",
    prefix: "Prefix",
    createdAt: "Created",
    lastUsed: "Last used",
    revoked: "Revoked",
    active: "Active",
    revoke: "Revoke",
    editConsumer: "Edit",
    saveConsumer: "Save",
    consumerUpdated: "Consumer updated",
    revokeTitle: "Revoke Consumer?",
    revokeDescription:
      "This cannot be undone. Every caller using this Consumer will fail immediately.",
    cancel: "Cancel",
    confirmRevoke: "Revoke Consumer",
    consumerAppHelp:
      "Create one Consumer per AI app and name it after the app so usage, troubleshooting, and revocation stay isolated.",
    saveConsumerTitle: "Save this Consumer now",
    saveConsumerDescription:
      "It cannot be viewed again after closing. Do not put it in browser code, logs, or chat.",
    savedConsumer: "I stored it safely",
    copied: "Copied",
    consumerRevoked: "Consumer revoked",
    usageTitle: "Usage pivot",
    usageDescription:
      "Cross-tabulate request Tokens by user, masked API token, model, and date. Adjust rows, columns, and aggregate data to isolate usage.",
    noUsage: "No usage yet",
    noUsageDescription:
      "Usage appears here by dimension after API calls in the selected period.",
    requests: "Requests",
    errors: "Errors",
    averageLatency: "Average latency",
    last24Hours: "Last 24 hours",
    last7Days: "Last 7 days",
    allUsers: "All users",
    allConsumers: "All Consumers",
    allModels: "All models",
    model: "Model",
    consumerLabel: "Consumer",
    date: "Date",
    rows: "Rows",
    columns: "Columns",
    data: "Data",
    hidden: "Hidden",
    inputTokens: "Input Tokens",
    cachedInputTokens: "Cached Input Tokens",
    outputTokens: "Output Tokens",
    usageRows: "aggregated rows",
    sortColumn: "Sort",
    total: "Total",
    clearFilters: "Clear filters",
    pivotFields: "Pivot fields",
    groupOrder: "Grouping order",
    sum: "Sum",
    auditTitle: "Per-call audit",
    auditDescription:
      "Request/response diagnostic previews are stored in SQLite; Authorization and OAuth credentials are excluded.",
    noAudit: "No audit events",
    noAuditDescription:
      "A basic audit record is written when each proxy call terminates.",
    time: "Time",
    requestId: "Request ID",
    provider: "Provider",
    endpointModel: "Endpoint / model",
    latency: "Latency",
    cachedInput: "Cached input",
    details: "Details",
    requestDetail: "Request details",
    backToAudit: "Back to audit",
    auditDetailDescription:
      "Shows retained request and response diagnostic previews; sensitive credentials are excluded.",
    requestHeaders: "Request headers",
    requestBody: "Request body",
    responseHeaders: "Response headers",
    responseBody: "Response body",
    previewTruncated: "Preview truncated",
    auditArchiveUnavailable:
      "The diagnostic record for this request has expired or is unavailable.",
    affinitySource: "Affinity source",
    affinityRequestId: "Affinity request ID",
    affinityHash: "Affinity hash",
    previousRequest: "Previous request",
    nextRequest: "Next request",
    messages: "Message structure",
    requestSettings: "Request settings",
    instructions: "Instructions",
    tools: "Tools",
    rawRequest: "Raw request",
    identityPermissions: "Identity and permissions",
    identityDescription:
      "Auth Mini manages the browser session; the backend only verifies access JWTs.",
    proxyBoundary: "Proxy boundary",
    proxyDescription:
      "OpenAI / CodeX capabilities only; no other vendor protocol compatibility.",
    unableLoad: "Unable to load",
    unknownError: "Unknown error",
    close: "Close",
    inflight: "Inflight",
    accessKey: "Access key",
    refreshKey: "Refresh key",
    consumer: "Consumer",
    input: "Input",
    output: "Output",
    userId: "User ID",
    role: "Role",
    authIssuer: "Auth issuer",
    upstream: "Upstream",
    bodyLimit: "Body limit",
    affinityTtl: "Affinity TTL",
    statusActive: "Available",
    statusCooldown: "Cooling down",
    statusAuthError: "Authentication error",
    statusDisabled: "Disabled",
    statusUnknown: "Unknown",
    roleRoot: "Root",
    roleAdmin: "Administrator",
    roleUser: "Tenant user",
    loginUnknown: "Authentication failed. Try again.",
    adminAuditTitle: "Administrator action audit",
    adminAuditDescription:
      "Provider and OAuth operations, failed attempts, source IP, and target.",
    administrator: "Administrator",
    action: "Action",
    target: "Target",
    clientIp: "Client IP",
    setupTitle: "Initialize OpenAI-LB",
    setupDescription:
      "Connect the brand Auth Mini instance and bind the first verified user as the only root.",
    setupIssuer: "Auth Mini issuer",
    setupIssuerHelp:
      "Enter the Auth Mini HTTPS URL supplied by the brand. OpenAI-LB connects to it; it does not deploy or manage it.",
    setupAudience: "JWT audience (optional)",
    connectAuth: "Connect Auth Mini",
    changeAuth: "Change instance",
    setupLogin: "Verify the root identity",
    setupLoginHelp:
      "After sign-in, this Auth Mini user_id becomes the OpenAI-LB root.",
    finishSetup: "Bind root and finish setup",
    finishingSetup: "Finishing setup",
    setupStepConnect: "Connect identity",
    setupStepLogin: "Verify first user",
    setupStepFinish: "Bind root",
    setupConnected: "Connected",
    setupWaiting: "Pending",
    setupAuthenticated: "Identity verified",
    setupSecurity:
      "The setup endpoint closes immediately after completion. Later first-time users receive the user role.",
    usersTitle: "Users and provider access",
    usersDescription:
      "New tenant users cannot use providers until an administrator grants access. Administrators and root always have access.",
    noUsers: "No users",
    noUsersDescription:
      "Users appear here after their first Auth Mini sign-in.",
    displayName: "Display name",
    roleUpdated: "User role updated",
    providerAccess: "Provider access",
    providerAccessUpdated: "Provider access updated",
    alwaysAllowed: "Administrators always allowed",
    runtimeSettings: "Runtime settings",
    runtimeSettingsDescription:
      "These values live in SQLite app_meta. URLs and models apply immediately; body limits apply after restart.",
    saveSettings: "Save settings",
    settingsSaved: "Settings saved",
    imageHostModel: "Image host model",
    oauthAuthorizeUrl: "OAuth authorize URL",
    oauthTokenUrl: "OAuth token URL",
    oauthRedirectUri: "OAuth redirect URI",
    oauthClientId: "OAuth client ID",
    responseLimit: "Responses limit",
    imageLimit: "Image request limit",
    audioLimit: "Audio request limit",
  },
} satisfies Record<Locale, Record<string, string>>

function App({ startupError = "" }: { startupError?: string }) {
  const [locale, setLocale] = useState<Locale>(
    () => (localStorage.getItem("locale") as Locale) || "zh"
  )
  const [bootError, setBootError] = useState(startupError)
  const [sdk, setSdk] = useState<AuthSdk | null>(null)
  const [authenticated, setAuthenticated] = useState(false)
  const [recovering, setRecovering] = useState(true)
  const configQuery = useQuery({
    queryKey: ["config"],
    queryFn: async ({ signal }) => {
      const response = await fetch("/api/config", { signal })
      if (!response.ok)
        throw new Error(`Configuration request failed (${response.status})`)
      return response.json() as Promise<PublicConfig>
    },
  })
  const config = configQuery.data

  useEffect(() => {
    if (!config) return
    let unsubscribe: () => void = () => undefined
    if (config.setup_required) {
      setRecovering(false)
      return
    }
    if (!config.auth_issuer) {
      setBootError("Auth Mini issuer is missing")
      setRecovering(false)
      return
    }
    const next = createBrowserSdk(config.auth_issuer)
    setSdk(next)
    const update = () => {
      const session = next.session.getState()
      setAuthenticated(session.authenticated)
      setRecovering(session.status === "recovering")
    }
    update()
    unsubscribe = next.session.onChange(update)
    return () => unsubscribe()
  }, [config])

  useEffect(() => {
    document.documentElement.lang = locale === "zh" ? "zh-CN" : "en"
  }, [locale])
  const changeLocale = (next: Locale) => {
    localStorage.setItem("locale", next)
    setLocale(next)
  }

  const configError = configQuery.error ? message(configQuery.error) : bootError
  if (!config && !configError) return <CenteredLoading />
  if (configError)
    return (
      <main className="mx-auto flex min-h-svh w-full max-w-2xl items-center p-4">
        <ErrorState message={configError} />
      </main>
    )
  if (!config) return <CenteredLoading />
  if (config?.setup_required)
    return (
      <TooltipProvider>
        <Setup locale={locale} setLocale={changeLocale} />
        <Toaster richColors />
      </TooltipProvider>
    )
  if (recovering || !sdk) return <CenteredLoading />
  return (
    <TooltipProvider>
      {authenticated ? (
        <Console sdk={sdk} locale={locale} setLocale={changeLocale} />
      ) : (
        <Login
          issuer={config.auth_issuer!}
          locale={locale}
          setLocale={changeLocale}
        />
      )}
      <Toaster richColors />
    </TooltipProvider>
  )
}

function Setup({
  locale,
  setLocale,
}: {
  locale: Locale
  setLocale: (locale: Locale) => void
}) {
  const t = copy[locale]
  const [setupDraft] = useState(() => readAuthMiniSetupDraft())
  const [issuer, setIssuer] = useState(setupDraft?.issuer ?? "")
  const [audience, setAudience] = useState(setupDraft?.audience ?? "")
  const [issuerError, setIssuerError] = useState("")
  const [sdk, setSdk] = useState<AuthSdk | null>(() =>
    setupDraft ? createBrowserSdk(setupDraft.issuer) : null
  )
  const [authenticated, setAuthenticated] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!sdk) return
    const update = () => setAuthenticated(sdk.session.getState().authenticated)
    update()
    return sdk.session.onChange(update)
  }, [sdk])

  function connect(event: FormEvent) {
    event.preventDefault()
    setIssuerError("")
    try {
      const normalizedIssuer = normalizeAuthMiniIssuer(issuer)
      setIssuer(normalizedIssuer)
      setSdk(createBrowserSdk(normalizedIssuer))
    } catch {
      setIssuerError(t.setupIssuerHelp)
    }
  }

  async function finish() {
    if (!sdk) return
    setPending(true)
    setError("")
    try {
      await api(sdk, "/api/setup", {
        method: "POST",
        body: JSON.stringify({
          auth_issuer: issuer.trim(),
          auth_audience: audience.trim() || null,
        }),
      })
      clearAuthMiniSetupDraft()
      window.location.reload()
    } catch (cause) {
      setError(message(cause, t))
      setPending(false)
    }
  }

  const steps = [
    [t.setupStepConnect, sdk ? t.setupConnected : t.setupWaiting, Boolean(sdk)],
    [
      t.setupStepLogin,
      authenticated ? t.setupAuthenticated : t.setupWaiting,
      authenticated,
    ],
    [t.setupStepFinish, t.setupWaiting, false],
  ] as const
  return (
    <main className="min-h-svh bg-muted/40 p-4 sm:p-6">
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
        <header className="flex items-start justify-between gap-4 py-2">
          <div className="flex max-w-2xl flex-col gap-1">
            <h1 className="text-2xl font-semibold tracking-tight text-balance">
              {t.setupTitle}
            </h1>
            <p className="text-sm text-pretty text-muted-foreground">
              {t.setupDescription}
            </p>
          </div>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setLocale(locale === "zh" ? "en" : "zh")}
          >
            <LanguagesIcon data-icon="inline-start" />
            {t.english}
          </Button>
        </header>
        <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(22rem,1.15fr)]">
          <Card>
            <CardHeader>
              <CardTitle>{t.title}</CardTitle>
              <CardDescription>{t.setupSecurity}</CardDescription>
            </CardHeader>
            <CardContent>
              <ol className="flex flex-col gap-4">
                {steps.map(([label, status, complete], index) => (
                  <li key={label} className="flex items-center gap-3">
                    <Badge variant={complete ? "secondary" : "outline"}>
                      {index + 1}
                    </Badge>
                    <span className="min-w-0 flex-1 text-sm font-medium">
                      {label}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {status}
                    </span>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>{sdk ? t.setupLogin : t.setupStepConnect}</CardTitle>
              <CardDescription>
                {sdk ? t.setupLoginHelp : t.setupIssuerHelp}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!sdk ? (
                <form onSubmit={connect}>
                  <FieldGroup>
                    <Field data-invalid={Boolean(issuerError)}>
                      <FieldLabel htmlFor="setup-issuer">
                        {t.setupIssuer}
                      </FieldLabel>
                      <Input
                        id="setup-issuer"
                        type="url"
                        inputMode="url"
                        autoComplete="url"
                        placeholder="https://auth.example.com"
                        value={issuer}
                        onChange={(event) => setIssuer(event.target.value)}
                        aria-invalid={Boolean(issuerError)}
                        required
                      />
                      <FieldError>{issuerError}</FieldError>
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="setup-audience">
                        {t.setupAudience}
                      </FieldLabel>
                      <Input
                        id="setup-audience"
                        value={audience}
                        onChange={(event) => setAudience(event.target.value)}
                      />
                    </Field>
                    <Button type="submit" disabled={!issuer.trim()}>
                      {t.connectAuth}
                      <ChevronRightIcon data-icon="inline-end" />
                    </Button>
                  </FieldGroup>
                </form>
              ) : (
                <div className="flex flex-col gap-5">
                  {authenticated ? (
                    <>
                      <Alert>
                        <CheckCircle2Icon />
                        <AlertTitle>{t.setupAuthenticated}</AlertTitle>
                        <AlertDescription>{t.setupLoginHelp}</AlertDescription>
                      </Alert>
                      {error && (
                        <Alert variant="destructive">
                          <ShieldAlertIcon />
                          <AlertTitle>{t.unableLoad}</AlertTitle>
                          <AlertDescription>{error}</AlertDescription>
                        </Alert>
                      )}
                      <Button disabled={pending} onClick={() => void finish()}>
                        {pending && <Spinner data-icon="inline-start" />}
                        {pending ? t.finishingSetup : t.finishSetup}
                      </Button>
                    </>
                  ) : (
                    <HostedAuth
                      issuer={issuer}
                      locale={locale}
                      setupDraft={{ issuer, audience }}
                    />
                  )}
                  <Button
                    variant="ghost"
                    disabled={pending || authenticated}
                    onClick={() => {
                      clearAuthMiniSetupDraft()
                      setAuthenticated(false)
                      setSdk(null)
                    }}
                  >
                    {t.changeAuth}
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </main>
  )
}

function Login({
  issuer,
  locale,
  setLocale,
}: {
  issuer: string
  locale: Locale
  setLocale: (locale: Locale) => void
}) {
  const t = copy[locale]
  return (
    <main className="flex min-h-svh items-center justify-center bg-muted/40 p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="flex items-start justify-between gap-3">
            <div>
              <CardTitle>OpenAI-LB</CardTitle>
              <CardDescription>{t.loginDescription}</CardDescription>
            </div>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setLocale(locale === "zh" ? "en" : "zh")}
            >
              <LanguagesIcon data-icon="inline-start" />
              {t.english}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <HostedAuth issuer={issuer} locale={locale} />
        </CardContent>
      </Card>
    </main>
  )
}

function HostedAuth({
  issuer,
  locale,
  setupDraft,
}: {
  issuer: string
  locale: Locale
  setupDraft?: SetupDraft
}) {
  const t = copy[locale]
  const [error, setError] = useState("")
  function redirect() {
    setError("")
    try {
      startAuthMiniLogin(issuer, setupDraft)
    } catch (cause) {
      setError(message(cause, t))
    }
  }
  return (
    <div className="flex flex-col gap-4">
      <Alert>
        <LogInIcon />
        <AlertTitle>{t.authRedirectTitle}</AlertTitle>
        <AlertDescription>{t.authRedirectHelp}</AlertDescription>
      </Alert>
      {error && (
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>{t.unableLoad}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <Button onClick={redirect}>
        <LogInIcon data-icon="inline-start" />
        {t.continueAuthMini}
      </Button>
    </div>
  )
}

function Console({
  sdk,
  locale,
  setLocale,
}: {
  sdk: AuthSdk
  locale: Locale
  setLocale: (locale: Locale) => void
}) {
  const location = useLocation()
  const navigate = useNavigate()
  const {
    data: user,
    error: userError,
    loading: userLoading,
  } = useApiQuery<User>(sdk, "/api/me")
  const page = pageForPath(location.pathname)
  const t = copy[locale]
  const nav = useMemo(
    () =>
      [
        ["dashboard", CircleGaugeIcon],
        ...(user?.role === "root" || user?.role === "admin"
          ? [["providers", BoxesIcon]]
          : []),
        ["consumers", KeyRoundIcon],
        ["usage", ActivityIcon],
        ["audit", ScrollTextIcon],
        ...(user?.role === "root" || user?.role === "admin"
          ? [["users", UserRoundCogIcon]]
          : []),
        ["settings", SettingsIcon],
      ] as [NavPage, typeof CircleGaugeIcon][],
    [user?.role]
  )
  function toggleLocale() {
    const next = locale === "zh" ? "en" : "zh"
    localStorage.setItem("locale", next)
    setLocale(next)
  }
  return (
    <SidebarProvider>
      <Sidebar collapsible="offcanvas">
        <SidebarHeader className="border-b p-4">
          <div className="flex flex-col gap-0.5">
            <strong className="text-sm">{t.title}</strong>
            <span className="text-xs text-muted-foreground">{t.subtitle}</span>
          </div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>{t.console}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {nav.map(([item, Icon]) => (
                  <SidebarMenuItem key={item}>
                    <SidebarMenuButton
                      isActive={page === item}
                      onClick={() => navigate(`/${item}`)}
                    >
                      <Icon />
                      <span>{t[item]}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
        <SidebarFooter className="border-t p-3">
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton onClick={toggleLocale}>
                <LanguagesIcon />
                <span>{t.english}</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
            <SidebarMenuItem>
              <SidebarMenuButton onClick={() => void sdk.session.logout()}>
                <LogOutIcon />
                <span>{t.signout}</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
      </Sidebar>
      <SidebarInset>
        <header className="sticky top-0 flex h-14 items-center gap-3 border-b bg-background px-4">
          <SidebarTrigger />
          <Separator orientation="vertical" className="h-5!" />
          <span className="text-sm text-muted-foreground">
            {user?.email || user?.id || "—"}
          </span>
          <Badge variant="outline">
            {user ? roleLabel(user.role, locale) : t.roleLoading}
          </Badge>
        </header>
        <div className="flex flex-1 flex-col gap-5 p-4 md:p-6">
          <PageHeader
            title={pageTitle(page, locale)}
            description={pageDescription(page, locale)}
          />
          {userError ? (
            <ErrorState message={message(userError)} />
          ) : userLoading || !user ? (
            <LoadingTable />
          ) : (
            <Routes>
              <Route path="/" element={<Navigate replace to="/dashboard" />} />
              <Route
                path="/dashboard"
                element={<Dashboard sdk={sdk} locale={locale} />}
              />
              <Route
                path="/providers"
                element={<Providers sdk={sdk} locale={locale} />}
              />
              <Route
                path="/consumers"
                element={<Consumers sdk={sdk} locale={locale} />}
              />
              <Route
                path="/usage"
                element={<UsagePage sdk={sdk} locale={locale} user={user} />}
              />
              <Route
                path="/audit"
                element={
                  <AuditPage
                    sdk={sdk}
                    locale={locale}
                    user={user}
                    onOpenDetail={(id) => navigate(`/audit/${id}`)}
                  />
                }
              />
              <Route
                path="/audit/:auditId"
                element={<RequestDetailPage sdk={sdk} locale={locale} />}
              />
              <Route
                path="/users"
                element={<UsersPage sdk={sdk} locale={locale} user={user} />}
              />
              <Route
                path="/settings"
                element={<SettingsPage sdk={sdk} user={user} locale={locale} />}
              />
              <Route path="*" element={<Navigate replace to="/dashboard" />} />
            </Routes>
          )}
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}

function PageHeader({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <div className="flex flex-col gap-1">
      <h1 className="text-2xl font-semibold tracking-tight text-balance">
        {title}
      </h1>
      <p className="max-w-3xl text-sm text-pretty text-muted-foreground">
        {description}
      </p>
    </div>
  )
}

function Dashboard({ sdk, locale }: { sdk: AuthSdk; locale: Locale }) {
  const t = copy[locale]
  const { data, error, loading } = useApiQuery<Record<string, number>>(
    sdk,
    "/api/dashboard"
  )
  if (loading) return <LoadingTable />
  if (error) return <ErrorState message={error} />
  const rows = [
    [t.availableProviders, data?.available_providers],
    [t.activeConsumers, data?.active_consumers],
    [t.calls24h, data?.calls_24h],
    [t.errors24h, data?.errors_24h],
  ]
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t.operationalStatus}</CardTitle>
        <CardDescription>{t.operationalDescription}</CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-2 lg:grid-cols-4">
          {rows.map(([label, value]) => (
            <div
              key={String(label)}
              className="flex flex-col gap-1 bg-background p-4"
            >
              <dt>{label}</dt>
              <dd className="text-2xl font-semibold tabular-nums">
                {value ?? 0}
              </dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  )
}

function Providers({ sdk, locale }: { sdk: AuthSdk; locale: Locale }) {
  const t = copy[locale]
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [oauth, setOauth] = useState<{
    state: string
    authorize_url: string
  } | null>(null)
  const [tokenDialog, setTokenDialog] =
    useState<ProviderTokenDialogState | null>(null)
  const [testState, setTestState] = useState<ProviderTestState | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Provider | null>(null)
  const [deletePending, setDeletePending] = useState(false)
  const tokenRequest = useRef<AbortController | null>(null)
  const testRequest = useRef<AbortController | null>(null)
  const { data, error, loading } = useApiQuery<Provider[]>(sdk, "/api/providers")
  const { data: usageData, error: usageError } =
    useApiQuery<ProviderUsageResponse>(sdk, "/api/providers/usage")
  useEffect(
    () => () => {
      tokenRequest.current?.abort()
      testRequest.current?.abort()
    },
    []
  )
  function refreshProviders() {
    void queryClient.invalidateQueries({ queryKey: ["/api/providers"] })
  }
  async function mutate(id: string, body: object) {
    try {
      await api(sdk, `/api/providers/${id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      })
      refreshProviders()
      toast.success(t.providerUpdated)
    } catch (cause) {
      toast.error(message(cause, t))
    }
  }
  async function openTokens(provider: Provider) {
    tokenRequest.current?.abort()
    const request = new AbortController()
    tokenRequest.current = request
    setTokenDialog({ provider, loading: true })
    try {
      const tokens = await api<ProviderTokens>(
        sdk,
        `/api/providers/${provider.id}`,
        { signal: request.signal }
      )
      if (tokenRequest.current === request)
        setTokenDialog({ provider, loading: false, tokens })
    } catch (cause) {
      if (!isAbortError(cause) && tokenRequest.current === request)
        setTokenDialog({ provider, loading: false, error: message(cause, t) })
    } finally {
      if (tokenRequest.current === request) tokenRequest.current = null
    }
  }
  async function test(provider: Provider) {
    testRequest.current?.abort()
    const request = new AbortController()
    testRequest.current = request
    setTestState({ provider, status: "loading" })
    try {
      const result = await api<{ usage: ProviderUsage }>(
        sdk,
        `/api/providers/${provider.id}/test`,
        { method: "POST", signal: request.signal }
      )
      if (testRequest.current === request) {
        setTestState({ provider, status: "success", usage: result.usage })
        toast.success(t.testSucceeded)
      }
    } catch (cause) {
      if (!isAbortError(cause) && testRequest.current === request)
        setTestState({ provider, status: "error", error: message(cause, t) })
    } finally {
      if (testRequest.current === request) testRequest.current = null
    }
  }
  async function remove() {
    if (!deleteTarget || deletePending) return
    setDeletePending(true)
    try {
      await api(sdk, `/api/providers/${deleteTarget.id}`, { method: "DELETE" })
      setDeleteTarget(null)
      refreshProviders()
      toast.success(t.providerDeleted)
    } catch (cause) {
      toast.error(message(cause, t))
    } finally {
      setDeletePending(false)
    }
  }
  function closeTokens() {
    tokenRequest.current?.abort()
    tokenRequest.current = null
    setTokenDialog(null)
  }
  function closeTest() {
    testRequest.current?.abort()
    testRequest.current = null
    setTestState(null)
  }
  if (loading) return <LoadingTable />
  if (error) return <ErrorState message={error} />
  return (
    <>
      <Card>
        <CardHeader className="flex-row items-start justify-between">
          <div>
            <CardTitle>{t.providerPool}</CardTitle>
            <CardDescription>{t.providerDescription}</CardDescription>
          </div>
          <Button onClick={() => setOpen(true)}>
            <PlusIcon data-icon="inline-start" />
            {t.addProvider}
          </Button>
        </CardHeader>
        <CardContent>
          {!data?.length ? (
            <EmptyState
              icon={<BoxesIcon />}
              title={t.noProviders}
              description={t.noProvidersDescription}
              action={
                <Button onClick={() => setOpen(true)}>{t.addProvider}</Button>
              }
            />
          ) : (
            <DataTable>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t.name}</TableHead>
                    <TableHead>{t.account}</TableHead>
                    <TableHead>{t.usageEmail}</TableHead>
                    <TableHead>{t.usagePlan}</TableHead>
                    <TableHead>{t.quotaRemaining}</TableHead>
                    <TableHead>{t.resetsIn}</TableHead>
                    <TableHead>{t.status}</TableHead>
                    <TableHead>{t.inflight}</TableHead>
                    <TableHead>{t.recoveryReason}</TableHead>
                    <TableHead className="text-right">{t.actions}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.map((provider) => {
                    const entry = usageData?.providers[provider.id]
                    const usage = entry?.usage
                    const quota =
                      usage?.rate_limit?.primary_window ??
                      usage?.rate_limit?.secondary_window
                    return (
                      <TableRow key={provider.id}>
                        <TableCell className="font-medium">
                          {provider.name}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {provider.account_id}
                        </TableCell>
                        <TableCell className="text-xs">
                          {usageEmail(usage) || "—"}
                        </TableCell>
                        <TableCell>{usage?.plan_type || "—"}</TableCell>
                        <TableCell>
                          <QuotaProgress
                            window={quota}
                            label={`${t.quotaRemaining}: ${provider.name}`}
                            unavailable={entry?.error || usageError}
                          />
                        </TableCell>
                        <TableCell className="text-xs tabular-nums">
                          {quotaReset(quota, locale)}
                        </TableCell>
                        <TableCell>
                          <StatusBadge
                            status={provider.status}
                            locale={locale}
                          />
                        </TableCell>
                        <TableCell className="tabular-nums">
                          {provider.inflight}
                        </TableCell>
                        <TableCell className="max-w-64 text-xs text-muted-foreground">
                          {provider.last_error ||
                            (provider.cooldown_until
                              ? formatTime(provider.cooldown_until, locale)
                              : "—")}
                        </TableCell>
                        <TableCell>
                          <div className="flex justify-end gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={
                                tokenDialog?.provider.id === provider.id &&
                                tokenDialog.loading
                              }
                              onClick={() => void openTokens(provider)}
                            >
                              {tokenDialog?.provider.id === provider.id &&
                              tokenDialog.loading ? (
                                <Spinner data-icon="inline-start" />
                              ) : (
                                <KeyRoundIcon data-icon="inline-start" />
                              )}
                              {t.editProvider}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={
                                testState?.provider.id === provider.id &&
                                testState.status === "loading"
                              }
                              onClick={() => void test(provider)}
                            >
                              {testState?.provider.id === provider.id &&
                              testState.status === "loading" ? (
                                <Spinner data-icon="inline-start" />
                              ) : (
                                <ActivityIcon data-icon="inline-start" />
                              )}
                              {t.testProvider}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() =>
                                void mutate(provider.id, { refresh: true })
                              }
                            >
                              <RefreshCwIcon data-icon="inline-start" />
                              {t.refresh}
                            </Button>
                            <Switch
                              aria-label={`${t.status}: ${provider.name}`}
                              checked={!provider.manual_disabled}
                              onCheckedChange={(checked) =>
                                void mutate(provider.id, { enabled: checked })
                              }
                            />
                            <Button
                              size="icon-sm"
                              variant="ghost"
                              aria-label={`${t.deleteProvider}: ${provider.name}`}
                              onClick={() => setDeleteTarget(provider)}
                            >
                              <Trash2Icon />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </DataTable>
          )}
        </CardContent>
      </Card>
      <ProviderDialog
        sdk={sdk}
        locale={locale}
        open={open}
        onOpenChange={setOpen}
        oauth={oauth}
        setOauth={setOauth}
        onDone={() => {
          setOpen(false)
          refreshProviders()
        }}
      />
      <ProviderTokensDialog
        sdk={sdk}
        locale={locale}
        state={tokenDialog}
        onClose={closeTokens}
        onSaved={() => {
          closeTokens()
          refreshProviders()
        }}
      />
      <ProviderTestDialog
        locale={locale}
        state={testState}
        onClose={closeTest}
      />
      <AlertDialog
        open={Boolean(deleteTarget)}
        onOpenChange={(next) =>
          !next && !deletePending && setDeleteTarget(null)
        }
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.deleteProviderTitle}</AlertDialogTitle>
            <AlertDialogDescription>
              {t.deleteProviderDescription}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletePending}>
              {t.cancel}
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deletePending}
              onClick={() => void remove()}
            >
              {deletePending && <Spinner data-icon="inline-start" />}
              {t.confirmDeleteProvider}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

function ProviderTokensDialog({
  sdk,
  locale,
  state,
  onClose,
  onSaved,
}: {
  sdk: AuthSdk
  locale: Locale
  state: ProviderTokenDialogState | null
  onClose: () => void
  onSaved: () => void
}) {
  const t = copy[locale]
  const [name, setName] = useState("")
  const [access, setAccess] = useState("")
  const [refresh, setRefresh] = useState("")
  const [pending, setPending] = useState(false)
  const saveRequest = useRef<AbortController | null>(null)
  useEffect(() => {
    saveRequest.current?.abort()
    saveRequest.current = null
    setPending(false)
    setName(state?.provider.name ?? "")
    setAccess(state?.tokens?.access_key ?? "")
    setRefresh(state?.tokens?.refresh_key ?? "")
  }, [state])
  async function save(event: FormEvent) {
    event.preventDefault()
    if (!state || pending) return
    const request = new AbortController()
    saveRequest.current = request
    setPending(true)
    try {
      await api(sdk, `/api/providers/${state.provider.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name,
          access_key: access,
          refresh_key: refresh,
        }),
        signal: request.signal,
      })
      if (saveRequest.current === request) {
        toast.success(t.tokensSaved)
        onSaved()
      }
    } catch (cause) {
      if (!isAbortError(cause) && saveRequest.current === request)
        toast.error(message(cause, t))
    } finally {
      if (saveRequest.current === request) {
        saveRequest.current = null
        setPending(false)
      }
    }
  }
  function close() {
    saveRequest.current?.abort()
    saveRequest.current = null
    setPending(false)
    onClose()
  }
  return (
    <Dialog open={Boolean(state)} onOpenChange={(next) => !next && close()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {t.tokenTitle}: {state?.provider.name}
          </DialogTitle>
          <DialogDescription>{t.tokenDescription}</DialogDescription>
        </DialogHeader>
        {state?.loading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            {t.loadingTokens}
          </div>
        ) : state?.error ? (
          <ErrorState message={state.error} />
        ) : (
          <form onSubmit={save}>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="edit-provider-name">{t.name}</FieldLabel>
                <Input
                  id="edit-provider-name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="edit-access-key">{t.accessKey}</FieldLabel>
                <Input
                  id="edit-access-key"
                  autoComplete="off"
                  value={access}
                  onChange={(event) => setAccess(event.target.value)}
                  required
                />
                <FieldDescription>{t.accessClaimHelp}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="edit-refresh-key">
                  {t.refreshKey}
                </FieldLabel>
                <Input
                  id="edit-refresh-key"
                  autoComplete="off"
                  value={refresh}
                  onChange={(event) => setRefresh(event.target.value)}
                  required
                />
              </Field>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={close}>
                  {t.cancel}
                </Button>
                <Button
                  type="submit"
                  disabled={
                    pending || !name.trim() || !access.trim() || !refresh.trim()
                  }
                >
                  {pending && <Spinner data-icon="inline-start" />}
                  {t.saveTokens}
                </Button>
              </DialogFooter>
            </FieldGroup>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

function ProviderTestDialog({
  locale,
  state,
  onClose,
}: {
  locale: Locale
  state: ProviderTestState | null
  onClose: () => void
}) {
  const t = copy[locale]
  const usage = state?.usage
  const primary = usage?.rate_limit?.primary_window
  const secondary = usage?.rate_limit?.secondary_window
  const hasSummary = Boolean(
    usageEmail(usage) ||
    usage?.plan_type ||
    primary ||
    secondary ||
    usage?.credits
  )
  return (
    <Dialog open={Boolean(state)} onOpenChange={(next) => !next && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {t.testTitle}: {state?.provider.name}
          </DialogTitle>
          <DialogDescription>{t.testDescription}</DialogDescription>
        </DialogHeader>
        {state?.status === "loading" ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            {t.testingProvider}
          </div>
        ) : state?.status === "error" ? (
          <ErrorState message={state.error || t.unknownError} />
        ) : (
          usage && (
            <div className="flex flex-col gap-4">
              {hasSummary ? (
                <Definition
                  rows={[
                    [t.usageEmail, usageEmail(usage) || "—"],
                    [t.usagePlan, usage.plan_type || "—"],
                    [t.quotaRemaining, remainingPercent(primary ?? secondary)],
                    [t.resetsIn, quotaReset(primary ?? secondary, locale)],
                    [
                      t.credits,
                      usage.credits?.unlimited
                        ? "∞"
                        : (usage.credits?.balance ?? "—"),
                    ],
                  ]}
                />
              ) : (
                <Alert>
                  <AlertTitle>{t.usageUnavailable}</AlertTitle>
                </Alert>
              )}
              <div className="flex flex-col gap-2">
                <h3 className="text-sm font-medium">{t.rawUsage}</h3>
                <ScrollArea className="max-h-72 rounded-lg border bg-muted p-3">
                  <pre className="text-xs break-all whitespace-pre-wrap">
                    {JSON.stringify(usage, null, 2)}
                  </pre>
                </ScrollArea>
              </div>
            </div>
          )
        )}
        <DialogFooter>
          <Button onClick={onClose}>{t.close}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function ProviderDialog({
  sdk,
  locale,
  open,
  onOpenChange,
  oauth,
  setOauth,
  onDone,
}: {
  sdk: AuthSdk
  locale: Locale
  open: boolean
  onOpenChange: (open: boolean) => void
  oauth: { state: string; authorize_url: string } | null
  setOauth: (value: { state: string; authorize_url: string } | null) => void
  onDone: () => void
}) {
  const t = copy[locale]
  const [name, setName] = useState("")
  const [access, setAccess] = useState("")
  const [refresh, setRefresh] = useState("")
  const [code, setCode] = useState("")
  const [pending, setPending] = useState(false)
  async function direct(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    try {
      await api(sdk, "/api/providers", {
        method: "POST",
        body: JSON.stringify({
          name,
          access_key: access,
          refresh_key: refresh,
        }),
      })
      toast.success(t.providerAdded)
      onDone()
    } catch (cause) {
      toast.error(message(cause, t))
    } finally {
      setPending(false)
    }
  }
  async function startOAuth() {
    setPending(true)
    try {
      const value = await api<{ state: string; authorize_url: string }>(
        sdk,
        "/api/oauth/start",
        { method: "POST" }
      )
      setOauth(value)
      window.open(value.authorize_url, "_blank", "noopener,noreferrer")
    } catch (cause) {
      toast.error(message(cause, t))
    } finally {
      setPending(false)
    }
  }
  async function completeOAuth() {
    if (!oauth) return
    setPending(true)
    try {
      await api(sdk, "/api/oauth/complete", {
        method: "POST",
        body: JSON.stringify({ state: oauth.state, code, name }),
      })
      toast.success(t.oauthProviderAdded)
      setOauth(null)
      onDone()
    } catch (cause) {
      toast.error(message(cause, t))
    } finally {
      setPending(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t.addProviderTitle}</DialogTitle>
          <DialogDescription>{t.addProviderDescription}</DialogDescription>
        </DialogHeader>
        <form onSubmit={direct}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="provider-name">{t.name}</FieldLabel>
              <Input
                id="provider-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="access-key">{t.accessKey}</FieldLabel>
              <Input
                id="access-key"
                type="password"
                autoComplete="off"
                value={access}
                onChange={(e) => setAccess(e.target.value)}
              />
              <FieldDescription>{t.accessClaimHelp}</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="refresh-key">{t.refreshKey}</FieldLabel>
              <Input
                id="refresh-key"
                type="password"
                autoComplete="off"
                value={refresh}
                onChange={(e) => setRefresh(e.target.value)}
              />
            </Field>
            {oauth && (
              <Field>
                <FieldLabel htmlFor="oauth-code">{t.oauthCode}</FieldLabel>
                <Input
                  id="oauth-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
                <FieldDescription>{t.oauthStateHelp}</FieldDescription>
              </Field>
            )}
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={pending || !name}
                onClick={() => void startOAuth()}
              >
                {t.startOauth}
                <ChevronRightIcon data-icon="inline-end" />
              </Button>
              {oauth ? (
                <Button
                  type="button"
                  disabled={pending || !code || !name}
                  onClick={() => void completeOAuth()}
                >
                  {pending && <Spinner data-icon="inline-start" />}
                  {t.completeOauth}
                </Button>
              ) : (
                <Button
                  type="submit"
                  disabled={pending || !name || !access || !refresh}
                >
                  {pending && <Spinner data-icon="inline-start" />}
                  {t.importCredentials}
                </Button>
              )}
            </DialogFooter>
          </FieldGroup>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function Consumers({ sdk, locale }: { sdk: AuthSdk; locale: Locale }) {
  const t = copy[locale]
  const queryClient = useQueryClient()
  const [name, setName] = useState("")
  const [open, setOpen] = useState(false)
  const [secret, setSecret] = useState("")
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [editTarget, setEditTarget] = useState<Consumer | null>(null)
  const [editName, setEditName] = useState("")
  const [editPending, setEditPending] = useState(false)
  const { data, error, loading } = useApiQuery<Consumer[]>(sdk, "/api/consumers")
  function refreshConsumers() {
    void queryClient.invalidateQueries({ queryKey: ["/api/consumers"] })
  }
  async function create(event: FormEvent) {
    event.preventDefault()
    try {
      const value = await api<{ secret: string }>(sdk, "/api/consumers", {
        method: "POST",
        body: JSON.stringify({ name }),
      })
      setSecret(value.secret)
      setName("")
      refreshConsumers()
    } catch (cause) {
      toast.error(message(cause, t))
    }
  }
  async function revoke() {
    if (!revokeId) return
    try {
      await api(sdk, `/api/consumers/${revokeId}`, { method: "DELETE" })
      refreshConsumers()
      setRevokeId(null)
      toast.success(t.consumerRevoked)
    } catch (cause) {
      toast.error(message(cause, t))
    }
  }
  function openEdit(consumer: Consumer) {
    setEditTarget(consumer)
    setEditName(consumer.name)
  }
  async function update(event: FormEvent) {
    event.preventDefault()
    if (!editTarget || editPending) return
    setEditPending(true)
    try {
      await api(sdk, `/api/consumers/${editTarget.id}`, {
        method: "PATCH",
        body: JSON.stringify({ name: editName }),
      })
      setEditTarget(null)
      refreshConsumers()
      toast.success(t.consumerUpdated)
    } catch (cause) {
      toast.error(message(cause, t))
    } finally {
      setEditPending(false)
    }
  }
  if (loading) return <LoadingTable />
  if (error) return <ErrorState message={error} />
  return (
    <>
      <Card>
        <CardHeader className="flex-row items-start justify-between">
          <div>
            <CardTitle>{t.consumersTitle}</CardTitle>
            <CardDescription>{t.consumersDescription}</CardDescription>
          </div>
          <Button onClick={() => setOpen(true)}>
            <PlusIcon data-icon="inline-start" />
            {t.create}
          </Button>
        </CardHeader>
        <CardContent>
          {!data?.length ? (
            <EmptyState
              icon={<KeyRoundIcon />}
              title={t.noConsumers}
              description={t.noConsumersDescription}
              action={<Button onClick={() => setOpen(true)}>{t.create}</Button>}
            />
          ) : (
            <DataTable>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t.name}</TableHead>
                    <TableHead>{t.prefix}</TableHead>
                    <TableHead>{t.createdAt}</TableHead>
                    <TableHead>{t.lastUsed}</TableHead>
                    <TableHead>{t.status}</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.map((consumer) => (
                    <TableRow key={consumer.id}>
                      <TableCell className="font-medium">{consumer.name}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {consumer.prefix}…
                      </TableCell>
                      <TableCell>
                        {formatTime(consumer.created_at, locale)}
                      </TableCell>
                      <TableCell>
                        {formatTime(consumer.last_used_at, locale)}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={consumer.revoked_at ? "destructive" : "secondary"}
                        >
                          {consumer.revoked_at ? t.revoked : t.active}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => openEdit(consumer)}
                        >
                          <PencilIcon data-icon="inline-start" />
                          {t.editConsumer}
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={Boolean(consumer.revoked_at)}
                          onClick={() => setRevokeId(consumer.id)}
                        >
                          {t.revoke}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </DataTable>
          )}
        </CardContent>
      </Card>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t.create} {t.consumer}
            </DialogTitle>
            <DialogDescription>{t.consumerAppHelp}</DialogDescription>
          </DialogHeader>
          <form onSubmit={create}>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="consumer-name">{t.name}</FieldLabel>
                <Input
                  id="consumer-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </Field>
              <DialogFooter>
                <Button type="submit" disabled={!name.trim()}>
                  {t.create}
                </Button>
              </DialogFooter>
            </FieldGroup>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog
        open={Boolean(editTarget)}
        onOpenChange={(next) => !next && !editPending && setEditTarget(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t.editConsumer} {t.consumer}
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={update}>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="consumer-edit-name">{t.name}</FieldLabel>
                <Input
                  id="consumer-edit-name"
                  value={editName}
                  onChange={(event) => setEditName(event.target.value)}
                  required
                />
              </Field>
              <DialogFooter>
                <Button
                  type="submit"
                  disabled={editPending || !editName.trim()}
                >
                  {editPending && <Spinner data-icon="inline-start" />}
                  {t.saveConsumer}
                </Button>
              </DialogFooter>
            </FieldGroup>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog
        open={Boolean(secret)}
        onOpenChange={(next) => !next && setSecret("")}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t.saveConsumerTitle}</DialogTitle>
            <DialogDescription>{t.saveConsumerDescription}</DialogDescription>
          </DialogHeader>
          <div className="flex items-center gap-2 rounded-lg border bg-muted p-3">
            <code className="min-w-0 flex-1 text-xs break-all">{secret}</code>
            <Button
              size="icon-sm"
              variant="outline"
              aria-label={t.copied}
              onClick={() =>
                void navigator.clipboard
                  .writeText(secret)
                  .then(() => toast.success(t.copied))
              }
            >
              <ClipboardIcon />
            </Button>
          </div>
          <DialogFooter>
            <Button onClick={() => setSecret("")}>{t.savedConsumer}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <AlertDialog
        open={Boolean(revokeId)}
        onOpenChange={(next) => !next && setRevokeId(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.revokeTitle}</AlertDialogTitle>
            <AlertDialogDescription>
              {t.revokeDescription}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => void revoke()}
            >
              {t.confirmRevoke}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

function UsagePage({
  sdk,
  locale,
  user,
}: {
  sdk: AuthSdk
  locale: Locale
  user: User
}) {
  const t = copy[locale]
  const [period, setPeriod] = useState<UsagePeriod>("24h")
  const [userFilter, setUserFilter] = useState("all")
  const [consumerFilter, setConsumerFilter] = useState("all")
  const [modelFilter, setModelFilter] = useState("all")
  const [rowDimensions, setRowDimensions] = useState<PivotDimension[]>([
    "user",
    "consumer",
    "model",
  ])
  const [columnDimensions, setColumnDimensions] = useState<PivotDimension[]>([
    "date",
  ])
  const [dataFields, setDataFields] = useState<UsageMetric[]>([
    "input_tokens",
    "output_tokens",
    "cached_tokens",
  ])
  const [sorting, setSorting] = useState<SortingState>([])
  const { data, error, loading } = useApiQuery<UsageResponse>(
    sdk,
    `/api/usage?period=${period}`
  )
  const rows = useMemo(() => data?.rows ?? [], [data])
  const fieldLabels = useMemo<Record<PivotDimension, string>>(
    () => ({ user: t.userId, consumer: t.consumerLabel, model: t.model, date: t.date }),
    [t],
  )
  const users = useMemo(
    () => uniqueUsageOptions(rows, (row) => row.user_id, usageUserLabel),
    [rows]
  )
  const consumers = useMemo(
    () => uniqueUsageOptions(rows, (row) => row.consumer_id, usageConsumerLabel),
    [rows]
  )
  const models = useMemo(
    () =>
      uniqueUsageOptions(
        rows,
        (row) => row.model,
        (row) => row.model
      ),
    [rows]
  )
  const filteredRows = useMemo(
    () =>
      rows.filter(
        (row) =>
          (userFilter === "all" || row.user_id === userFilter) &&
          (consumerFilter === "all" || row.consumer_id === consumerFilter) &&
          (modelFilter === "all" || row.model === modelFilter)
      ),
    [rows, userFilter, consumerFilter, modelFilter]
  )
  const pivot = useMemo(
    () =>
      pivotUsageRows(
        filteredRows,
        rowDimensions,
        columnDimensions,
        (row) =>
          columnDimensions
            .map((dimension) => usageDimensionLabel(row, dimension))
            .join(" / ") || t.total
      ),
    [columnDimensions, filteredRows, rowDimensions, t.total]
  )
  const columns = useMemo<ColumnDef<PivotTableRow>[]>(() => {
    const result: ColumnDef<PivotTableRow>[] = rowDimensions.map(
      (dimension) => ({
        id: dimension,
        accessorFn: (row) => usageDimensionLabel(row.values, dimension),
        header: fieldLabels[dimension],
        cell: ({ row }) => (
          <UsageDimensionCell dimension={dimension} row={row.original.values} />
        ),
      })
    )
    if (!result.length)
      result.push({ id: "total", header: t.total, cell: () => t.total })
    for (const pivotColumn of pivot.columns) {
      result.push({
        id: `column-${pivotColumn.id}`,
        header: pivotColumn.label,
        columns: dataFields.map((field) => ({
          id: `${pivotColumn.id}-${field}`,
          accessorFn: (row) => row.cells[pivotColumn.id]?.[field] ?? 0,
          header: usageAggregateLabel(field, t),
          cell: (info) => (
            <span className="tabular-nums">
              {Number(info.getValue()).toLocaleString(locale)}
            </span>
          ),
        })),
      })
    }
    return result
  }, [dataFields, fieldLabels, locale, pivot.columns, rowDimensions, t])
  // TanStack Table owns mutable table state, so React Compiler must not memoize this hook.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: pivot.rows,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })
  function assignDimension(
    dimension: PivotDimension,
    placement: PivotPlacement
  ) {
    setRowDimensions((current) =>
      placement === "rows"
        ? appendPivotDimension(current, dimension)
        : current.filter((item) => item !== dimension)
    )
    setColumnDimensions((current) =>
      placement === "columns"
        ? appendPivotDimension(current, dimension)
        : current.filter((item) => item !== dimension)
    )
  }
  const clearFilters = () => {
    setUserFilter("all")
    setConsumerFilter("all")
    setModelFilter("all")
  }
  if (loading) return <LoadingTable />
  if (error) return <ErrorState message={error} />
  return (
    <Card>
      <CardHeader className="gap-4">
        <div>
          <CardTitle>{t.usageTitle}</CardTitle>
          <CardDescription>{t.usageDescription}</CardDescription>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {(["24h", "7d"] as UsagePeriod[]).map((value) => (
            <Button
              key={value}
              size="sm"
              variant={period === value ? "default" : "outline"}
              aria-pressed={period === value}
              onClick={() => setPeriod(value)}
            >
              {value === "24h" ? t.last24Hours : t.last7Days}
            </Button>
          ))}
          {user.role !== "user" && (
            <UsageSelect
              ariaLabel={t.userId}
              value={userFilter}
              onValueChange={setUserFilter}
              allLabel={t.allUsers}
              options={users}
            />
          )}
          <UsageSelect
            ariaLabel={t.consumerLabel}
            value={consumerFilter}
            onValueChange={setConsumerFilter}
            allLabel={t.allConsumers}
            options={consumers}
          />
          <UsageSelect
            ariaLabel={t.model}
            value={modelFilter}
            onValueChange={setModelFilter}
            allLabel={t.allModels}
            options={models}
          />
        </div>
        <div className="grid gap-3 border-t pt-3 text-xs xl:grid-cols-[1fr_1fr_auto] xl:items-start">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground">{t.pivotFields}</span>
            {pivotDimensions.map((dimension) => (
              <PivotFieldAssignment
                key={dimension}
                label={fieldLabels[dimension]}
                placement={pivotPlacement(
                  dimension,
                  rowDimensions,
                  columnDimensions
                )}
                onChange={(placement) => assignDimension(dimension, placement)}
                rowsLabel={t.rows}
                columnsLabel={t.columns}
                hiddenLabel={t.hidden}
              />
            ))}
          </div>
          <div className="flex flex-col gap-1.5">
            <PivotOrder
              label={t.rows}
              dimensions={rowDimensions}
              labels={fieldLabels}
              onChange={setRowDimensions}
            />
            <PivotOrder
              label={t.columns}
              dimensions={columnDimensions}
              labels={fieldLabels}
              onChange={setColumnDimensions}
            />
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-muted-foreground">{t.data}</span>
            {usageMetrics.map((field) => (
              <Button
                key={field}
                size="xs"
                variant={dataFields.includes(field) ? "secondary" : "ghost"}
                aria-pressed={dataFields.includes(field)}
                onClick={() =>
                  setDataFields((current) => toggleUsageMetric(current, field))
                }
              >
                {usageAggregateLabel(field, t)}
              </Button>
            ))}
          </div>
        </div>
        <span className="text-xs text-muted-foreground tabular-nums">
          {pivot.rows.length.toLocaleString(locale)} {t.usageRows}
        </span>
      </CardHeader>
      <CardContent>
        {!rows.length || !filteredRows.length ? (
          <EmptyState
            icon={<SlidersHorizontalIcon />}
            title={t.noUsage}
            description={t.noUsageDescription}
            action={
              filteredRows.length ? undefined : (
                <Button variant="outline" onClick={clearFilters}>
                  {t.clearFilters}
                </Button>
              )
            }
          />
        ) : (
          <DataTable>
            <Table>
              <TableHeader>
                {table.getHeaderGroups().map((headerGroup) => (
                  <TableRow key={headerGroup.id}>
                    {headerGroup.headers.map((header) => (
                      <TableHead key={header.id}>
                        {header.isPlaceholder ? null : header.column.getCanSort() ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="-ml-2"
                            onClick={header.column.getToggleSortingHandler()}
                            aria-label={`${t.sortColumn}: ${String(header.column.columnDef.header)}`}
                          >
                            <span>
                              {flexRender(
                                header.column.columnDef.header,
                                header.getContext()
                              )}
                            </span>
                            <ArrowDownUpIcon />
                          </Button>
                        ) : (
                          <span className="px-0.5">
                            {flexRender(
                              header.column.columnDef.header,
                              header.getContext()
                            )}
                          </span>
                        )}
                      </TableHead>
                    ))}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {table.getRowModel().rows.map((row) => (
                  <TableRow key={row.id}>
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id}>
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext()
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataTable>
        )}
      </CardContent>
    </Card>
  )
}

function UsageSelect({
  ariaLabel,
  value,
  onValueChange,
  allLabel,
  options,
}: {
  ariaLabel: string
  value: string
  onValueChange: (value: string) => void
  allLabel: string
  options: [string, string][]
}) {
  return (
    <Select
      value={value}
      onValueChange={(next) => {
        if (next) onValueChange(next)
      }}
    >
      <SelectTrigger className="max-w-52" aria-label={ariaLabel}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          <SelectItem value="all">{allLabel}</SelectItem>
          {options.map(([optionValue, label]) => (
            <SelectItem key={optionValue} value={optionValue}>
              {label}
            </SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}

function PivotFieldAssignment({
  label,
  placement,
  onChange,
  rowsLabel,
  columnsLabel,
  hiddenLabel,
}: {
  label: string
  placement: PivotPlacement
  onChange: (placement: PivotPlacement) => void
  rowsLabel: string
  columnsLabel: string
  hiddenLabel: string
}) {
  return (
    <Select
      value={placement}
      onValueChange={(value) => {
        if (value) onChange(value as PivotPlacement)
      }}
    >
      <SelectTrigger size="sm" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          <SelectItem value="rows">
            {label} · {rowsLabel}
          </SelectItem>
          <SelectItem value="columns">
            {label} · {columnsLabel}
          </SelectItem>
          <SelectItem value="hidden">
            {label} · {hiddenLabel}
          </SelectItem>
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}

function PivotOrder({
  label,
  dimensions,
  labels,
  onChange,
}: {
  label: string
  dimensions: PivotDimension[]
  labels: Record<PivotDimension, string>
  onChange: (dimensions: PivotDimension[]) => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-1">
      <span className="mr-1 text-muted-foreground">{label}</span>
      {dimensions.length ? (
        dimensions.map((dimension, index) => (
          <span
            key={dimension}
            className="inline-flex items-center rounded-md border bg-muted/50 pl-2"
          >
            <span>{labels[dimension]}</span>
            <Button
              size="icon-xs"
              variant="ghost"
              aria-label={`${label}: ${labels[dimension]} ←`}
              disabled={index === 0}
              onClick={() =>
                onChange(movePivotDimension(dimensions, index, -1))
              }
            >
              <ChevronLeftIcon />
            </Button>
            <Button
              size="icon-xs"
              variant="ghost"
              aria-label={`${label}: ${labels[dimension]} →`}
              disabled={index === dimensions.length - 1}
              onClick={() => onChange(movePivotDimension(dimensions, index, 1))}
            >
              <ChevronRightIcon />
            </Button>
          </span>
        ))
      ) : (
        <span className="text-muted-foreground">—</span>
      )}
    </div>
  )
}

function UsageDimensionCell({
  dimension,
  row,
}: {
  dimension: PivotDimension
  row: UsageRow
}) {
  if (dimension === "user")
    return (
      <div className="flex flex-col">
        <span className="font-medium">{usageUserLabel(row)}</span>
        <code>{row.user_id}</code>
      </div>
    )
  if (dimension === "consumer")
    return (
      <div className="flex flex-col">
        <span className="font-medium">{row.consumer_name}</span>
        <code>{row.consumer_prefix}…</code>
      </div>
    )
  return <code>{usageDimensionLabel(row, dimension)}</code>
}

function AuditPage({
  sdk,
  locale,
  user,
  onOpenDetail,
}: {
  sdk: AuthSdk
  locale: Locale
  user: User
  onOpenDetail: (id: string) => void
}) {
  const t = copy[locale]
  const { data, error, loading } = useApiQuery<Audit[]>(
    sdk,
    "/api/audit?limit=200"
  )
  async function openDetail(row: Audit) {
    onOpenDetail(row.id)
  }
  if (loading) return <LoadingTable />
  if (error) return <ErrorState message={error} />
  return (
    <div className="flex flex-col gap-5">
      <Card>
        <CardHeader>
          <CardTitle>{t.auditTitle}</CardTitle>
          <CardDescription>{t.auditDescription}</CardDescription>
        </CardHeader>
        <CardContent>
          {!data?.length ? (
            <EmptyState
              icon={<ScrollTextIcon />}
              title={t.noAudit}
              description={t.noAuditDescription}
            />
          ) : (
            <DataTable>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t.time}</TableHead>
                    <TableHead>{t.endpointModel}</TableHead>
                    <TableHead>{t.consumer}</TableHead>
                    <TableHead>{t.userId}</TableHead>
                    <TableHead>{t.provider}</TableHead>
                    <TableHead>{t.status}</TableHead>
                    <TableHead>{t.usage}</TableHead>
                    <TableHead className="text-right">{t.actions}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell className="whitespace-nowrap">
                        {formatTime(row.created_at, locale)}
                      </TableCell>
                      <TableCell>
                        <div className="flex max-w-56 flex-col gap-0.5">
                          <span className="font-medium">{row.path}</span>
                          <code>{row.model || "—"}</code>
                          <code
                            title={row.request_id}
                            aria-label={`${t.requestId}: ${row.request_id}`}
                          >
                            {row.request_id.slice(0, 12)}…
                          </code>
                        </div>
                      </TableCell>
                      <TableCell className="font-medium">
                        {row.consumer_name}
                      </TableCell>
                      <TableCell>
                        <code>{row.user_id}</code>
                      </TableCell>
                      <TableCell title={row.provider_id}>
                        {row.provider_name || "—"}
                      </TableCell>
                      <TableCell>
                        <div className="flex max-w-48 flex-col gap-1">
                          <Badge
                            className="w-fit"
                            variant={
                              row.status >= 400 ? "destructive" : "secondary"
                            }
                          >
                            {row.status}
                          </Badge>
                          <span className="text-xs text-muted-foreground tabular-nums">
                            {formatLatency(row.latency_ms)}
                          </span>
                          {row.error && (
                            <span className="text-xs text-destructive">
                              {row.error}
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-3 text-xs tabular-nums">
                          <div className="flex flex-col gap-0.5">
                            <span className="text-muted-foreground">
                              {t.input}
                            </span>
                            <span>{row.input_tokens.toLocaleString()}</span>
                          </div>
                          <div className="flex flex-col gap-0.5">
                            <span className="text-muted-foreground">
                              {t.cachedInput}
                            </span>
                            <span>{row.cached_tokens.toLocaleString()}</span>
                          </div>
                          <div className="flex flex-col gap-0.5">
                            <span className="text-muted-foreground">
                              {t.output}
                            </span>
                            <span>{row.output_tokens.toLocaleString()}</span>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => void openDetail(row)}
                        >
                          {t.details}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </DataTable>
          )}
        </CardContent>
      </Card>
      {user.role !== "user" && <AdminAuditSection sdk={sdk} locale={locale} />}
    </div>
  )
}

function RequestDetailPage({ sdk, locale }: { sdk: AuthSdk; locale: Locale }) {
  const { auditId } = useParams()
  const navigate = useNavigate()
  const t = copy[locale]
  const { data, error, loading } = useApiQuery<AuditDetail>(
    sdk,
    "/api/audit/" + (auditId || "")
  )
  if (!auditId) return <ErrorState message={t.unknownError} />
  if (loading) return <LoadingTable />
  if (error) return <ErrorState message={error} />
  if (!data) return <ErrorState message={t.unknownError} />
  const request = parseJson(data.request_body)
  const affinityId = affinityRequestId(request, data.affinity_source)
  return (
    <div className="flex max-w-6xl flex-col gap-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Button variant="outline" onClick={() => navigate("/audit")}>
          <ChevronLeftIcon data-icon="inline-start" />
          {t.backToAudit}
        </Button>
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={!data.previous}
            onClick={() =>
              data.previous && navigate(`/audit/${data.previous.id}`)
            }
          >
            <ChevronLeftIcon data-icon="inline-start" />
            {t.previousRequest}
          </Button>
          <Button
            variant="outline"
            disabled={!data.next}
            onClick={() => data.next && navigate(`/audit/${data.next.id}`)}
          >
            {t.nextRequest}
            <ChevronRightIcon data-icon="inline-end" />
          </Button>
        </div>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>{data.path}</CardTitle>
          <CardDescription>
            {formatTime(data.created_at, locale)} ·{" "}
            {formatLatency(data.latency_ms)}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Definition
            rows={[
              [t.requestId, data.request_id],
              [t.consumer, data.consumer_name],
              [t.userId, data.user_id],
              [t.provider, data.provider_name || data.provider_id || "—"],
              [t.endpointModel, data.model || "—"],
              [t.status, data.status],
              [t.affinitySource, data.affinity_source || "—"],
              [t.affinityRequestId, affinityId || "—"],
              [t.affinityHash, data.affinity_hash || "—"],
            ]}
          />
        </CardContent>
      </Card>
      {data.path === "/v1/responses" && data.archive_available ? (
        <ResponsesRequest request={request} locale={locale} />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>{t.requestBody}</CardTitle>
            <CardDescription>{t.auditDetailDescription}</CardDescription>
          </CardHeader>
          <CardContent>
            {data.archive_available ? (
              <DiagnosticPreview
                title={t.rawRequest}
                value={data.request_body}
                truncated={data.request_body_truncated}
              />
            ) : (
              <EmptyState
                icon={<ScrollTextIcon />}
                title={t.auditArchiveUnavailable}
                description={t.auditDetailDescription}
              />
            )}
          </CardContent>
        </Card>
      )}
      {data.archive_available && (
        <Card>
          <CardHeader>
            <CardTitle>{t.responseBody}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col gap-5">
              <DiagnosticPreview
                title={t.requestHeaders}
                value={data.request_headers}
              />
              <DiagnosticPreview
                title={t.responseHeaders}
                value={data.response_headers}
              />
              <DiagnosticPreview
                title={t.responseBody}
                value={data.response_body}
                truncated={data.response_body_truncated}
              />
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function ResponsesRequest({
  request,
  locale,
}: {
  request: unknown
  locale: Locale
}) {
  const t = copy[locale]
  const record = recordValue(request)
  if (!record)
    return (
      <Card>
        <CardHeader>
          <CardTitle>{t.messages}</CardTitle>
        </CardHeader>
        <CardContent>
          <DiagnosticPreview
            title={t.rawRequest}
            value={typeof request === "string" ? request : undefined}
          />
        </CardContent>
      </Card>
    )
  const input = record.input
  const settings = [
    ["model", record.model],
    ["stream", record.stream],
    ["store", record.store],
    [t.instructions, record.instructions],
    [t.tools, record.tools],
  ]
  return (
    <div className="flex flex-col gap-5">
      <Card>
        <CardHeader>
          <CardTitle>{t.requestSettings}</CardTitle>
        </CardHeader>
        <CardContent>
          <Definition
            rows={settings
              .filter(([, value]) => value !== undefined)
              .map(([label, value]) => [String(label), structuredValue(value)])}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{t.messages}</CardTitle>
          <CardDescription>
            {t.affinityRequestId}:{" "}
            {affinityRequestId(request, "previous_response_id") || "—"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {input === undefined ? (
            <DiagnosticPreview
              title={t.rawRequest}
              value={JSON.stringify(record, null, 2)}
            />
          ) : (
            <ResponseMessages input={input} locale={locale} />
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function ResponseMessages({
  input,
  locale,
}: {
  input: unknown
  locale: Locale
}) {
  const t = copy[locale]
  const messages = Array.isArray(input) ? input : [input]
  return (
    <div className="flex flex-col gap-3">
      {messages.map((message, index) => {
        const record = recordValue(message)
        const role =
          typeof record?.role === "string"
            ? record.role
            : typeof record?.type === "string"
              ? record.type
              : "input"
        const content = record?.content ?? message
        return (
          <section key={index} className="rounded-md border">
            <div className="flex items-center gap-2 border-b bg-muted px-3 py-2">
              <Badge variant="secondary">{role}</Badge>
              <span className="text-xs text-muted-foreground">
                #{index + 1}
              </span>
            </div>
            <div className="p-3">
              <ResponseContent value={content} label={t.requestBody} />
            </div>
          </section>
        )
      })}
    </div>
  )
}

function ResponseContent({ value, label }: { value: unknown; label: string }) {
  if (typeof value === "string")
    return (
      <pre className="font-mono text-xs break-words whitespace-pre-wrap">
        {value}
      </pre>
    )
  if (Array.isArray(value))
    return (
      <div className="flex flex-col gap-3">
        {value.map((part, index) => {
          const record = recordValue(part)
          const type = typeof record?.type === "string" ? record.type : label
          const text = record?.text
          return (
            <div key={index} className="flex flex-col gap-2">
              <Badge className="w-fit" variant="outline">
                {type}
              </Badge>
              <ResponseContent value={text ?? part} label={label} />
            </div>
          )
        })}
      </div>
    )
  return (
    <pre className="font-mono text-xs break-all whitespace-pre-wrap">
      {structuredValue(value)}
    </pre>
  )
}

function DiagnosticPreview({
  title,
  value,
  truncated = false,
}: {
  title: string
  value?: string
  truncated?: boolean
}) {
  const t = currentMessages()
  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-medium">{title}</h3>
        {truncated && <Badge variant="secondary">{t.previewTruncated}</Badge>}
      </div>
      <pre className="max-h-80 overflow-auto rounded-md border bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap">
        {value || "—"}
      </pre>
    </section>
  )
}

function UsersPage({
  sdk,
  locale,
  user,
}: {
  sdk: AuthSdk
  locale: Locale
  user: User
}) {
  const t = copy[locale]
  const queryClient = useQueryClient()
  const { data, error, loading } = useApiQuery<ManagedUser[]>(sdk, "/api/users")
  function refreshUsers() {
    void queryClient.invalidateQueries({ queryKey: ["/api/users"] })
  }
  async function updateRole(id: string, role: "admin" | "user") {
    try {
      await api(sdk, `/api/users/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ role }),
      })
      refreshUsers()
      toast.success(t.roleUpdated)
    } catch (cause) {
      toast.error(message(cause, t))
    }
  }
  async function updateProviderAccess(id: string, provider_access: boolean) {
    try {
      await api(sdk, `/api/users/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ provider_access }),
      })
      refreshUsers()
      toast.success(t.providerAccessUpdated)
    } catch (cause) {
      toast.error(message(cause, t))
    }
  }
  if (loading) return <LoadingTable />
  if (error) return <ErrorState message={error} />
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t.usersTitle}</CardTitle>
        <CardDescription>{t.usersDescription}</CardDescription>
      </CardHeader>
      <CardContent>
        {!data?.length ? (
          <EmptyState
            icon={<UserRoundCogIcon />}
            title={t.noUsers}
            description={t.noUsersDescription}
          />
        ) : (
          <DataTable>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t.email}</TableHead>
                  <TableHead>{t.displayName}</TableHead>
                  <TableHead>{t.userId}</TableHead>
                  <TableHead>{t.createdAt}</TableHead>
                  <TableHead>{t.role}</TableHead>
                  <TableHead>{t.providerAccess}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>{item.email || "—"}</TableCell>
                    <TableCell>{item.display_name || "—"}</TableCell>
                    <TableCell>
                      <code>{item.id}</code>
                    </TableCell>
                    <TableCell>{formatTime(item.created_at, locale)}</TableCell>
                    <TableCell>
                      {user.role === "root" && item.role !== "root" ? (
                        <Select
                          value={item.role}
                          onValueChange={(value) =>
                            void updateRole(item.id, value as "admin" | "user")
                          }
                        >
                          <SelectTrigger
                            aria-label={`${t.role}: ${item.email || item.id}`}
                          >
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectGroup>
                              <SelectItem value="admin">
                                {t.roleAdmin}
                              </SelectItem>
                              <SelectItem value="user">{t.roleUser}</SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      ) : (
                        <Badge variant="secondary">
                          {roleLabel(item.role, locale)}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {item.role === "user" ? (
                        <Switch
                          aria-label={`${t.providerAccess}: ${item.email || item.id}`}
                          checked={item.provider_access}
                          onCheckedChange={(checked) =>
                            void updateProviderAccess(item.id, checked)
                          }
                        />
                      ) : (
                        <div className="flex items-center gap-2">
                          <Switch
                            aria-label={`${t.providerAccess}: ${item.email || item.id}`}
                            checked
                            disabled
                          />
                          <span className="text-xs text-muted-foreground">
                            {t.alwaysAllowed}
                          </span>
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataTable>
        )}
      </CardContent>
    </Card>
  )
}

function SettingsPage({
  sdk,
  user,
  locale,
}: {
  sdk: AuthSdk
  user: User
  locale: Locale
}) {
  const t = copy[locale]
  const { data, error, loading } = useApiQuery<SettingsData>(
    sdk,
    "/api/settings"
  )
  if (loading) return <LoadingTable />
  if (error) return <ErrorState message={error} />
  if (!data) return <ErrorState message={t.unknownError} />
  return (
    <div className="flex max-w-4xl flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{t.identityPermissions}</CardTitle>
          <CardDescription>{t.identityDescription}</CardDescription>
        </CardHeader>
        <CardContent>
          <Definition
            rows={[
              [t.userId, user.id],
              [t.email, user.email || "—"],
              [t.role, roleLabel(user.role, locale)],
              [t.authIssuer, data.auth_issuer],
            ]}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{t.proxyBoundary}</CardTitle>
          <CardDescription>{t.proxyDescription}</CardDescription>
        </CardHeader>
        <CardContent>
          <Definition
            rows={[
              [t.upstream, data.upstream_base],
              [
                t.bodyLimit,
                `${data.response_body_limit} / ${data.image_body_limit} / ${data.audio_body_limit} bytes`,
              ],
              [t.affinityTtl, `${data.affinity_ttl_seconds} s`],
            ]}
          />
        </CardContent>
      </Card>
      {user.role === "root" && (
        <RuntimeSettings sdk={sdk} locale={locale} initial={data} />
      )}
    </div>
  )
}

function RuntimeSettings({
  sdk,
  locale,
  initial,
}: {
  sdk: AuthSdk
  locale: Locale
  initial: SettingsData
}) {
  const t = copy[locale]
  const [settings, setSettings] = useState(initial)
  const [pending, setPending] = useState(false)
  function update<K extends keyof SettingsData>(
    key: K,
    value: SettingsData[K]
  ) {
    setSettings((current) => ({ ...current, [key]: value }))
  }
  async function save(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    try {
      await api(sdk, "/api/settings", {
        method: "PATCH",
        body: JSON.stringify(settings),
      })
      toast.success(t.settingsSaved)
    } catch (cause) {
      toast.error(message(cause, t))
    } finally {
      setPending(false)
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t.runtimeSettings}</CardTitle>
        <CardDescription>{t.runtimeSettingsDescription}</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={save}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="settings-upstream">{t.upstream}</FieldLabel>
              <Input
                id="settings-upstream"
                type="url"
                value={settings.upstream_base}
                onChange={(event) =>
                  update("upstream_base", event.target.value)
                }
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="settings-image-model">
                {t.imageHostModel}
              </FieldLabel>
              <Input
                id="settings-image-model"
                value={settings.image_host_model}
                onChange={(event) =>
                  update("image_host_model", event.target.value)
                }
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="settings-authorize-url">
                {t.oauthAuthorizeUrl}
              </FieldLabel>
              <Input
                id="settings-authorize-url"
                type="url"
                value={settings.oauth_authorize_url}
                onChange={(event) =>
                  update("oauth_authorize_url", event.target.value)
                }
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="settings-token-url">
                {t.oauthTokenUrl}
              </FieldLabel>
              <Input
                id="settings-token-url"
                type="url"
                value={settings.oauth_token_url}
                onChange={(event) =>
                  update("oauth_token_url", event.target.value)
                }
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="settings-redirect-uri">
                {t.oauthRedirectUri}
              </FieldLabel>
              <Input
                id="settings-redirect-uri"
                type="url"
                value={settings.oauth_redirect_uri}
                onChange={(event) =>
                  update("oauth_redirect_uri", event.target.value)
                }
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="settings-client-id">
                {t.oauthClientId}
              </FieldLabel>
              <Input
                id="settings-client-id"
                value={settings.oauth_client_id}
                onChange={(event) =>
                  update("oauth_client_id", event.target.value)
                }
                required
              />
            </Field>
            <FieldGroup className="grid gap-4 sm:grid-cols-2">
              <Field>
                <FieldLabel htmlFor="settings-response-limit">
                  {t.responseLimit}
                </FieldLabel>
                <Input
                  id="settings-response-limit"
                  type="number"
                  min={1024}
                  max={16777216}
                  value={settings.response_body_limit}
                  onChange={(event) =>
                    update("response_body_limit", event.target.valueAsNumber)
                  }
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="settings-image-limit">
                  {t.imageLimit}
                </FieldLabel>
                <Input
                  id="settings-image-limit"
                  type="number"
                  min={1024}
                  max={16777216}
                  value={settings.image_body_limit}
                  onChange={(event) =>
                    update("image_body_limit", event.target.valueAsNumber)
                  }
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="settings-audio-limit">
                  {t.audioLimit}
                </FieldLabel>
                <Input
                  id="settings-audio-limit"
                  type="number"
                  min={1048576}
                  max={2000000000}
                  value={settings.audio_body_limit}
                  onChange={(event) =>
                    update("audio_body_limit", event.target.valueAsNumber)
                  }
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="settings-affinity-ttl">
                  {t.affinityTtl}
                </FieldLabel>
                <Input
                  id="settings-affinity-ttl"
                  type="number"
                  min={60}
                  max={2592000}
                  value={settings.affinity_ttl_seconds}
                  onChange={(event) =>
                    update("affinity_ttl_seconds", event.target.valueAsNumber)
                  }
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="settings-archive-retention">
                  {locale === "zh"
                    ? "请求/响应诊断记录保留天数"
                    : "Request/response diagnostic retention (days)"}
                </FieldLabel>
                <Input
                  id="settings-archive-retention"
                  type="number"
                  min={1}
                  max={365}
                  value={settings.request_archive_retention_days}
                  onChange={(event) =>
                    update(
                      "request_archive_retention_days",
                      event.target.valueAsNumber
                    )
                  }
                  required
                />
              </Field>
            </FieldGroup>
            <Button className="self-start" type="submit" disabled={pending}>
              {pending && <Spinner data-icon="inline-start" />}
              {t.saveSettings}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}

function AdminAuditSection({ sdk, locale }: { sdk: AuthSdk; locale: Locale }) {
  const t = copy[locale]
  const { data, error, loading } = useApiQuery<AdminAudit[]>(
    sdk,
    "/api/admin-audit?limit=200"
  )
  if (loading) return <LoadingTable />
  if (error) return <ErrorState message={error} />
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t.adminAuditTitle}</CardTitle>
        <CardDescription>{t.adminAuditDescription}</CardDescription>
      </CardHeader>
      <CardContent>
        {!data?.length ? (
          <EmptyState
            icon={<ShieldAlertIcon />}
            title={t.noAudit}
            description={t.noAuditDescription}
          />
        ) : (
          <DataTable>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t.time}</TableHead>
                  <TableHead>{t.administrator}</TableHead>
                  <TableHead>{t.action}</TableHead>
                  <TableHead>{t.target}</TableHead>
                  <TableHead>{t.clientIp}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell>{formatTime(row.created_at, locale)}</TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span>{row.admin_email || row.admin_user_id}</span>
                        <code>{row.admin_user_id}</code>
                      </div>
                    </TableCell>
                    <TableCell>
                      <code>{row.action}</code>
                    </TableCell>
                    <TableCell>
                      <code>{row.target_id || "—"}</code>
                    </TableCell>
                    <TableCell>
                      <code>{row.client_ip || "—"}</code>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataTable>
        )}
      </CardContent>
    </Card>
  )
}

type PivotDimension = "user" | "consumer" | "model" | "date"
type PivotPlacement = "rows" | "columns" | "hidden"
type UsageMetric = keyof PivotCell

const pivotDimensions: PivotDimension[] = ["user", "consumer", "model", "date"]
const usageMetrics: UsageMetric[] = [
  "input_tokens",
  "output_tokens",
  "cached_tokens",
]

function usageUserLabel(row: UsageRow) {
  return row.user_name || row.user_email || row.user_id
}
function usageConsumerLabel(row: UsageRow) {
  return `${row.consumer_name} · ${row.consumer_prefix}…`
}
function usageDimensionLabel(row: UsageRow, dimension: PivotDimension) {
  return dimension === "user"
    ? usageUserLabel(row)
    : dimension === "consumer"
      ? usageConsumerLabel(row)
      : row[dimension]
}
function usageAggregateLabel(metric: UsageMetric, t: typeof copy.zh) {
  return `SUM(${metric === "input_tokens" ? t.inputTokens : metric === "cached_tokens" ? t.cachedInputTokens : t.outputTokens})`
}
function uniqueUsageOptions(
  rows: UsageRow[],
  value: (row: UsageRow) => string,
  label: (row: UsageRow) => string
): [string, string][] {
  return [...new Map(rows.map((row) => [value(row), label(row)])).entries()]
}
function pivotPlacement(
  dimension: PivotDimension,
  rows: PivotDimension[],
  columns: PivotDimension[]
): PivotPlacement {
  return rows.includes(dimension)
    ? "rows"
    : columns.includes(dimension)
      ? "columns"
      : "hidden"
}
function appendPivotDimension(
  dimensions: PivotDimension[],
  dimension: PivotDimension
) {
  return dimensions.includes(dimension)
    ? dimensions
    : [...dimensions, dimension]
}
function movePivotDimension(
  dimensions: PivotDimension[],
  index: number,
  distance: number
) {
  const next = [...dimensions]
  const target = index + distance
  ;[next[index], next[target]] = [next[target], next[index]]
  return next
}
function toggleUsageMetric(metrics: UsageMetric[], metric: UsageMetric) {
  return metrics.length === 1 && metrics.includes(metric)
    ? metrics
    : metrics.includes(metric)
    ? metrics.filter((item) => item !== metric)
    : [...metrics, metric]
}
function pivotUsageRows(
  rows: UsageRow[],
  rowDimensions: PivotDimension[],
  columnDimensions: PivotDimension[],
  label: (row: UsageRow) => string
) {
  const columns = new Map<string, PivotColumn>()
  const grouped = new Map<string, PivotTableRow>()
  for (const row of rows) {
    const rowId = usagePivotKey(row, rowDimensions)
    const columnId = usagePivotKey(row, columnDimensions)
    columns.set(columnId, { id: columnId, label: label(row) })
    const pivotRow = grouped.get(rowId) ?? { id: rowId, values: row, cells: {} }
    const cell = pivotRow.cells[columnId] ?? {
      input_tokens: 0,
      cached_tokens: 0,
      output_tokens: 0,
    }
    cell.input_tokens += row.input_tokens
    cell.cached_tokens += row.cached_tokens
    cell.output_tokens += row.output_tokens
    pivotRow.cells[columnId] = cell
    grouped.set(rowId, pivotRow)
  }
  return {
    rows: [...grouped.values()],
    columns: [...columns.values()].sort((left, right) =>
      left.label.localeCompare(right.label)
    ),
  }
}
function usagePivotKey(row: UsageRow, dimensions: PivotDimension[]) {
  return (
    dimensions
      .map((dimension) => usageDimensionLabel(row, dimension))
      .join("\u001f") || "total"
  )
}
function parseJson(value?: string): unknown {
  if (!value) return undefined
  try {
    return JSON.parse(value)
  } catch {
    return value
  }
}
function recordValue(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}
function structuredValue(value: unknown): string {
  return typeof value === "string"
    ? value
    : JSON.stringify(value, null, 2) || "—"
}
function affinityRequestId(
  request: unknown,
  source?: string
): string | undefined {
  const value = source ? recordValue(request)?.[source] : undefined
  return typeof value === "string" ? value : undefined
}
function Definition({ rows }: { rows: [string, unknown][] }) {
  return (
    <dl className="grid gap-3">
      {rows.map(([label, value]) => (
        <div
          key={label}
          className="grid gap-1 border-b pb-3 last:border-0 last:pb-0 sm:grid-cols-[10rem_1fr]"
        >
          <dt>{label}</dt>
          <dd className="font-mono text-xs break-all">
            {String(value ?? "—")}
          </dd>
        </div>
      ))}
    </dl>
  )
}
function StatusBadge({ status, locale }: { status: string; locale: Locale }) {
  const bad = status === "auth_error" || status === "disabled"
  return (
    <Badge variant={bad ? "destructive" : "secondary"}>
      {status === "active" ? (
        <CheckCircle2Icon />
      ) : status === "cooldown" ? (
        <CircleGaugeIcon />
      ) : (
        <XCircleIcon />
      )}
      {statusLabel(status, locale)}
    </Badge>
  )
}
function DataTable({ children }: { children: ReactNode }) {
  return (
    <ScrollArea className="w-full whitespace-nowrap">
      <div className="min-w-180">{children}</div>
    </ScrollArea>
  )
}
function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon: ReactNode
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <Empty className="border">
      <EmptyHeader>
        <EmptyMedia variant="icon">{icon}</EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
      {action && <EmptyContent>{action}</EmptyContent>}
    </Empty>
  )
}
function ErrorState({ message: detail }: { message: string }) {
  const t = currentMessages()
  return (
    <Alert variant="destructive">
      <ShieldAlertIcon />
      <AlertTitle>{t.unableLoad}</AlertTitle>
      <AlertDescription>{detail}</AlertDescription>
    </Alert>
  )
}
function LoadingTable() {
  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-5 w-40" />
        <Skeleton className="h-4 w-72 max-w-full" />
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {Array.from({ length: 5 }, (_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </CardContent>
    </Card>
  )
}
function CenteredLoading() {
  const t = currentMessages()
  return (
    <main className="flex min-h-svh items-center justify-center">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Spinner />
        {t.loading}
      </div>
    </main>
  )
}

function useApiQuery<T>(sdk: AuthSdk, path: string) {
  const query = useQuery({
    queryKey: [path],
    queryFn: ({ signal }) => api<T>(sdk, path, { signal }),
  })
  return {
    data: query.data ?? null,
    error: query.error ? message(query.error) : "",
    loading: query.isPending,
    reload: query.refetch,
  }
}
function currentMessages() {
  return copy[document.documentElement.lang.startsWith("zh") ? "zh" : "en"]
}
function message(cause: unknown, t = currentMessages()) {
  return cause instanceof Error ? cause.message : t.unknownError
}
function isAbortError(cause: unknown) {
  return cause instanceof DOMException && cause.name === "AbortError"
}
function formatTime(timestamp: number | undefined, locale: Locale) {
  return timestamp
    ? new Intl.DateTimeFormat(locale === "zh" ? "zh-CN" : "en-US", {
        dateStyle: "short",
        timeStyle: "medium",
      }).format(timestamp * 1000)
    : "—"
}
function formatLatency(milliseconds: number) {
  return milliseconds >= 1000
    ? `${(milliseconds / 1000).toFixed(2)} s`
    : `${milliseconds} ms`
}
function usageEmail(usage: ProviderUsage | undefined) {
  return usage?.email ?? usage?.account_email ?? usage?.account?.email
}
function quotaPercent(window: UsageWindow | undefined) {
  return typeof window?.used_percent === "number"
    ? Math.max(0, Math.min(100, 100 - window.used_percent))
    : undefined
}
function remainingPercent(window: UsageWindow | undefined) {
  const percent = quotaPercent(window)
  return percent === undefined ? "—" : `${percent.toFixed(1)}%`
}
function quotaReset(window: UsageWindow | undefined, locale: Locale) {
  const seconds = window?.reset_at
    ? Math.max(0, window.reset_at - Math.floor(Date.now() / 1000))
    : window?.reset_after_seconds
  if (typeof seconds !== "number") return "—"
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return locale === "zh" ? `${hours}小时${minutes}分` : `${hours}h ${minutes}m`
}
function QuotaProgress({
  window,
  label,
  unavailable,
}: {
  window: UsageWindow | undefined
  label: string
  unavailable?: string
}) {
  const percent = quotaPercent(window)
  if (percent === undefined)
    return (
      <span className="text-xs text-muted-foreground" title={unavailable}>
        —
      </span>
    )
  return (
    <div className="flex min-w-28 items-center gap-2">
      <progress
        aria-label={label}
        className="h-2 w-20 accent-primary"
        value={percent}
        max={100}
      >
        {percent.toFixed(1)}%
      </progress>
      <span className="text-xs tabular-nums">{percent.toFixed(1)}%</span>
    </div>
  )
}
function roleLabel(role: User["role"], locale: Locale) {
  const t = copy[locale]
  return role === "root"
    ? t.roleRoot
    : role === "admin"
      ? t.roleAdmin
      : t.roleUser
}
function statusLabel(status: string, locale: Locale) {
  const t = copy[locale]
  return (
    {
      active: t.statusActive,
      cooldown: t.statusCooldown,
      auth_error: t.statusAuthError,
      disabled: t.statusDisabled,
    }[status] || t.statusUnknown
  )
}
function pageForPath(pathname: string): Page {
  if (pathname.startsWith("/audit/")) return "request-detail"
  return (
    (
      {
        "/dashboard": "dashboard",
        "/providers": "providers",
        "/consumers": "consumers",
        "/usage": "usage",
        "/audit": "audit",
        "/users": "users",
        "/settings": "settings",
      } as const
    )[pathname] ?? "dashboard"
  )
}
function pageTitle(page: Page, locale: Locale) {
  const t = copy[locale]
  return page === "request-detail" ? t.requestDetail : t[page]
}
function pageDescription(page: Page, locale: Locale) {
  const t = copy[locale]
  return {
    dashboard: t.pageDashboard,
    providers: t.pageProviders,
    consumers: t.pageConsumers,
    usage: t.pageUsage,
    audit: t.pageAudit,
    "request-detail": t.pageRequestDetail,
    users: t.pageUsers,
    settings: t.pageSettings,
  }[page]
}

export default App
