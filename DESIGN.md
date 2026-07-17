---
name: OpenAI-LB
description: Calm, precise operations console for the CodeX OAuth load balancer
colors:
  background: "oklch(1 0 0)"
  foreground: "oklch(0.145 0 0)"
  primary: "oklch(0.205 0 0)"
  primary-foreground: "oklch(0.985 0 0)"
  secondary: "oklch(0.97 0 0)"
  secondary-foreground: "oklch(0.205 0 0)"
  muted: "oklch(0.97 0 0)"
  muted-foreground: "oklch(0.556 0 0)"
  destructive: "oklch(0.577 0.245 27.325)"
  border: "oklch(0.922 0 0)"
  ring: "oklch(0.708 0 0)"
typography:
  headline:
    fontFamily: "Geist Variable, Geist, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Geist Variable, Geist, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.5
  body:
    fontFamily: "Geist Variable, Geist, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  control:
    fontFamily: "Geist Variable, Geist, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 500
    lineHeight: 1.4
  label:
    fontFamily: "Geist Variable, Geist, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 500
    lineHeight: 1.4
rounded:
  sm: "6px"
  md: "8px"
  lg: "10px"
  xl: "14px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "20px"
  2xl: "24px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.primary-foreground}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
    height: "36px"
  button-secondary:
    backgroundColor: "{colors.secondary}"
    textColor: "{colors.secondary-foreground}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
    height: "36px"
  input:
    backgroundColor: "{colors.background}"
    textColor: "{colors.foreground}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
    height: "36px"
  panel:
    backgroundColor: "{colors.background}"
    textColor: "{colors.foreground}"
    rounded: "{rounded.lg}"
    padding: "20px"
---

# Design System: OpenAI-LB

## Overview

**Creative North Star: "The Operations Ledger"**

这套界面像一份持续更新、可立即采取行动的运维账本：以中性表面、细边界和明确的文字层级组织高密度状态。它继承 1Exchange 的冷静与精确，不把代理基础设施包装成营销产品；任何视觉强调都必须对应操作、选择、异常或恢复状态。

桌面端采用稳定的侧栏与内容区，数据密集页面以工具栏、筛选器和表格为主；移动端将侧栏折叠为 Sheet，并让宽表格在 ScrollArea 中保留列标题和上下文。shadcn/ui 是唯一基础组件语言，优先组合 Sidebar、Breadcrumb、Tabs、Table、Badge、Alert、Dialog、Sheet、DropdownMenu、Pagination、Skeleton、Empty 与 sonner，而非自制等价控件。

**Key Characteristics:**

- 高密度、低装饰、清晰层级。
- 状态先于汇总，原因先于情绪化提示。
- 单一中性强调色，危险状态只在需要介入时出现。
- 中英文均能自然扩展，关键上下文不被截断。
- 状态变化使用 150–200ms 的克制过渡；减少动态模式下即时切换。

## Colors

颜色系统采用 1Exchange 的中性 OKLCH 语义令牌：白色工作表面、近黑文字、浅灰分层和单一红色危险语义。令牌值以前置 YAML 为唯一规范来源。

### Primary

- **Operational Ink:** 主操作、当前选择与高优先级文字；它不是装饰色。
- **Inverse Ink:** 深色主操作上的前景与反相状态。

### Neutral

- **Clean Canvas:** 页面、卡片与输入的默认工作表面。
- **Soft Utility:** 次级按钮、筛选区、悬停和低强调背景。
- **Quiet Copy:** 辅助说明、时间戳和非关键元数据；不得承载正文或关键状态。
- **Hairline Boundary:** 表格分隔、输入边界和面板轮廓。
- **Focus Graphite:** 所有键盘焦点环的统一颜色。

### Named Rules

**The One-Ink Rule.** 中性主色只用于操作、选择和信息层级；同屏不得引入第二个品牌强调色。

**The State-Needs-Words Rule.** 成功、限流、禁用、恢复和错误必须同时提供文字或图标标签，禁止只靠颜色表达。

**The Chart-Earns-Its-Place Rule.** 只有时间趋势、分布或容量变化需要图表；单个总数使用文字，禁止装饰性图表。

## Typography

**Display Font:** Geist Variable（回退为 Geist、sans-serif）
**Body Font:** Geist Variable（回退为 Geist、sans-serif）
**Label/Mono Font:** 数据标识、哈希、Consumer 前缀与请求 ID 使用系统等宽字体栈。

**Character:** 单一 Geist 家族让标题、表格和控件共享技术型但不生硬的节奏。字重承担层级，字号变化保持克制，避免管理界面出现展示型排版。

### Hierarchy

- **Headline**（600，1.5rem，1.25）：页面标题与关键对象名称；禁止营销式超大标题。
- **Title**（600，1rem，1.5）：面板标题、表格分组和弹层标题。
- **Body**（400，0.875rem，1.5）：表格、表单与说明文字；连续说明限制在 65–75ch。
- **Label**（500，0.75rem，1.4）：字段标签、表头与元数据，不默认全大写或扩大字距。
- **Mono Data**（400，0.75rem，1.5）：请求 ID、上游提供商 ID、模型名、限流头与脱敏凭据；长值允许复制并按场景换行或截断。

### Named Rules

**The Data-Is-Not-Decoration Rule.** 等宽字体只用于机器标识与原始技术值，不用于按钮、标题或普通正文。

**The No-Eyebrow Rule.** 禁止在每个区块上方重复微型全大写 kicker；层级由标题、间距和分隔完成。

## Elevation

系统默认扁平，通过中性表面差异、1px 边界和内容分组表达深度。常驻面板不使用阴影；DropdownMenu、Popover、Dialog、Sheet、Tooltip 和 Toast 等浮层沿用 shadcn/ui 的受控浮层阴影与层级。禁止在同一表面同时叠加 1px 边框与宽模糊装饰阴影。

### Shadow Vocabulary

- **Overlay:** `0 4px 8px oklch(0.145 0 0 / 0.12)`，只用于需要脱离文档流的浮层。
- **Focus:** `0 0 0 3px oklch(0.708 0 0 / 0.5)`，用于键盘焦点，不表达海拔。

### Named Rules

**The Flat-by-Default Rule.** 静止内容表面保持无阴影；只有浮层和焦点状态获得视觉抬升。

**The Semantic Stack Rule.** 层级顺序固定为下拉菜单、粘性导航、遮罩、模态框、Toast、Tooltip；不得使用任意 `z-index`。

## Components

所有界面以 shadcn/ui 组件为基础，并完整覆盖 default、hover、focus-visible、active、disabled、loading 和 error 状态。布局类只负责排列与间距，颜色和排版始终使用语义令牌。

### Buttons

- **Shape:** 紧凑圆角矩形（8px），默认高度 36px；破坏性操作使用 destructive 变体并在执行前用 AlertDialog 确认。
- **Primary:** Operational Ink 背景与反相文字；每个区域只保留一个明确主操作。
- **Hover / Focus:** 悬停只调整语义背景；键盘焦点使用 3px Focus Graphite 环，过渡 150ms。
- **Loading:** 使用 `Spinner`、`disabled` 和内联状态文案；图标带 `data-icon`，不手工设置图标尺寸。

### Chips

- **Style:** 状态与计数使用 Badge；默认 6px 圆角，短枚举可使用胶囊形但不得用于主要操作。
- **State:** 上游提供商状态同时显示图标或文字：可用、接近限流、冷却中、禁用、恢复检查中。

### Cards / Containers

- **Corner Style:** 面板使用轻圆角（10px），不得超过 14px。
- **Background:** Clean Canvas；工具栏和次级分组使用 Soft Utility。
- **Shadow Strategy:** 常驻面板无阴影，以 Hairline Boundary 区分。
- **Internal Padding:** 默认 20px；高密度表格单元采用 12px 垂直节奏。
- **Composition:** Card 必须使用 CardHeader、CardTitle、CardDescription、CardContent 与必要时的 CardFooter；禁止嵌套卡片。

### Inputs / Fields

- **Style:** 36px 高、8px 圆角、Clean Canvas 背景和 Hairline Boundary 边界。
- **Composition:** 表单使用 FieldGroup 与 Field；选项组使用 ToggleGroup 或 FieldSet，不手工拼装。
- **Focus:** 3px Focus Graphite 环，并保留可见边界。
- **Error / Disabled:** `data-invalid` 与 `aria-invalid` 同步；错误包含明确修复建议，禁用状态说明原因。

### Navigation

- **Desktop:** Sidebar + Breadcrumb 提供租户与位置上下文；当前项使用 Soft Utility 背景和加重文字，不使用彩色侧边条。
- **Mobile:** Sidebar 收入带可访问标题的 Sheet；页面级操作进入 DropdownMenu 或固定操作区，不隐藏在手势中。
- **Tables:** Table、ScrollArea、Pagination 和 DropdownMenu 组合承担排序、筛选、分页与行操作；加载使用 Skeleton，空数据使用 Empty 并给出下一步。

### Audit Event Row

审计行固定展示时间、租户、Consumer 前缀、上游提供商、能力/模型、状态、耗时、用量与请求 ID。原始详情在 Sheet 中按字段分组展示；敏感头与 OAuth 凭据必须脱敏，复制操作逐项授权并留下管理审计记录。

## Do's and Don'ts

### Do:

- **Do** 使用 shadcn/ui 现有组件和语义变体组合页面，保持同一操作在各处具有同一外观与行为。
- **Do** 把上游提供商健康、限流余量、冷却截止时间、禁用原因和恢复条件放在同一可扫描上下文中。
- **Do** 用表格承载 Consumer 用量和逐次调用审计，并提供时间、租户、Consumer、上游提供商、能力与结果筛选。
- **Do** 使用 10px 面板圆角、8px 控件圆角、1px 边界和 20px 面板内边距作为默认密度基线。
- **Do** 为键盘焦点、加载、空、错误、禁用和权限不足状态提供完整反馈；所有过渡尊重 `prefers-reduced-motion`。
- **Do** 让中文和英文标签可增长，并为完整值提供 Tooltip、Sheet 或复制入口。

### Don't:

- **Don't** 使用“营销型大屏、超大 Hero、霓虹或 AI 渐变、玻璃拟态、没有行动价值的装饰图表、重复的同尺寸卡片阵列，以及通用 SaaS 落地页模式”。
- **Don't** 使用渐变文字、装饰性条纹背景、彩色粗侧边条或边框加宽模糊阴影的 ghost-card 模式。
- **Don't** 把普通卡片、输入或区块做成 24px 以上圆角；内容表面上限为 14px。
- **Don't** 用模态框作为默认交互；优先内联编辑、展开详情或 Sheet，只在必须阻断流程时使用 Dialog。
- **Don't** 隐藏限流、禁用或恢复原因，也不要仅显示“失败”而不给时间、请求 ID 和下一步。
- **Don't** 在 UI、日志或复制操作中暴露完整 access_key、refresh_key 或租户 Consumer 凭据。
