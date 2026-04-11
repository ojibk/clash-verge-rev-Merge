# # 存储路径参考： %APPDATA%\io.github.clash-verge-rev.clash-verge-rev\profiles
# # ======================================================================================
# # 全局扩展覆写配置 (Merge Config) — 锚点组架构
# # --------------------------------------------------------------------------------------
# # 【运行范式】
# #  本文件工作在锚点组架构下，负责基础网络路由管线 (L1-L5)。可不依赖 Script.js 单独运行。
# #  若同时启用 Script.js，则特例拦截与动态提权在 L0 层协同完成，L0 规则优先于本文件规则链。
# #  职责分工：
# #    rule-providers → Map 合并注入自定义规则集
# #    proxy-groups   → 必须声明固定锚点组，rules 出口的唯一保障
# #    rules          → 自完备规则链，硬编码指向锚点组名
# #
# # 【proxy-groups 必须声明】
# #  rules 中的代理出口硬编码为 [节点选择]。
# #  若不声明此块，换订阅时一旦订阅不含该组名，Mihomo 启动即报错
# #  proxy not found，rules 中所有指向该组的条目失效。
# #  必须在本文件中定义该组，由本文件自身保证组名必然存在。
# #
# # 【系统设计哲学】
# #  本配置是一个"弱一致规则系统 + 强确定出口模型"：
# #  · 弱一致：rule-providers 可失效，GEOIP 为黑箱不可靠，在污染环境下 DNS 可能不可靠（尤其 UDP/53）
# #  · 强确定：MATCH 永远有出口，规则链无死路，不依赖外部 fallback
# #  · 设计取向：容错优先，而非精确优先
# #  · 隐含策略立场：未知域名默认走代理（Unknown → Proxy），
# #    以避免 DNS 解析导致的 GeoIP 误判（CDN 污染场景）。
# #    已知 trade-off：选择"安全优先"而非"最优路径优先"，
# #    国内小众域名未收录时走代理，企业私有 SaaS / CDN 边缘域名可能不直连，
# #    这是有意识的设计取舍，而非缺陷。
# #
# # 【覆写机制总览】
# #  ● Map 类型  (rule-providers)：键值对合并，异名 Key 无损保留
# #  ● Array 类型 (proxy-groups / rules)：全量替换，本文件内容为唯一来源，须自完备
# # ======================================================================================


# # ======================================================================================
# # 1. 规则集提供者 (Rule Providers) — Map（键值对） 合并，不替换订阅原有条目
# # --------------------------------------------------------------------------------------
# # 【格式审计 — 关键】
# #  Loyalsoldier @release 分支的源文件并非裸列表，其首行为 `payload:`，属于 YAML 格式。
# #  若误写 format: text，内核会将 `payload:` 字符串本身当作第一条规则条目处理，
# #  导致首条规则损坏，后续条目虽能部分解析但结果不可靠。
# #  典型症状：规则集界面显示 0 条，或域名本应命中规则却穿透至 MATCH 兜底。
# #  因此，所有 Loyalsoldier 源必须强制指定 format: yaml。
# #
# # 【格式审计 — 例外】
# #  Blackmatrix7 AdvertisingLite_Domain.txt 为纯文本裸列表，不含 payload: 头，
# #  须使用 format: text，与 Loyalsoldier 源严格区分，两者不可混用。
# #
# # 【behavior 性能审计】
# #  全线选用 domain / ipcidr，内核加载时构建后缀匹配树 (Domain Trie) /
# #  前缀树 (CIDR Trie)，一次树查询即可完成匹配。
# #  相比 classical 模式的逐行线性扫描，在处理 direct (条目规模庞大) 时
# #  可显著降低 CPU 与内存开销，匹配速度更快。
# #  classical 模式要求文件内每行含完整类型前缀（如 DOMAIN、IP-CIDR），
# #  本配置所选源文件均为纯列表，不使用此模式。
# #
# # 【动作下放原则】
# #  所有规则集文件均不自带策略动作，流量最终去向完全由 rules 段行末尾的指令决定。
# #
# # 【下载源说明】
# #  规则集使用 testingcf.jsdelivr.net（jsdelivr 官方 Cloudflare 节点），
# #  相比 fastly.jsdelivr.net 在国内可达性更稳定，无需依赖第三方代理中转。
# #
# # 【type: http 运行时行为说明】
# #  Mihomo 对远程规则集采用"静默容错"机制，而非强一致加载：
# #  · 首次启动无缓存且下载失败：
# #    RULE-SET 条目数为 0，对应规则匹配失败 (match fail)，流量滑落至后续规则。
# #  · 非首次启动下载失败（CDN 波动 / DNS 污染 / GitHub 被干扰）：
# #    Mihomo 自动使用本地缓存继续运行，用户无感知。
# #  · 以上均为 Mihomo 内核机制，非本文件设计结果。
# #    本配置通过末尾 MATCH 兜底规则承接所有未命中流量，保证异常时仍有确定出口。
# #  · 若需确认规则集当前状态，可在 CVR「规则集」界面查看条目数与最后更新时间。
# #    ⚠️ 注意：规则集失效 = 静默降级
# #    1.加载失败 → 使用缓存；2.首次失败 → 0 条
# #    当：CDN 持续失败 + 无缓存
# #    链变成：L1 → L2（空）→ L3（空）→ L4 → L5
# #    👉 实际效果：几乎全部流量 → MATCH → 代理
# #    🔥 这叫：隐式全局代理模式！用户无感知
# #    ⚠️ 若 rule-providers 全部加载失败且无缓存：系统退化为"近似全局代理"，用户无明显提示
# #    建议通过日志或 CVR 规则集界面检测 rule-providers 加载状态
# # ======================================================================================
# # 【全局行为调优】— 提升进程可见性与配置持久化
find-process-mode: always     # 强制获取连接进程名（需 TUN 模式 + 管理员权限）
#                               # 可选值: off / strict / always
#                               # 设置为 always 可确保 CVR 连接日志显示进程名，
#                               # 即使脚本禁用或部分规则失效，进程信息仍可获取。
profile:
  store-selected: true       # 记住策略组选择，将 Proxy Groups 的选择写入 cache.db 映射表。策略组选路持久化：存储节点选择，防止重启或订阅更新导致出口重置
#  store-fake-ip: true       # Fake-IP 映射持久化：加速域名二次解析并减少内网 IP 跳变
#                               # ⚠️ 仅 DNS 模式为 fake-ip 时有效，redir-host 模式下无意义，默认不开启
#                               # ⚠️ 隐私审计：cache.db 会记录访问域名历史、域名映射关系和常用的代理节点。极端隐私需求可定期手动清理。
global-client-fingerprint: chrome   # 全局 TLS 客户端指纹模拟（提升代理隐匿性）。可选值: chrome / firefox / safari / random
#                                   # 模拟 Chrome 的 TLS 握手特征，避免因指纹不符触发网站验证码或拒绝连接
#                                   # ❗ 新版内核逐步迁移至 tls.fingerprint


# # ======================================================================================
rule-providers:

  private: # 局域网域名保护 (Loyalsoldier private.txt)
    type: http        # 类型：远程 HTTP 资源，运行时按需下载并缓存至本地 path 路径
    behavior: domain  # 行为：域名模式，文件为纯域名列表，内核构建后缀匹配树 (Domain Trie)
                      # 策略不内置于文件，由引用此集合的 rules 行末指令统一决定
    format: yaml      # 格式：源文件首行为 `payload:`，属于 YAML 列表格式
                      # 必须指定 yaml，误用 text 会将 payload: 当作规则条目导致首条损坏
    url: "https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt"
                      # 远程地址：jsdelivr 官方 Cloudflare 节点，国内可达性优于 fastly 节点
    path: "./rules/providers/private.list"
                      # 本地缓存路径：相对于 CVR profiles 目录，落盘后供内核离线加载
                      # ⚠️ 若目录不存在或无写入权限：
                      #    · 部分内核版本可自动创建目录，部分环境（尤其 Windows 权限受限）会失败
                      #    · 失败时退化为仅内存缓存（不落盘）
                      #    · 表现为：每次启动均需重新下载规则集，重启后缓存丢失
    lazy: false       # 核心分流规则建议不开启 lazy，确保启动后路由即刻就绪
    interval: 86400   # 缓存更新间隔：86400 秒 = 24 小时，到期后内核后台静默拉取更新

  lan_cidr: # 局域网 IP 段补丁 (Loyalsoldier lancidr.txt)
    # 设计说明：private.txt 仅收录私有域名（如 router.asus.com），
    #           不覆盖 192.168.x.x / 10.x.x.x / 172.16.x.x 等私有 IP 段。
    #           本条目作为 IP 层补丁，与 private 共同构成完整的局域网直连防线，缺一不可。
    #           缺失时，内网 IP 直连规则完全失效，内网请求将穿透至代理出口。
    type: http        # 类型：远程 HTTP 资源
    behavior: ipcidr  # 行为：IP 网段模式，文件为纯 CIDR 列表（如 192.168.0.0/16）
                      # 内核构建前缀树 (CIDR Trie) 进行匹配，与 domain 模式不可互换
    format: yaml      # 格式：源文件含 payload: 头，必须使用 yaml
                      # 误用 text 典型症状：规则集界面显示 0 条，内网 IP 直连完全失效
    url: "https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt"
    path: "./rules/providers/lan_cidr.list"
                      # ⚠️ 缓存落盘前提同 private：目录须存在且有写入权限，
                      #    否则退化为内存缓存，每次启动重新下载
    lazy: false       # 核心分流规则建议不开启 lazy，确保启动后路由即刻就绪
    interval: 86400

  AdvertisingLite_Domain: # 进阶应用广告拦截 (Blackmatrix7 AdvertisingLite_Domain.txt)
    # 变体选型说明（三选一）：
    #   Advertising.list              → classical 格式（含 DOMAIN/IP-CIDR 类型前缀及策略字段）
    #                                   与 behavior: domain 不兼容，不可使用
    #   Advertising_Domain.list       → 纯域名完整版，条目数量庞大
    #                                   加载耗时长，可能导致内核启动时 IPC send timeout
    #   AdvertisingLite_Domain.txt    → 纯域名精简版，覆盖主流广告域名 ✅ 当前选用
    #                                   体积小，启动性能更优，日常使用覆盖率足够
    type: http        # 类型：远程 HTTP 资源
    behavior: domain  # 行为：域名模式，_Lite 文件为纯域名裸列表，严格对应 domain 模式
    format: text      # 格式：Blackmatrix7 源为纯文本裸列表，不含 payload: 头
                      # 必须使用 text，与所有 Loyalsoldier 源的 format: yaml 严格区分
    url: "https://testingcf.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AdvertisingLite/AdvertisingLite_Domain.txt"
    path: "./rules/providers/AdvertisingLite_Domain.list"
    lazy: true        # 懒加载触发的瞬间延迟构建 Trie 树，仅在首次匹配时初始化，显著提升启动速度。避免重载时重复构建
    interval: 86400

  # reject: # 基础广告与追踪域名拦截 (Loyalsoldier reject.txt)
  #   # 💡 与 AdvertisingLite_Domain 的语义区分：
  #   #   reject.txt              → 威胁情报（广告联盟 / 追踪器 / 恶意软件 / C2 域名）→ 安全防护
  #   #   AdvertisingLite_Domain  → 应用内广告域名 → 体验优化
  #   #   两者互补，非替代关系。条目规模庞大若导致卡顿可注释掉
  #   #   主流追踪 / 遥测域名，与 reject.txt 存在大量语义重叠，为减少规则集加载开销可暂时禁用。
  #   # ❗ 若未启用任何拦截脚本，建议取消注释恢复此条目，否则追踪 / 恶意域名无防护。
  #   type: http        # 类型：远程 HTTP 资源
  #   behavior: domain  # 行为：域名模式，纯域名列表，内核构建后缀匹配树
  #   format: yaml      # 格式：Loyalsoldier 源，含 payload: 头，必须使用 yaml
  #   url: "https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt"
  #   path: "./rules/providers/reject.list"
  #   lazy: true          # 懒加载触发的瞬间延迟构建 Trie 树，仅在首次匹配时初始化，显著提升启动速度。避免重载时重复构建
  #   interval: 86400

  direct: # 国内主流域名直连库 (Loyalsoldier direct.txt)
    # 收录国内常见域名，大规模域名集合（数量随上游维护动态变化）
    # 覆盖盲区：仅含主流域名，小众 / 地区性 / 企业内部域名不在列表内，
    #           由后续 GEOIP,CN,no-resolve 规则以 IP 维度兜底补盲。
    # ⚠️ 互斥说明：direct 与 proxy 非强互斥：极少数域名可能同时存在于 direct/proxy，实际行为由规则顺序决定
    #           direct 在前是有意为之的优先级表达：当极少数边界域名同时被两个列表覆盖时，
    #           direct 先命中保证国内域名直连，符合"国内优先"的设计意图。
    type: http        # 类型：远程 HTTP 资源
    behavior: domain  # 行为：域名模式，纯域名列表，内核构建后缀匹配树
                      # domain 模式在条目规模庞大时性能显著优于 classical 模式逐行线性扫描
    format: yaml      # 格式：Loyalsoldier 源，含 payload: 头，必须使用 yaml
    url: "https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"
    path: "./rules/providers/direct.list"
    lazy: false       # 核心分流规则建议不开启 lazy，确保启动后路由即刻就绪
    interval: 86400

  proxy: # 境外常用加速域名库 (Loyalsoldier proxy.txt)
    # 收录 Google / GitHub / Telegram / Twitter / YouTube 等高频境外服务域名。
    # 命中此规则集的流量送入锚点组 [节点选择]，经用户所选代理节点出站。
    # ⚠️ 互斥说明：direct 与 proxy 非强互斥：极少数域名可能同时存在于 direct/proxy，实际行为由规则顺序决定
    #           direct 在前确保国内域名在进入本条之前已优先命中，符合"国内优先"意图。
    type: http        # 类型：远程 HTTP 资源
    behavior: domain  # 行为：域名模式，纯域名列表，内核构建后缀匹配树
    format: yaml      # 格式：Loyalsoldier 源，含 payload: 头，必须使用 yaml
    url: "https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
    path: "./rules/providers/proxy.list"
    lazy: false       # 核心分流规则建议不开启 lazy，确保启动后路由即刻就绪
    interval: 86400


# # ======================================================================================
# # 2. 策略组 (Proxy Groups) — 必须声明，锚点组是 rules 出口的唯一保障
# # --------------------------------------------------------------------------------------
# # 【锚点组设计逻辑】
# #  · 在本文件中定义固定组名 [节点选择]，rules 段硬编码指向此名称。
# #  · 该组由本文件保证必然存在，切换任意订阅均不会因找不到组名而触发启动报错。
# #  · include-all: true 令内核启动时自动将订阅内所有裸节点及 proxy-provider 节点注入本组
# #    切换订阅后无需手动维护节点列表，实现跨订阅节点自动继承。
# #    订阅内的嵌套策略组（如自动选择、地区分组）不会被自动包含。
# #    大多数机场提供的均为裸节点，此限制在常见场景下影响极小。
# #
# # 【接受代价】
# #  proxy-groups 为 Array 类型，声明即触发全量替换，订阅原有所有分流组被丢弃。
# #  代理面板仅保留 [节点选择] 一个出口，由用户手动切换节点。
# #  订阅原有精细分流组（自动选择 / ChatGPT / Netflix / TikTok 等）将完全消失。
# #  若需同时保留订阅分流组与稳定出口，须注释掉本文件的 proxy-groups 段，改由脚本主导。
# # ======================================================================================
proxy-groups:
  - name: 节点选择    # 固定锚点组名，rules 段的唯一代理出口
                      # 名称变动须同步修改 rules L3 的 proxy 行和 L5 的 MATCH 行，否则报错
    type: select      # 类型：手动选择，由用户在 CVR 代理面板点击切换当前生效节点
    include-all: true # 继承裸节点及 proxy-provider 节点，同时兼容脚本 include-all 字段检测
                      # 切换订阅后节点列表自动同步，无需手动维护 proxies 数组
                      # ⚠️ 隐式前提：订阅必须暴露裸节点（直接定义的服务器条目）
                      #    以下两种情况均会导致本组注入 0 个节点，[节点选择] 成为空组：
                      #    · 机场仅提供 proxy-groups 分流组，不暴露原始裸节点
                      #    · 订阅仅提供 relay / url-test / fallback 等策略组，
                      #      且未将原始 proxies 暴露（UI 看似有节点，实则不可继承）
                      #    空组时触发 Fail-Fast 硬失败，而非静默降级：
                      #    · 所有流量在 MATCH 后无可用出口
                      #    · 表现为连接失败（timeout / ERR_PROXY_CONNECTION_FAILED）
                      #    · 不会自动回退直连，不报错但完全不可用
                      #    这是有意设计——让问题立即暴露，而非静默掩盖。
                      #    遇此情况须改用硬编码订阅组名方案或脚本主导架构。


# # ======================================================================================
# # 3. 路由规则 (Rules) — 自完备规则链 (Array 类型，全量替换)
# # --------------------------------------------------------------------------------------
# # 【替换说明】
# #  此字段为 Array 类型，写入即丢弃订阅原有全部 rules，本段成为唯一生效规则链。
# #  因此规则链必须覆盖所有流量场景，末尾 MATCH 兜底不可省略。
# #
# # 【确定性分层设计】
# #  规则链按"命中确定性"由高到低排列，共 5 层：
# #
# #  L1 强确定性层：本地 CIDR / 私有域名，规则内容固定，命中结果 100% 可预期。
# #  L2 清洗层：    远程规则集 REJECT，依赖加载状态，加载失败静默跳过。
# #  L3 分流层：    远程规则集分流，依赖加载状态，direct/proxy 非强互斥：极少数域名可能同时存在于 direct/proxy，实际行为由规则顺序决定
# #  L4 IP 兜底层： 内置 GeoIP 黑箱数据库，概率正确，CDN 场景存在误判风险。
# #                 GEOIP 为黑箱（不可见内容），与 RULE-SET（可见文件）性质不同，
# #                 出现误判只能通过行为观测定位，无法直接审查数据库内容。
# #                 层内顺序遵循确定性优先：PRIVATE（绝对确定集合）在 CN（概率集合）之前，
# #                 GeoIP 数据库异常时 PRIVATE 仍能确定性命中，不受概率层污染影响。
# #  L5 最终出口层：MATCH 兜底，不可再分，承接所有未命中流量。
# #
# #  解读：L1 为域名/CIDR 双模式精确匹配，L4 为 IP 级兜底，两者互补而非重复。
# #
# # 【隐含策略立场与 no-resolve 行为】
# #  no-resolve：禁止内核为 GEOIP 规则主动触发 DNS 解析（此为 Mihomo 内核行为）。
# #  · 流量已有 IP：直接比对 GeoIP 数据库，命中则执行对应动作。
# #  · 流量仅有域名且上方规则未命中：因无 IP 可比对，规则匹配失败 (match fail)，
# #    流量自然滑落至 L5 的 MATCH 条目走代理——此为 MATCH 驱动的结果，非内核原生策略。
# #    这隐含了设计立场：Unknown → Proxy。
# #  · 该设计是有意为之：代理兜底优于强制 DNS 解析后因 CDN 误判为国内 IP 而直连。
# #  · 已知 trade-off：选择"安全优先"而非"最优路径优先"：
# #    国内小众域名未收录时走代理，企业私有 SaaS / CDN 边缘域名可能不直连，
# #    这是有意识的设计取舍，而非缺陷。
# #
# # 【动作来源】
# #  所有 rule-providers 文件均无内置策略，行末动作指令是流量去向的唯一依据。
# #
# # 【调试方法（外部观测，无需修改配置）】
# #  · 验证规则集是否加载：CVR「规则集」界面查看条目数，无需改配置。
# #  · 验证域名路径覆盖：在怀疑被遮蔽的规则集之前临时插入精确匹配条目，
# #    观察是否命中，可判断上层是否存在遮蔽，用后注释掉即可。
# #  · 验证 GEOIP 误判：临时将 GEOIP,CN 出口改为测试节点，观察命中流量，
# #    GEOIP 是黑箱库，这是唯一有效的运行时观测手段。
# #  · 常规定位：修改规则 → 重载 → 查看 CVR 连接日志，无需内置调试系统。
# # ======================================================================================
rules:
  # =============================================================
  # L1: 强确定性层 — 本地匹配，规则内容固定，命中结果 100% 可预期
  # =============================================================
  - RULE-SET,private,DIRECT             # 局域网域名   -> 直连，匹配 router.asus.com 等私有域名，不经过代理
  - RULE-SET,lan_cidr,DIRECT            # 局域网 IP 段 -> 直连，private 的 IP 层补丁，覆盖 192.168/10/172.16 等私有网段

  # =============================================================
  # L2: 清洗层 — 远程规则集 REJECT，依赖加载状态，加载失败静默跳过
  # 返回错误（客户端可感知）/ REJECT-DROP 静默丢包（更像真实网络失败）
  # REJECT-DROP vs REJECT 选型原则：
  # REJECT      → 立即返回 RST，软件立刻感知失败，进入离线模式，无启动卡顿
  # REJECT-DROP → 静默丢包，软件等待 TCP 超时（通常 15-30s）后感知失败
  #               适用场景：防止进程感知到被拦截后快速切换备用链路或疯狂重试
  #               代价：软件启动时若命中此规则会有明显卡顿，谨慎使用
  #               如遇软件启动极慢，可将 REJECT-DROP 批量改为 REJECT
  # =============================================================
  - RULE-SET,AdvertisingLite_Domain,REJECT  # 进阶应用广告 -> 拒绝，Blackmatrix7 精简版覆盖主流应用广告。
  # - RULE-SET,reject,REJECT            # 基础广告域名 -> 拒绝，内核层直接丢包，不建立任何连接  

  # =============================================================
  # L3: 分流层 — 远程规则集，依赖加载状态，direct/proxy 非强互斥：极少数域名可能同时存在于 direct/proxy，实际行为由规则顺序决定
  #             direct 在前是有意为之的优先级表达，确保国内域名优先直连
  # =============================================================
  - RULE-SET,direct,DIRECT              # 国内主流域名 -> 直连，覆盖主流国内域名集合（规模较大），基于 Trie 树极速放行。
                                        # 避免 CDN 多归属场景下 GeoIP 误判（多归属 IP 可能被错误归类），以域名规则精确放行。存在长尾盲区由 L4 补偿
  - RULE-SET,proxy,节点选择              # 境外加速域名 -> 送入锚点组 [节点选择]，经用户所选代理节点出站

  # =============================================================
  # L4: IP 兜底层 — 内置 GeoIP 黑箱库，概率正确，CDN 场景存在误判风险
  #               层内顺序遵循确定性优先：PRIVATE（绝对确定）在 CN（概率）之前
  #               no-resolve 下仅有域名的流量匹配失败 (match fail) 后滑落至 L5
  #               隐含策略：Unknown → Proxy，由 L5 的 MATCH 条目驱动，非内核原生行为
  #               ⚠️ 注意：GEOIP ≠ 地理位置 ≈ IP归属猜测。基于 IP 归属库，不代表真实物理位置，在 CDN/Anycast 跨区调度场景下可能出现"境外服务命中 CN"或反之。
  #               ⚠️ GeoIP 数据库存在滞后 / CDN 污染 / Anycast 误判风险。该层为"概率兜底"，非强保证
  # =============================================================
  - GEOIP,PRIVATE,DIRECT,no-resolve     # 私有 IP 防线 -> 直连，绝对确定集合（RFC 1918），确定性优先前置
                                        #    与 L1 形成双重保障，私有 IP 范围固定无需触发 DNS 解析
  - GEOIP,CN,DIRECT,no-resolve          # 国内 IP 兜底 -> 直连，概率集合（GeoIP 库），弥补 L3 direct 的域名库长尾盲区
                                        #    仅有域名且上方未命中时匹配失败 (match fail)，滑落至 L5——此为预期行为

  # =============================================================
  # ⚠️ 警告：若所有 rule-providers 加载失败且无缓存，将退化为近似全局代理模式。此 MATCH 将使全量流量进入代理。用户无明显提示。内核行为，非本配置设计
  # L5: 最终出口层 — 不可再分，承接所有未命中流量
  #               MATCH 永远有出口，规则链无死路
  # =============================================================
  - MATCH,节点选择                      # 最终兜底     -> 所有未命中规则的流量送入锚点组 [节点选择]，由用户节点决定去向
