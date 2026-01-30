import * as Defaults from '@/constant/profile'
import { Inbound, Outbound, RuleAction, Strategy, TunStack } from '@/enums/kernel'

import { deepAssign, sampleID } from './others'

const detectRuleType = (rule: any) => {
  if (rule.type && !['inline'].includes(rule.type)) return rule.type
  const matchers = [
    'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'geosite',
    'ip_cidr', 'ip_is_private', 'geoip', 'source_ip_cidr', 'source_geoip',
    'source_ip_is_private', 'source_port', 'source_port_range', 'port', 'port_range',
    'process_name', 'process_path', 'process_path_regex', 'package_name', 'user', 'user_id',
    'clash_mode', 'network_type', 'network_is_expensive', 'network_is_constrained',
    'wifi_ssid', 'wifi_bssid', 'rule_set', 'inbound', 'protocol', 'network',
    'query_type', 'source_format', 'client', 'preferred_by'
  ]
  const foundMatchers = matchers.filter((k) => rule[k] !== undefined)
  if (foundMatchers.length > 1) return 'inline'
  if (foundMatchers.length === 1) return foundMatchers[0]
  if (rule.action || rule.outbound || rule.server) return 'inline'
  return undefined
}

const getInlinePayload = (rule: any) => {
  const matchers = [
    'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'geosite',
    'ip_cidr', 'ip_is_private', 'geoip', 'source_ip_cidr', 'source_geoip',
    'source_ip_is_private', 'source_port', 'source_port_range', 'port', 'port_range',
    'process_name', 'process_path', 'process_path_regex', 'package_name', 'user', 'user_id',
    'clash_mode', 'network_type', 'network_is_expensive', 'network_is_constrained',
    'wifi_ssid', 'wifi_bssid', 'rule_set', 'inbound', 'protocol', 'network',
    'query_type', 'source_format', 'client', 'preferred_by'
  ]
  const res: any = {}
  matchers.forEach((k) => {
    if (rule[k] !== undefined) res[k] = rule[k]
  })
  return JSON.stringify(res, null, 2)
}

const restoreRule = (
  rule: any,
  OutboundsIds: any,
  DnsServersIds: any,
  isDns?: boolean,
  isNested?: boolean,
): any | undefined => {
  const type = detectRuleType(rule)
  if (!type) return undefined

  const extra: Recordable = {}
  const action = rule.action || RuleAction.Route

  if (isDns) {
    if ([RuleAction.Route, RuleAction.Resolve].includes(action as any)) {
      if (rule.server) extra.server = DnsServersIds[rule.server] || rule.server
    }
  } else {
    if (action === RuleAction.Route) {
      if (rule.outbound) extra.outbound = OutboundsIds[rule.outbound] || rule.outbound
    } else if (action === RuleAction.Resolve) {
      if (rule.server) extra.server = DnsServersIds[rule.server] || rule.server
      if (rule.strategy) extra.strategy = rule.strategy
    } else if (action === RuleAction.Reject) {
      extra.outbound = rule.method || 'default'
    }
  }

  if (action === RuleAction.Sniff) {
    if (rule.sniffer) extra.sniffer = rule.sniffer
  }
  if (rule.invert) extra.invert = rule.invert

  // Special handling for rule_set tag mapping in nested/inline rules
  if (rule.rule_set) {
    extra.rule_set = (Array.isArray(rule.rule_set) ? rule.rule_set : [rule.rule_set]).map(
      (tag: string) => (typeof tag === 'string' ? tag : tag),
    )
  }

  if (isNested) {
    // For nested rules, we want to keep them close to original SingBox format
    // but with mapped IDs/Tags where necessary.
    return {
      ...rule,
      ...extra,
    }
  }

  const restored: any = {
    ...rule,
    ...extra,
    id: sampleID(),
    type,
    action: rule.action || RuleAction.Route,
    payload:
      type === 'inline'
        ? getInlinePayload(rule)
        : Array.isArray(rule[type])
          ? rule[type].join(',')
          : String(rule[type] || ''),
    enable: true,
  }

  if (type === 'logical' && rule.rules) {
    restored.rules = rule.rules
      .map((r: any) => restoreRule(r, OutboundsIds, DnsServersIds, isDns, true))
      .filter(Boolean)
  }

  return restored
}

export const restoreProfile = (config: Recordable, subId?: string) => {
  const isStrategy = (type: string) =>
    [
      Outbound.Selector,
      Outbound.Urltest,
      'url-test',
      Outbound.Direct,
      Outbound.Block,
      'dns',
      'static',
    ].includes(type as any)

  const profile: IProfile = {
    id: sampleID(),
    name: sampleID(),
    log: Defaults.DefaultLog(),
    experimental: Defaults.DefaultExperimental(),
    inbounds: [],
    outbounds: [],
    route: {
      rule_set: [],
      rules: [],
      auto_detect_interface: true,
      find_process: false,
      default_interface: '',
      final: '',
      default_domain_resolver: {
        server: '',
        client_subnet: '',
      },
    },
    dns: {
      servers: [],
      rules: [],
      disable_cache: false,
      disable_expire: false,
      independent_cache: false,
      client_subnet: '',
      final: '',
      strategy: Strategy.Default,
    },
    mixin: Defaults.DefaultMixin(),
    script: Defaults.DefaultScript(),
  }

  const InboundsIds = (config.inbounds || []).reduce(
    (p: any, c: any) => ({ ...p, [c.tag]: sampleID() }),
    {},
  )
  const OutboundsIds = (config.outbounds || []).reduce(
    (p: any, c: any) => ({ ...p, [c.tag]: sampleID() }),
    {},
  )
  const DnsServersIds = (config.dns?.servers || []).reduce(
    (p: any, c: any) => ({ ...p, [c.tag]: sampleID() }),
    {},
  )

  Object.entries(config).forEach(([field, value]) => {
    if (field === 'log') {
      const log: any = { ...value }
      if (log.disabled !== undefined) {
        log.level = log.disabled ? 'disabled' : log.level
      }
      deepAssign(profile[field], log)
    } else if (field === 'experimental') {
      deepAssign(profile[field], value)
    } else if (field === 'inbounds') {
      profile.inbounds = value.flatMap((inbound: any) => {
        if (![Inbound.Http, Inbound.Mixed, Inbound.Socks, Inbound.Tun].includes(inbound.type)) {
          return []
        }
        const extra = {
          id: InboundsIds[inbound.tag],
          tag: inbound.tag,
          type: inbound.type,
          enable: true,
        }
        if (inbound.type === Inbound.Tun) {
          return {
            ...extra,
            tun: {
              interface_name: inbound.interface_name || '',
              address: inbound.address || ['172.18.0.1/30', 'fdfe:dcba:9876::1/126'],
              mtu: inbound.mtu || 0,
              auto_route: !!inbound.auto_route,
              strict_route: !!inbound.strict_route,
              route_address: inbound.route_address || [],
              route_exclude_address: inbound.route_exclude_address || [],
              endpoint_independent_nat: !!inbound.endpoint_independent_nat,
              stack: inbound.stack || TunStack.Mixed,
            },
          }
        }
        if ([Inbound.Mixed, Inbound.Http, Inbound.Socks].includes(inbound.type)) {
          return {
            ...extra,
            [inbound.type]: {
              listen: {
                listen: inbound.listen,
                listen_port: inbound.listen_port,
                tcp_fast_open: !!inbound.tcp_fast_open,
                tcp_multi_path: !!inbound.tcp_multi_path,
                udp_fragment: !!inbound.udp_fragment,
              },
              users: (inbound.users || []).map((user: any) => user.username + ':' + user.password),
            },
          }
        }
      })
    } else if (field === 'outbounds') {
      profile.outbounds = (value || []).flatMap((outbound: any) => {
        if (!isStrategy(outbound.type)) return []

        const extra: Recordable = { ...outbound }
        extra.id = OutboundsIds[outbound.tag] || sampleID()
        if (outbound.outbounds) {
          extra.outbounds = (outbound.outbounds || []).flatMap((tag: string) => {
            if (OutboundsIds[tag]) {
              const target = (value || []).find((v: any) => v.tag === tag)
              const type =
                target && !isStrategy(target.type) ? subId || 'Subscription' : 'Built-in'
              return {
                id: OutboundsIds[tag],
                type,
                tag,
              }
            }
            if (['direct', 'block'].includes(tag.toLowerCase())) {
              return { id: tag.toLowerCase(), type: 'Built-in', tag }
            }
            return []
          })
        }
        return extra
      })
    } else if (field === 'route') {
      profile.route = {
        rules: (value.rules || []).flatMap((rule: any) => {
          const res = restoreRule(rule, OutboundsIds, DnsServersIds, false)
          return res ? [res] : []
        }),
        rule_set: (value.rule_set || []).map((rs: any) => ({
          ...rs,
          id: rs.tag,
          tag: rs.tag,
          type: rs.type,
          format: rs.format,
          url: rs.url,
          path: rs.path,
          download_detour: OutboundsIds[rs.download_detour] || rs.download_detour,
          update_interval: rs.update_interval,
          rules: rs.rules, // for inline
        })),
        final: OutboundsIds[value.final] || value.final || '',
        auto_detect_interface: value.auto_detect_interface ?? true,
        find_process: !!value.find_process,
        default_interface: value.default_interface || '',
        default_domain_resolver: {
          server:
            DnsServersIds[value.default_domain_resolver?.server] ||
            value.default_domain_resolver?.server ||
            '',
          client_subnet: value.default_domain_resolver?.client_subnet || '',
        },
      }
    } else if (field === 'dns') {
      profile.dns = {
        disable_cache: value.disable_cache ?? false,
        disable_expire: value.disable_expire ?? false,
        independent_cache: value.independent_cache ?? false,
        final: DnsServersIds[value.final] || value.final || '',
        strategy: value.strategy || Strategy.Default,
        client_subnet: value.client_subnet || '',
        servers: (value.servers || []).map((server: any) => {
          // Restore 1.12+ DNS server format
          const res: any = {
            id: DnsServersIds[server.tag] || sampleID(),
            enable: true,
            ...server,
          }
          if (server.address && !server.server && !server.type) {
            // Legacy format - address URL
          }
          return res
        }),
        rules: (value.rules || []).flatMap((rule: any) => {
          const res = restoreRule(rule, {}, DnsServersIds, true)
          return res ? [res] : []
        }),
        reverse_mapping: !!value.reverse_mapping,
        cache_capacity: value.cache_capacity,
      }
    }
  })

  return profile
}
