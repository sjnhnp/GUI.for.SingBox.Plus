import * as Defaults from '@/constant/profile'
import { Inbound, Outbound, RuleAction, Strategy, TunStack } from '@/enums/kernel'

import { deepAssign, sampleID } from './others'

const detectRuleType = (rule: any) => {
  if (rule.type) return rule.type
  const keys = [
    'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'geosite',
    'ip_cidr', 'ip_is_private', 'geoip', 'source_ip_cidr', 'source_geoip',
    'source_port', 'source_port_range', 'port', 'port_range', 'process_name',
    'process_path', 'package_name', 'wifi_ssid', 'wifi_bssid', 'rule_set',
    'clash_mode', 'inbound', 'protocol', 'network', 'query_type', 'source_format'
  ]
  return keys.find((k) => rule[k] !== undefined)
}

export const restoreProfile = (config: Recordable) => {
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

  const InboundsIds = config.inbounds.reduce(
    (p: any, c: any) => ({ ...p, [c.tag]: sampleID() }),
    {},
  )
  const OutboundsIds = config.outbounds.reduce(
    (p: any, c: any) => ({ ...p, [c.tag]: sampleID() }),
    {},
  )
  // const RulesetIds = config.route.rule_set.reduce(
  //   (p: any, c: any) => ({ ...p, [c.tag]: sampleID() }),
  //   {}
  // )
  const DnsServersIds = config.dns.servers.reduce(
    (p: any, c: any) => ({ ...p, [c.tag]: sampleID() }),
    {},
  )

  Object.entries(config).forEach(([field, value]) => {
    if (field === 'log') {
      deepAssign(profile[field], value)
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
        if (!outbound.type || !outbound.tag) {
          return []
        }
        const extra: Recordable = { ...outbound }
        extra.id = OutboundsIds[outbound.tag] || sampleID()
        if (outbound.outbounds) {
          extra.outbounds = (outbound.outbounds || []).flatMap((tag: string) => {
            if (!OutboundsIds[tag]) {
              return []
            }
            return {
              id: OutboundsIds[tag],
              type: 'Built-in',
              tag,
            }
          })
        }
        return extra
      })
    } else if (field === 'route') {
      profile.route = {
        rules: (value.rules || []).flatMap((rule: any) => {
          const type = detectRuleType(rule)
          if (!type) return []

          const extra: Recordable = {}
          if (rule.action === RuleAction.Route) {
            extra.outbound = OutboundsIds[rule.outbound] || rule.outbound
          } else if (rule.action === RuleAction.RouteOptions) {
            // extra.outbound = ... (route options usually don't have outbound tag)
          } else if (rule.action === RuleAction.Resolve) {
            extra.server = DnsServersIds[rule.server] || rule.server
            if (rule.strategy) extra.strategy = rule.strategy
          } else if (rule.action === RuleAction.Sniff) {
            if (rule.sniffer) extra.sniffer = rule.sniffer
          }
          if (rule.invert) extra.invert = rule.invert

          return {
            id: sampleID(),
            type,
            action: rule.action || RuleAction.Route,
            payload: rule[type] || '',
            ...extra,
            ...rule,
          }
        }),
        rule_set: (value.rule_set || []).map((rs: any) => ({
          id: sampleID(),
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

      // Fix Rule Payload: The UI expects `payload` to be a string (comma separated) for list types.
      profile.route.rules = profile.route.rules.map((r: any) => {
        const key = r.type // e.g. 'domain', 'ip_cidr'

        let payload = r[key]
        if (Array.isArray(payload)) {
          payload = payload.join(',')
        } else if (typeof payload === 'boolean') {
          payload = String(payload)
        }
        // If payload is undefined, maybe it is stored in `payload` already? No, raw config doesn't have `payload`.

        // Let's try to fetch it from the rule object itself
        // Iterate common keys?
        if (
          [
            'domain',
            'domain_suffix',
            'domain_keyword',
            'domain_regex',
            'geosite',
            'ip_cidr',
            'ip_is_private',
            'geoip',
            'source_ip_cidr',
            'source_port',
            'source_port_range',
            'port',
            'port_range',
            'process_name',
            'process_path',
            'package_name',
            'wifi_ssid',
            'wifi_bssid',
            'rule_set',
            'clash_mode',
            'invert',
          ].includes(key)
        ) {
          let rawPayload = r[key]
          if (Array.isArray(rawPayload)) {
            payload = rawPayload.join(',')
          } else {
            payload = String(rawPayload ?? '')
          }
        }

        return {
          ...r,
          payload: payload,
        }
      })
    } else if (field === 'dns') {
      profile.dns = {
        disable_cache: value.disable_cache ?? false,
        disable_expire: value.disable_expire ?? false,
        independent_cache: value.independent_cache ?? false,
        final: DnsServersIds[value.final] || value.final || '',
        strategy: value.strategy || Strategy.Default,
        client_subnet: value.client_subnet || '',
        servers: (value.servers || []).map((server: any) => {
          // Restore basic DNS server info
          return {
            id: DnsServersIds[server.tag] || sampleID(),
            enable: true,
            ...server,
          }
        }),
        rules: (value.rules || []).flatMap((rule: any) => {
          const type = detectRuleType(rule)
          if (!type) return []

          const extra: Recordable = {}
          if (rule.action === RuleAction.Resolve) {
            extra.server = DnsServersIds[rule.server] || rule.server
          }
          return {
            id: sampleID(),
            type,
            action: rule.action || RuleAction.Route,
            payload: rule[type] || '',
            ...extra,
            ...rule,
          }
        }),
      }
    }
  })

  return profile
}
