#
# == Class: nss_pam_ldapd::config
#
# Manage configuration file +/etc/nslcd.conf+.
#
# === Parameters
#
# [*ldap*]
#   Hash containing the following parameters, which are documented in
#   +nslcd.conf(5)+:
#
#   [*uri*]
#     Array or string of URIs of LDAP servers
#
#   [*base*]
#   [*ssl*]
#   [*tls_cacertdir*]
#   [*tls_reqcert*]
#   [*timelimit*]
#   [*bind_timelimit*]
#   [*idle_timelimit*]
#   [*binddn*]
#   [*bindpw*]
#
#
class nss_pam_ldapd::config (
  $ldap = hiera('nss_pam_ldapd::config::ldap', {
    uri                           => [ 'ldap://localhost', ],
    base                          => { global => ['dc=example,dc=com'] },
    scope                         => undef,
    ssl                           => 'start_tls',
    tls_cacertdir                 => '/etc/openldap/cacerts',
    tls_cacertfile                => undef,
    tls_reqcert                   => 'never',
    tls_randfile                  => undef,
    tls_ciphers                   => undef,
    tls_cert                      => undef,
    tls_key                       => undef,
    timelimit                     => 120,
    bind_timelimit                => 120,
    idle_timelimit                => 3600,
    uid                           => undef,
    gid                           => undef,
    threads                       => undef,
    ldap_version                  => undef,
    binddn                        => undef,
    bindpw                        => undef,
    rootpwmoddn                   => undef,
    rootpwmodpw                   => undef,
    sasl_mech                     => undef,
    sasl_realm                    => undef,
    sasl_authcid                  => undef,
    sasl_secprops                 => undef,
    sasl_canonicalize             => undef,
    krb5_ccname                   => undef,
    deref                         => undef,
    referrals                     => undef,
    reconnect_sleeptime           => undef,
    reconnect_retrytime           => undef,
    pagesize                      => undef,
    nss_initgroups_ignoreusers    => undef,
    nss_min_uid                   => undef,
    nss_nested_groups             => undef,
    nss_getgrent_skipmembers      => undef,
    nss_disable_enumeration       => undef,
    validnames                    => undef,
    ignorecase                    => undef,
    pam_password_prohibit_message => undef,
    reconnect_invalidate          => undef,
    cache                         => undef,
    log                           => undef,
    pam_authc_ppolicy             => undef,
    pam_authz_search              => undef,
    filter                        => undef,
    map                           => undef,
    }),
) {

  # uri
  if (has_key($ldap, 'uri') and $ldap['uri'] != undef) {

    $uri = $ldap['uri']

    # Clean the current values first
    $aug_uri_clean = ['rm uri/*']

    # Index the uris. This will get [[1, url1], [2, url2], [3, url3]]
    $indexed_uri = zip(range(1, size($uri)), $uri)

    # Create a new Array with al the augeas operations
    $aug_uri = $indexed_uri.reduce($aug_uri_clean) |$result, $value| {
      zip(range(1, size($value[1].split(' '))), $value[1].split(' ')).reduce($result) | $inner_result, $inner_value | {
        concat($inner_result, "set uri[${value[0]}]/${inner_value[0]} '${inner_value[1]}'")
      }
    }

  } else {
    $aug_uri = undef
  }

  # base
  if (has_key($ldap, 'base') and $ldap['base'] != undef) {
    $base = $ldap['base']

    # Clean the current values first
    $aug_base_clean = ['rm base']

    # Process global keys
    if has_key($base, 'global') {
      $aug_base_global = $base['global'].map | $base_global_url| {
        "set base[last()+1] '${base_global_url}'"
      }
    }

    # Process the rest of the maps
    $aug_base_others = delete($base, 'global').map | $base_others_url| {
      $base_others_url[1].reduce([]) |$result, $value| {
        concat($result, "set base[last()+1]/${base_others_url[0]} '${value}'")
      }
    }

    # Merge all
    $aug_base = flatten(
      concat($aug_base_clean,
        concat($aug_base_global, $aug_base_others)))

  } else {
    $aug_base = undef
  }

  # scope
  if has_key($ldap, 'scope') and $ldap['scope'] != undef {
    $scope = $ldap['scope']

    # Clean the current values first
    $aug_scope_clean = ['rm scope']

    # Process global values first
    if has_key($scope, 'global') {
      $aug_scope_global = ["set scope[last()+1] '${scope['global']}'"]
    }

    # Process the rest of the maps
    $aug_scope_others = delete($scope, 'global').map | $scope_others_url| {
      "set scope[last()+1]/${scope_others_url[0]} '${scope_others_url[1]}'"
    }

    # Merge all
    $aug_scope = flatten(
      concat($aug_scope_clean,
        concat($aug_scope_global, $aug_scope_others)))

  } else {
    $aug_scope = undef
  }

  # ssl
  $aug_ssl = (has_key($ldap, 'ssl') and $ldap['ssl'] != undef) ? {
    true    => "set ssl '${ldap['ssl']}'",
    default => undef,
  }

  # tls_cacertdir
  $aug_tls_cacertdir = (has_key($ldap, 'tls_cacertdir') and $ldap['tls_cacertdir'] != undef) ? {
    true    => "set tls_cacertdir '${ldap['tls_cacertdir']}'",
    default => undef,
  }

  # tls_cacertfile
  $aug_tls_cacertfile = (has_key($ldap, 'tls_cacertfile') and $ldap['tls_cacertfile'] != undef) ? {
    true    => "set tls_cacertfile '${ldap['tls_cacertfile']}'",
    default => undef,
  }

  # tls_reqcert
  $aug_tls_reqcert = (has_key($ldap, 'tls_reqcert') and $ldap['tls_reqcert'] != undef) ? {
    true    => "set tls_reqcert '${ldap['tls_reqcert']}'",
    default => undef,
  }

  # tls_randfile
  $aug_tls_randfile = (has_key($ldap, 'tls_randfile') and $ldap['tls_randfile'] != undef) ? {
    true    => "set tls_randfile '${ldap['tls_randfile']}'",
    default => undef,
  }

  # tls_ciphers
  $aug_tls_ciphers = (has_key($ldap, 'tls_ciphers') and $ldap['tls_ciphers'] != undef) ? {
    true    => "set tls_ciphers '${ldap['tls_ciphers']}'",
    default => undef,
  }

  # tls_cert
  $aug_tls_cert = (has_key($ldap, 'tls_cert') and $ldap['tls_cert'] != undef) ? {
    true    => "set tls_cert '${ldap['tls_cert']}'",
    default => undef,
  }

  # tls_key
  $aug_tls_key = (has_key($ldap, 'tls_key') and $ldap['tls_key'] != undef) ? {
    true    => "set tls_key '${ldap['tls_key']}'",
    default => undef,
  }

  # timelimit
  $aug_timelimit = (has_key($ldap, 'timelimit') and $ldap['timelimit'] != undef) ? {
    true    => "set timelimit '${ldap['timelimit']}'",
    default => undef,
  }

  # bind_timelimit
  $aug_bind_timelimit = (has_key($ldap, 'bind_timelimit') and $ldap['bind_timelimit'] != undef) ? {
    true    => "set bind_timelimit '${ldap['bind_timelimit']}'",
    default => undef,
  }

  # idle_timelimit
  $aug_idle_timelimit = (has_key($ldap, 'idle_timelimit') and $ldap['idle_timelimit'] != undef) ? {
    true    => "set idle_timelimit '${ldap['idle_timelimit']}'",
    default => undef,
  }

  # uid
  $aug_uid = (has_key($ldap, 'uid') and $ldap['uid'] != undef) ? {
    true    => "set uid '${ldap['uid']}'",
    default => undef,
  }

  # gid
  $aug_gid = (has_key($ldap, 'gid') and $ldap['gid'] != undef) ? {
    true    => "set gid '${ldap['gid']}'",
    default => undef,
  }

  # threads
  $aug_threads = (has_key($ldap, 'threads') and $ldap['threads'] != undef) ? {
    true    => "set threads '${ldap['threads']}'",
    default => undef,
  }

  # ldap_version
  $aug_ldap_version = (has_key($ldap, 'ldap_version') and $ldap['ldap_version'] != undef) ? {
    true    => "set ldap_version '${ldap['ldap_version']}'",
    default => undef,
  }

  # binddn
  $aug_binddn = (has_key($ldap, 'binddn') and $ldap['binddn'] != undef) ? {
    true    => "set binddn '${ldap['binddn']}'",
    default => undef,
  }

  # bindpw
  $aug_bindpw = (has_key($ldap, 'bindpw') and $ldap['bindpw'] != undef) ? {
    true    => "set bindpw '${ldap['bindpw']}'",
    default => undef,
  }

  # rootpwmoddn
  $aug_rootpwmoddn = (has_key($ldap, 'rootpwmoddn') and $ldap['rootpwmoddn'] != undef) ? {
    true    => "set rootpwmoddn '${ldap['rootpwmoddn']}'",
    default => undef,
  }

  # rootpwmodpw
  $aug_rootpwmodpw = (has_key($ldap, 'rootpwmodpw') and $ldap['rootpwmodpw'] != undef) ? {
    true    => "set bindpw '${ldap['rootpwmodpw']}'",
    default => undef,
  }

  # sasl_mech
  $aug_sasl_mech = (has_key($ldap, 'sasl_mech') and $ldap['sasl_mech'] != undef)? {
    true    => "set sasl_mech '${ldap['sasl_mech']}'",
    default => undef,
  }

  # sasl_realm
  $aug_sasl_realm = (has_key($ldap, 'sasl_realm') and $ldap['sasl_realm'] != undef) ? {
    true    => "set sasl_realm '${ldap['sasl_realm']}'",
    default => undef,
  }

  # sasl_authcid
  $aug_sasl_authcid = (has_key($ldap, 'sasl_authcid') and $ldap['sasl_authcid'] != undef) ? {
    true    => "set sasl_authcid '${ldap['sasl_authcid']}'",
    default => undef,
  }

  # sasl_secprops
  $aug_sasl_secprops = (has_key($ldap, 'sasl_secprops') and $ldap['sasl_secprops'] != undef) ? {
    true    => "set sasl_secprops '${ldap['sasl_secprops']}'",
    default => undef,
  }

  # sasl_canonicalize
  $aug_sasl_canonicalize = (has_key($ldap, 'sasl_canonicalize') and $ldap['sasl_canonicalize'] != undef) ? {
    true    => "set sasl_canonicalize '${ldap['sasl_canonicalize']}'",
    default => undef,
  }

  # krb5_ccname
  $aug_krb5_ccname = (has_key($ldap, 'krb5_ccname') and $ldap['krb5_ccname'] != undef) ? {
    true    => "set krb5_ccname '${ldap['krb5_ccname']}'",
    default => undef,
  }

  # deref
  $aug_deref = (has_key($ldap, 'deref') and $ldap['deref'] != undef) ? {
    true    => "set deref '${ldap['deref']}'",
    default => undef,
  }

  # referrals
  $aug_referrals = (has_key($ldap, 'referrals') and $ldap['referrals'] != undef) ? {
    true    => "set referrals '${ldap['referrals']}'",
    default => undef,
  }

  # reconnect_sleeptime
  $aug_reconnect_sleeptime = (has_key($ldap, 'reconnect_sleeptime') and $ldap['reconnect_sleeptime'] != undef) ? {
    true    => "set reconnect_sleeptime '${ldap['reconnect_sleeptime']}'",
    default => undef,
  }

  # reconnect_retrytime
  $aug_reconnect_retrytime = (has_key($ldap, 'reconnect_retrytime') and $ldap['reconnect_retrytime'] != undef) ? {
    true    => "set reconnect_retrytime '${ldap['reconnect_retrytime']}'",
    default => undef,
  }

  # pagesize
  $aug_pagesize = (has_key($ldap, 'pagesize') and $ldap['pagesize'] != undef) ? {
    true    => "set pagesize '${ldap['pagesize']}'",
    default => undef,
  }

  # nss_initgroups_ignoreusers
  if has_key($ldap, 'nss_initgroups_ignoreusers') and $ldap['nss_initgroups_ignoreusers'] != undef {
    $nss_initgroups_ignoreusers = $ldap['nss_initgroups_ignoreusers']

    # Clean the current values first
    $aug_nss_initgroups_ignoreusers_clean = ['rm nss_initgroups_ignoreusers']

    # Create a new array with all the augeas operations
    $aug_nss_initgroups_ignoreusers_expr = $nss_initgroups_ignoreusers.map |$index, $value| {
      "set nss_initgroups_ignoreusers/${index} ${value}"
    }

    # Merge all
    $aug_nss_initgroups_ignoreusers = concat($aug_nss_initgroups_ignoreusers_clean, $aug_nss_initgroups_ignoreusers_expr)

  } else {
    $aug_nss_initgroups_ignoreusers = ['rm nss_initgroups_ignoreusers']
  }

  # nss_min_uid
  $aug_nss_min_uid = (has_key($ldap, 'nss_min_uid') and $ldap['nss_min_uid'] != undef)? {
    true    => "set nss_min_uid '${ldap['nss_min_uid']}'",
    default => undef,
  }

  # nss_nested_groups
  $aug_nss_nested_groups = (has_key($ldap, 'nss_nested_groups') and $ldap['nss_nested_groups'] != undef) ? {
    true    => "set nss_nested_groups '${ldap['nss_nested_groups']}'",
    default => undef,
  }

  # nss_getgrent_skipmembers
  $aug_nss_getgrent_skipmembers = (has_key($ldap, 'nss_getgrent_skipmembers') and $ldap['nss_getgrent_skipmembers'] != undef) ? {
    true    => "set nss_getgrent_skipmembers '${ldap['nss_getgrent_skipmembers']}'",
    default => undef,
  }

  # nss_disable_enumeration
  $aug_nss_disable_enumeration = (has_key($ldap, 'nss_disable_enumeration') and $ldap['nss_disable_enumeration'] != undef) ? {
    true    => "set nss_disable_enumeration '${ldap['nss_disable_enumeration']}'",
    default => undef,
  }

  # validnames
  $aug_validnames = (has_key($ldap, 'validnames') and $ldap['validnames'] != undef) ? {
    true    => "set validnames '${ldap['validnames']}'",
    default => undef,
  }

  # ignorecase
  $aug_ignorecase = (has_key($ldap, 'ignorecase') and $ldap['ignorecase'] != undef) ? {
    true    => "set ignorecase '${ldap['ignorecase']}'",
    default => undef,
  }

  # pam_password_prohibit_message
  $aug_pam_password_prohibit_message = (has_key($ldap, 'pam_password_prohibit_message') and $ldap['pam_password_prohibit_message'] != undef) ? {
    true    => "set pam_password_prohibit_message '${ldap['pam_password_prohibit_message']}'",
    default => undef,
  }

  # reconnect_invalidate
  $aug_reconnect_invalidate = (has_key($ldap, 'reconnect_invalidate') and $ldap['reconnect_invalidate'] != undef) ? {
    true    => "set reconnect_invalidate '${ldap['reconnect_invalidate']}'",
    default => undef,
  }

  # cache
  $aug_cache = (has_key($ldap, 'cache') and $ldap['cache'] != undef) ? {
    true    => "set cache '${ldap['cache']}'",
    default => undef,
  }

  # log
  $aug_log = (has_key($ldap, 'log') and $ldap['log'] != undef) ? {
    true    => "set log '${ldap['log']}'",
    default => undef,
  }

  # pam_authc_ppolicy
  $aug_pam_authc_ppolicy = (has_key($ldap, 'pam_authc_ppolicy') and $ldap['pam_authc_ppolicy'] != undef) ? {
    true    => "set pam_authc_ppolicy '${ldap['pam_authc_ppolicy']}'",
    default => undef,
  }

  # pam_authz_search
  $aug_pam_authz_search = (has_key($ldap, 'pam_authz_search') and $ldap['pam_authz_search'] != undef) ? {
    true    => "set pam_authz_search '${ldap['pam_authz_search']}'",
    default => undef,
  }

  # filter
  if has_key($ldap, 'filter') and $ldap['filter'] != undef {

    $filter = $ldap['filter']

    # Clean the current values first
    $aug_filter_clean = ['rm filter/*']

    # Process maps
    $aug_filter_expressions = $filter.map | $filter_expressions| {
      "set filter[last()+1]/${filter_expressions[0]} '${filter_expressions[1]}'"
    }

    # Merge all
    $aug_filter = concat($aug_filter_clean, $aug_filter_expressions)

    } else {
      $aug_filter = undef
    }

  # map
  if has_key($ldap, 'map') and $ldap['map'] != undef {
    $map = $ldap['map']

    # Empty.
    $aug_map_clean = []

    # Process maps
    $aug_map_temp = $map.map | $map_expressions| {
      $map_expressions[1].map |$value| {
        "set map[${map_expressions[0]}/${value[0]}]/${map_expressions[0]}/${value[0]} '${value[1]}'"
      }
    }
    # Merge all
    $aug_map = concat($aug_map_clean, $aug_map_temp)

  } else {
    $aug_map = undef
  }


  $augeas_changes = delete_undef_values(flatten([
    $aug_uri,
    $aug_base,
    $aug_scope,
    $aug_ssl,
    $aug_tls_cacertdir,
    $aug_tls_cacertfile,
    $aug_tls_reqcert,
    $aug_tls_randfile,
    $aug_tls_ciphers,
    $aug_tls_cert,
    $aug_tls_key,
    $aug_timelimit,
    $aug_bind_timelimit,
    $aug_idle_timelimit,
    $aug_uid,
    $aug_gid,
    $aug_threads,
    $aug_ldap_version,
    $aug_binddn,
    $aug_bindpw,
    $aug_rootpwmoddn,
    $aug_rootpwmodpw,
    $aug_sasl_mech,
    $aug_sasl_realm,
    $aug_sasl_authcid,
    $aug_sasl_secprops,
    $aug_sasl_canonicalize,
    $aug_krb5_ccname,
    $aug_deref,
    $aug_referrals,
    $aug_reconnect_sleeptime,
    $aug_reconnect_retrytime,
    $aug_pagesize,
    $aug_nss_initgroups_ignoreusers,
    $aug_nss_min_uid,
    $aug_nss_nested_groups,
    $aug_nss_getgrent_skipmembers,
    $aug_nss_disable_enumeration,
    $aug_validnames,
    $aug_ignorecase,
    $aug_pam_password_prohibit_message,
    $aug_reconnect_invalidate,
    $aug_cache,
    $aug_log,
    $aug_pam_authc_ppolicy,
    $aug_pam_authz_search,
    $aug_filter,
    $aug_map,
  ]))

  file { '/etc/nslcd.conf':
    mode  => '0400',
    owner => 'root',
    group => 'root',
  }

  augeas { '/etc/nslcd.conf':
    lens      => 'nslcd.lns',
    incl      => '/etc/nslcd.conf',
    changes   => $augeas_changes,
    load_path => "/usr/share/augeas/lenses:${settings::vardir}/lib/augeas/lenses"
  }
}
