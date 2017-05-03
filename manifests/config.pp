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
#   [*tls_checkpeer*]
#   [*tls_cacertdir*]
#   [*tls_reqcert*]
#   [*timelimit*]
#   [*bind_timelimit*]
#   [*idle_timelimit*]
#   [*binddn*]
#   [*bindpw*]
#
#   The following hash keys for *ldap* are supported for backwards
#   compatibility, but should not be used:
#     [*uris*]
#     [*basedn*]
#
# [*template*]
#   *Deprecated* - Unused name of template file.
#
# === Limitations
#
# This module uses the *Spacevars* Augeas lens, which assumes that the first
# word of each line is a unique key, which is not necessarily true for a number
# of parameters, such as *base*, *scope*, *filter* or *map*.
#
# Handling these parameters correctly requires writing a lens, which is a good
# deal more work.
#
class nss_pam_ldapd::config (
  $ldap = hiera('nss_pam_ldapd::config::ldap', {
    uri              => [ 'ldap://localhost', ],
    base             => 'dc=example,dc=com',
    ssl              => 'start_tls',
    tls_checkpeer    => 'no',
    tls_cacertdir    => undef,
    tls_reqcert      => 'never',
    timelimit        => 120,
    bind_timelimit   => 120,
    idle_timelimit   => 3600,
    binddn           => undef,
    bindpw           => undef,
    homeDirectory    => undef,
    loginShell       => undef,
    pam_authz_search => undef
    }),
  $template = undef
  ) {

  if $template {
    warning("${name} param 'template' is deprecated; please remove")
  }

  if has_key($ldap, 'uri') {
    $ldap_uri_val = is_array($ldap['uri']) ? {
          true    => join($ldap['uri'], ' '),
          default => $ldap['uri'],
      }
  }
  elsif has_key($ldap, 'uris') {

    warning("${name} param 'uris' is deprecated; use 'uri' instead")
    $ldap_uri_val = is_array($ldap['uris']) ? {
          true    => join($ldap['uris'], ' '),
          default => $ldap['uris'],
      }
  }

  if $ldap_uri_val {
    $aug_uri = "set uri '${ldap_uri_val}'"
  }
  else {
    $aug_uri = undef
  }

  if has_key($ldap, 'base') {
    $aug_base = "set base '${ldap['base']}'"
  }
  elsif has_key($ldap, 'basedn') {
    warning("${name} param 'basedn' is deprecated; use 'base' instead")
    $aug_base = "set base '${ldap['basedn']}'"
  }
  else {
    $aug_base = undef
  }

  $aug_ssl = has_key($ldap, 'ssl') ? {
        true    => "set ssl '${ldap['ssl']}'",
        default => undef,
      }

  $aug_tls_checkpeer = has_key($ldap, 'tls_checkpeer') ? {
        true => "set tls_checkpeer '${ldap['tls_checkpeer']}'",
        default => undef,
      }

  $aug_tls_cacertdir = has_key($ldap, 'tls_cacertdir') ? {
        true    => "set tls_cacertdir '${ldap['tls_cacertdir']}'",
        default => undef,
      }

  $aug_tls_reqcert = has_key($ldap, 'tls_reqcert') ? {
        true    => "set tls_reqcert '${ldap['tls_reqcert']}'",
        default => undef,
      }

  $aug_timelimit = has_key($ldap, 'timelimit') ? {
        true    => "set timelimit '${ldap['timelimit']}'",
        default => undef,
      }

  $aug_bind_timelimit = has_key($ldap, 'bind_timelimit') ? {
        true    => "set bind_timelimit '${ldap['bind_timelimit']}'",
        default => undef,
      }

  $aug_idle_timelimit = has_key($ldap, 'idle_timelimit') ? {
        true    => "set idle_timelimit '${ldap['idle_timelimit']}'",
        default => undef,
      }

  $aug_binddn = has_key($ldap, 'binddn') ? {
        true    => "set binddn '${ldap['binddn']}'",
        default => undef,
      }

  $aug_bindpw = has_key($ldap, 'bindpw') ? {
        true    => "set bindpw '${ldap['bindpw']}'",
        default => undef,
      }

  $aug_scope = has_key($ldap, 'scope') ? {
       true    => "set scope '${ldap['scope']}'",
       default => undef,
      }

  $aug_pagesize = has_key($ldap, 'pagesize') ? {
       true    => "set pagesize '${ldap['pagesize']}'",
       default => undef,
      }

  $aug_pam_authz_search = has_key($ldap, 'pam_authz_search') ? {
        true    => "set pam_authz_search '${ldap['pam_authz_search']}'",
        default => undef,
      }

  $aug_home_directory = has_key($ldap, 'homeDirectory') ? {
        true    => "set map '\"passwd homeDirectory ${ldap['homeDirectory']}'\"",
        default => undef,
       }

  $aug_login_shell = has_key($ldap, 'loginShell') ? {
        true    => "set map '\"passwd loginShell ${ldap['loginShell']}'\"",
        default => undef,
      }
  $augeas_changes = delete_undef_values(grep([
      $aug_uri,
      $aug_base,
      $aug_ssl,
      $aug_tls_checkpeer,
      $aug_tls_cacertdir,
      $aug_tls_reqcert,
      $aug_timelimit,
      $aug_bind_timelimit,
      $aug_idle_timelimit,
      $aug_binddn,
      $aug_bindpw,
      $aug_home_directory,
      $aug_login_shell,
      $aug_scope,
      $aug_pagesize,
      $aug_pam_authz_search
  ], '.'))

  file { '/etc/nslcd.conf':
    mode      => '0400',
    owner     => 'root',
    group     => 'root',
  }

  augeas { '/etc/nslcd.conf':
    lens      => 'nslcd.lns',
    incl      => '/etc/nslcd.conf',
    changes   => $augeas_changes,
    load_path => "/usr/share/augeas/lenses:${settings::vardir}/lib/augeas/lenses",
  }
}
