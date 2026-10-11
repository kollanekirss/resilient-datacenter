<?php
/* OPNsense 26.7 restricted operational channel and firewall generation guard.
 * Install as /conf/rdc-appliance/helper.php, root:wheel 0600. The bundle's
 * rdcappliance.inc loads this file once through the firewall plugin mechanism.
 * Inclusion declares the plugin only. Direct CLI invocation dispatches JSON.
 * Source-reviewed, not a substitute for the documented guest/packet lab.
 */
declare(strict_types=1);

const RDC_DIR = '/conf/rdc-appliance';
const RDC_PLUGIN = '/usr/local/etc/inc/plugins.inc.d/rdcappliance.inc';

function rdc_assert(bool $ok): void {
    if (!$ok) throw new RuntimeException('router-operation-refused');
}

function rdc_request(array $request): array {
    $action = $request['action'] ?? '';
    $keys = ['action', 'plan_id', 'nonce'];
    if ($action === 'apply-policy') {
        $keys = array_merge($keys, ['stage', 'operation_id', 'expected_digest', 'expected_boot_id']);
        rdc_assert(in_array($request['stage'] ?? '', ['bootstrap', 'transit'], true));
        rdc_assert(is_string($request['operation_id'] ?? null) && preg_match('/^[a-f0-9]{64}$/D', $request['operation_id']) === 1);
    } elseif ($action === 'export-config') {
        $keys = array_merge($keys, ['expected_digest', 'expected_boot_id']);
    } else {
        rdc_assert($action === 'inspect');
    }
    $actual = array_keys($request); sort($actual); sort($keys);
    rdc_assert($actual === $keys);
    foreach (['plan_id', 'expected_digest', 'expected_boot_id'] as $key) {
        if (isset($request[$key])) rdc_assert(is_string($request[$key]) && preg_match('/^[a-f0-9]{64}$/D', $request[$key]) === 1);
    }
    rdc_assert(is_string($request['nonce'] ?? null) && preg_match('/^[a-f0-9]{32}$/D', $request['nonce']) === 1);
    return $request;
}

function rdc_read(string $path, int $maximum = 524288, bool $private = true): string {
    for ($part = $path; $part !== '/'; $part = dirname($part)) rdc_assert(!is_link($part));
    $st = lstat($path);
    rdc_assert(is_array($st) && ($st['mode'] & 0170000) === 0100000 && $st['uid'] === 0 && $st['nlink'] === 1 && $st['size'] <= $maximum);
    if ($private) rdc_assert(($st['mode'] & 0777) === 0600);
    $data = file_get_contents($path, false, null, 0, $maximum + 1);
    rdc_assert(is_string($data) && strlen($data) <= $maximum);
    return $data;
}

function rdc_json(string $path): array {
    $value = json_decode(rdc_read($path), true, 32, JSON_THROW_ON_ERROR);
    rdc_assert(is_array($value));
    return $value;
}

function rdc_write(string $path, array $value): void {
    // All callers select fixed private paths; no request-provided path is used.
    $directory = dirname($path);
    rdc_assert(!is_link($directory) && is_dir($directory));
    $st = stat($directory);
    rdc_assert($st['uid'] === 0 && ($st['mode'] & 0777) === 0700 && !is_link($path));
    $temp = $directory . '/.pending-' . bin2hex(random_bytes(16));
    $file = fopen($temp, 'x+b'); rdc_assert($file !== false);
    try {
        rdc_assert(chmod($temp, 0600));
        $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
        rdc_assert(fwrite($file, $encoded) === strlen($encoded) && fflush($file) && fsync($file));
        rdc_assert(rename($temp, $path));
    } finally {
        fclose($file);
        if (file_exists($temp)) unlink($temp);
    }
    // FreeBSD/PHP permits opening a directory descriptor for fsync.
    $dir = fopen($directory, 'r'); rdc_assert($dir !== false);
    try { rdc_assert(fsync($dir)); } finally { fclose($dir); }
}

function rdc_exec(array $argv, bool $optional = false, int $timeout = 20): string {
    rdc_assert(is_string($argv[0]) && str_starts_with($argv[0], '/'));
    $pipes = [];
    $process = proc_open($argv, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes,
        '/', ['PATH' => '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin', 'LANG' => 'C']);
    rdc_assert(is_resource($process)); fclose($pipes[0]);
    stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
    $start = microtime(true); $out = ''; $err = ''; $code = -1;
    try {
        do {
            $out .= stream_get_contents($pipes[1]); $err .= stream_get_contents($pipes[2]);
            rdc_assert(strlen($out) + strlen($err) <= 524288 && microtime(true) - $start <= $timeout);
            $status = proc_get_status($process);
            if (!$status['running']) { $code = $status['exitcode']; break; }
            usleep(10000);
        } while (true);
        $out .= stream_get_contents($pipes[1]); $err .= stream_get_contents($pipes[2]);
        rdc_assert(strlen($out) + strlen($err) <= 524288 && ($code === 0 || $optional));
    } finally {
        if (proc_get_status($process)['running']) proc_terminate($process, 9);
        fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
    }
    return $code === 0 ? $out : '';
}

function rdc_range(string $cidr): array {
    $parts = explode('/', $cidr);
    rdc_assert(count($parts) === 2 && ctype_digit($parts[1]) && (int)$parts[1] <= 32);
    $address = ip2long($parts[0]); rdc_assert($address !== false);
    $mask = (int)$parts[1] === 0 ? 0 : ((0xffffffff << (32 - (int)$parts[1])) & 0xffffffff);
    $start = $address & $mask;
    rdc_assert(long2ip($start) . '/' . (int)$parts[1] === $cidr);
    return [$start, $start | (~$mask & 0xffffffff)];
}

function rdc_upstream_allowed(array $manifest, array $upstream): bool {
    try {
        rdc_assert(is_array($upstream['cidrs']) && count($upstream['cidrs']) > 0 && count($upstream['cidrs']) <= 16);
        $gateway = ip2long($upstream['gateway'] ?? ''); rdc_assert($gateway !== false); $gatewayMatch = false;
        foreach ($upstream['cidrs'] as $cidr) {
            rdc_assert(in_array($cidr, $manifest['upstream_cidrs'], true));
            [$a, $b] = rdc_range($cidr);
            if ($gateway > $a && $gateway < $b) $gatewayMatch = true;
            foreach ($manifest['protected_cidrs'] as $protected) {
                [$c, $d] = rdc_range($protected); rdc_assert($b < $c || $d < $a);
            }
        }
        return $gatewayMatch;
    } catch (Throwable $e) { return false; }
}

function rdc_manifest(): array {
    $manifest = rdc_json(RDC_DIR . '/manifest.json');
    rdc_assert(($manifest['schema'] ?? null) === 1 && ($manifest['version'] ?? '') === '26.7');
    rdc_assert(preg_match('/^[a-f0-9]{64}$/D', $manifest['plan_id'] ?? '') === 1);
    rdc_assert(hash('sha256', rdc_read(RDC_DIR . '/helper.php')) === ($manifest['helper_sha256'] ?? ''));
    rdc_assert(hash('sha256', rdc_read(RDC_PLUGIN)) === $manifest['plugin_sha256']);
    return $manifest;
}

function rdc_boot(): string {
    return hash('sha256', rdc_exec(['/sbin/sysctl', '-n', 'kern.boottime']));
}

function rdc_interfaces(string $raw): array {
    $result = []; $device = null;
    foreach (explode("\n", $raw) as $line) {
        if (preg_match('/^(vtnet[0-9]{1,2}):/', $line, $m)) $device = $m[1];
        elseif (preg_match('/^[A-Za-z0-9]+:/', $line)) $device = null;
        if ($device !== null && preg_match('/^\s+ether ([0-9a-f:]{17})\s*$/', $line, $m)) {
            rdc_assert(!isset($result[$m[1]])); $result[$m[1]] = $device;
        }
    }
    return $result;
}

function rdc_upstream(): array {
    global $config;
    $device = $config['interfaces']['wan']['if'] ?? '';
    rdc_assert(preg_match('/^vtnet[0-9]{1,2}$/D', $device) === 1);
    $raw = rdc_exec(['/sbin/ifconfig', $device]); $cidrs = [];
    preg_match_all('/\binet ([0-9.]+) netmask 0x([0-9a-f]{8})\b/', $raw, $matches, PREG_SET_ORDER);
    foreach ($matches as $m) {
        $mask = hexdec($m[2]); $bits = str_pad(decbin($mask), 32, '0', STR_PAD_LEFT);
        rdc_assert(preg_match('/^1*0*$/D', $bits) === 1 && ip2long($m[1]) !== false);
        $cidrs[] = long2ip(ip2long($m[1]) & $mask) . '/' . substr_count($bits, '1');
    }
    sort($cidrs); $route = rdc_exec(['/sbin/route', '-n', 'get', 'default'], true);
    $gateway = null;
    if (preg_match('/^\s*gateway:\s*([0-9.]+)\s*$/m', $route, $m) &&
        preg_match('/^\s*interface:\s*' . preg_quote($device, '/') . '\s*$/m', $route)) $gateway = $m[1];
    return ['cidrs' => $cidrs, 'gateway' => $gateway];
}

function rdc_permitted(array $manifest, array $upstream, string $boot): bool {
    global $config;
    try {
        $permit = rdc_json(RDC_DIR . '/permit.json');
        return ($config['rdcappliance']['stage'] ?? '') === 'transit' &&
            $permit['boot_id'] === $boot && $permit['plan_id'] === $manifest['plan_id'] &&
            $permit['upstream'] === $upstream && rdc_upstream_allowed($manifest, $upstream);
    } catch (Throwable $e) { return false; }
}

function rdc_destinations_except(string $address): array {
    // Exactly partition IPv4 minus the management endpoint. This avoids relying
    // on undocumented pfctl -k negation and preserves the live host->router SSH.
    $ip = ip2long($address); rdc_assert($ip !== false); $result = [];
    for ($prefix = 1; $prefix <= 32; $prefix++) {
        $mask = (0xffffffff << (32 - $prefix)) & 0xffffffff;
        $sibling = (($ip & $mask) ^ (1 << (32 - $prefix))) & 0xffffffff;
        $result[] = long2ip($sibling) . '/' . $prefix;
    }
    return $result;
}

function rdc_kill_forwarding_states(array $manifest, ?callable $run = null): void {
    $run ??= 'rdc_exec';
    foreach ($manifest['guest_cidrs'] as $cidr) {
        rdc_range($cidr);
        $run(['/sbin/pfctl', '-M', '-k', $cidr]);
        $run(['/sbin/pfctl', '-M', '-k', '0.0.0.0/0', '-k', $cidr]);
    }
    rdc_assert(ip2long($manifest['host_ip']) !== false);
    foreach (rdc_destinations_except($manifest['management_ip']) as $destination) {
        $run(['/sbin/pfctl', '-M', '-k', $manifest['host_ip'] . '/32', '-k', $destination]);
    }
}

function rdc_transport_devices(array $manifest): array {
    $result = [];
    foreach ($manifest['devices'] as $name => $device) {
        rdc_assert(preg_match('/^vtnet[0-9]{1,2}$/D', $device) === 1);
        if (preg_match('/^opt[0-9]+$/D', $name)) $result[] = $device;
    }
    rdc_assert(count(array_unique($manifest['devices'])) === count($manifest['devices']) && isset($manifest['devices']['lan']));
    return $result;
}

function rdc_quiesce(array $manifest, ?callable $run = null): void {
    $run ??= 'rdc_exec';
    // Local management is not forwarded, so it survives this global safety gate.
    // WAN remains up for its lease/route; forwarding=0 also covers host updates
    // from LAN. States are killed again after the effective deny rules load.
    $run(['/sbin/sysctl', 'net.inet.ip.forwarding=0']);
    foreach (rdc_transport_devices($manifest) as $device) $run(['/sbin/ifconfig', $device, 'down']);
    rdc_kill_forwarding_states($manifest, $run);
}

function rdc_restore_devices(array $devices, callable $loaded, ?callable $run = null): void {
    $run ??= 'rdc_exec';
    foreach ($devices as $device) {
        rdc_assert(preg_match('/^vtnet[0-9]{1,2}$/D', $device) === 1 && $loaded());
        $run(['/sbin/ifconfig', $device, 'up']);
    }
    rdc_assert($loaded());
    $run(['/sbin/sysctl', 'net.inet.ip.forwarding=1']);
}

function rdc_guard_token(array $manifest, string $boot): string {
    return substr(hash('sha256', $manifest['plan_id'] . ':' . $boot), 0, 32);
}

function rdc_guard_loaded(array $manifest, string $token, string $rules): bool {
    if (!preg_match('/^[a-f0-9]{32}$/D', $token)) return false;
    foreach ($manifest['devices'] as $interface => $device) {
        if ($interface !== 'lan' && !preg_match('/^opt[0-9]+$/D', $interface)) continue;
        $label = 'rdc_guard_' . $token . '_' . $interface;
        if (!preg_match('/^block(?![^\n]*\binet6\b)[^\n]*\bin\s+quick\s+on\s+' . preg_quote($device, '/') .
            '\s[^\n]*label "' . $label . '"/m', $rules)) return false;
    }
    return isset($manifest['devices']['lan'], $manifest['devices']['opt1'], $manifest['devices']['opt2']);
}

function rdc_register_guard($fw, array $manifest, string $token): void {
    // FilterRule's descr is only a comment; explicit labels survive pfctl -sr.
    foreach ($manifest['devices'] as $interface => $device) {
        if ($interface !== 'lan' && !preg_match('/^opt[0-9]+$/D', $interface)) continue;
        if ($interface === 'lan') {
            foreach ([22, 443] as $port) $fw->registerFilterRule(90, [
                'interface' => 'lan', 'direction' => 'in', 'ipprotocol' => 'inet', 'type' => 'pass',
                'quick' => true, 'protocol' => 'tcp', 'from' => 'any', 'to' => $manifest['management_ip'],
                'to_port' => $port, 'statetype' => 'keep', 'descr' => 'RDC local administration']);
        }
        foreach ([['tcp', 53], ['udp', 53], ['udp', 123]] as [$protocol, $port]) {
            $fw->registerFilterRule(90, ['interface' => $interface, 'direction' => 'in', 'ipprotocol' => 'inet',
                'type' => 'pass', 'quick' => true, 'protocol' => $protocol, 'from' => 'any', 'to' => '(self)',
                'to_port' => $port, 'statetype' => 'keep', 'descr' => 'RDC local services']);
        }
        if ($interface === 'opt2') {
            $fw->registerFilterRule(90, ['interface' => $interface, 'direction' => 'in', 'ipprotocol' => 'inet',
                'type' => 'pass', 'quick' => true, 'protocol' => 'udp', 'from_port' => 68, 'to_port' => 67,
                'to' => '255.255.255.255', 'descr' => 'RDC workload DHCP']);
        }
        $fw->registerFilterRule(100, ['interface' => $interface, 'direction' => 'in', 'ipprotocol' => 'inet46',
            'type' => 'block', 'quick' => true, 'from' => 'any', 'to' => 'any',
            'label' => 'rdc_guard_' . $token . '_' . $interface, 'descr' => 'RDC lease guard blocked']);
    }
}

function rdc_revoke(array $manifest): void {
    $boot = rdc_boot();
    rdc_write(RDC_DIR . '/guard.json', ['plan_id' => $manifest['plan_id'], 'boot_id' => $boot,
        'token' => rdc_guard_token($manifest, $boot), 'status' => 'quiesced']);
    // Even if a later step fails, forwarding stays disabled and transport stays
    // down. A post-load hook may restore it only after observing this guard.
    rdc_quiesce($manifest);
    if (is_file(RDC_DIR . '/permit.json')) rdc_assert(unlink(RDC_DIR . '/permit.json'));
}

function rdc_restore_guarded_links($verbose = false): void {
    if (!is_file(RDC_DIR . '/guard.json')) return;
    $manifest = rdc_manifest(); $record = rdc_json(RDC_DIR . '/guard.json'); $boot = rdc_boot();
    $loaded = function() use ($manifest, $record, $boot): bool {
        return $record['plan_id'] === $manifest['plan_id'] && $record['boot_id'] === $boot &&
            $boot === rdc_boot() && rdc_guard_loaded($manifest, $record['token'], rdc_exec(['/sbin/pfctl', '-sr']));
    };
    rdc_assert($loaded());
    // Kill again after the deny rules exist. In particular a host LAN flow could
    // have acquired a state while old transit rules were still installed.
    rdc_kill_forwarding_states($manifest);
    rdc_restore_devices(rdc_transport_devices($manifest), $loaded);
    rdc_assert(unlink(RDC_DIR . '/guard.json'));
}

function rdcappliance_configure(): array {
    return ['local' => ['rdc_restore_guarded_links'], 'newwanip' => ['rdc_restore_guarded_links']];
}

function rdcappliance_firewall($fw): void {
    global $config;
    try {
        $manifest = rdc_manifest(); $boot = rdc_boot();
        if (rdc_permitted($manifest, rdc_upstream(), $boot)) return;
        $token = rdc_guard_token($manifest, $boot);
        if (!rdc_guard_loaded($manifest, $token, rdc_exec(['/sbin/pfctl', '-sr']))) rdc_revoke($manifest);
        rdc_register_guard($fw, $manifest, $token);
    } catch (Throwable $e) {
        // A broken manifest/plugin must not leave an old transit ruleset live.
        rdc_exec(['/sbin/sysctl', 'net.inet.ip.forwarding=0']);
        foreach ($config['interfaces'] ?? [] as $name => $interface) {
            if (($name === 'wan' || preg_match('/^opt[0-9]+$/D', $name)) &&
                preg_match('/^vtnet[0-9]{1,2}$/D', $interface['if'] ?? '')) {
                rdc_exec(['/sbin/ifconfig', $interface['if'], 'down']);
            }
        }
        throw new RuntimeException('router-guard-refused');
    }
}

function rdc_sshd_restricted(): bool {
    $raw = rdc_exec(['/usr/sbin/sshd', '-T']);
    $required = ['passwordauthentication no', 'kbdinteractiveauthentication no', 'authenticationmethods publickey',
        'permitrootlogin forced-commands-only', 'permittty no', 'allowtcpforwarding no', 'allowstreamlocalforwarding no',
        'allowagentforwarding no', 'x11forwarding no', 'permittunnel no', 'permituserrc no',
        'forcecommand /usr/local/bin/php /conf/rdc-appliance/helper.php'];
    foreach ($required as $line) if (!in_array($line, explode("\n", $raw), true)) return false;
    return true;
}

function rdc_inspect(array $manifest): array {
    global $config;
    $xml = rdc_read('/conf/config.xml', 524288, false);
    $boot = rdc_boot(); $rootKind = 'unknown'; $rootDevice = '';
    foreach (explode("\n", rdc_exec(['/sbin/mount', '-p'])) as $line) {
        $parts = preg_split('/\s+/', trim($line));
        if (count($parts) >= 4 && $parts[1] === '/') {
            $rootDevice = $parts[0];
            if (($parts[2] === 'ufs' && preg_match('~^/dev/(?:gpt/|ada[0-9]|da[0-9]|vtbd[0-9])~', $rootDevice)) ||
                ($parts[2] === 'zfs' && preg_match('~^[a-zA-Z0-9_-]+/ROOT/[a-zA-Z0-9_-]+$~D', $rootDevice))) $rootKind = 'installed-disk';
        }
    }
    $listeners = [];
    foreach (explode("\n", rdc_exec(['/usr/bin/sockstat', '-4', '-6', '-l'])) as $line) {
        $parts = preg_split('/\s+/', trim($line));
        if (count($parts) < 7 || !preg_match('/^(tcp|udp)[46]/', $parts[4], $proto)) continue;
        if (!preg_match('/^(.*):([0-9]+)$/D', $parts[5], $address)) continue;
        $listeners[] = ['address' => trim($address[1], '[]'), 'port' => (int)$address[2], 'protocol' => $proto[1]];
    }
    $ifmap = rdc_interfaces(rdc_exec(['/sbin/ifconfig', '-a']));
    $dns = rdc_read('/usr/local/etc/dnsmasq.conf', 524288, false);
    rdc_assert(count(glob('/usr/local/etc/dnsmasq.conf.d/*.conf') ?: []) === 0);
    $dhcp = []; preg_match_all('/^dhcp-range=tag:(vtnet[0-9]{1,2}),([^\n]+)$/m', $dns, $ranges, PREG_SET_ORDER);
    // Unknown/broad/IPv6 ranges are a failure, not silently ignored.
    rdc_assert(count($ranges) === preg_match_all('/^dhcp-range=/m', $dns));
    foreach ($ranges as $range) {
        rdc_assert(!str_contains($range[2], ':'));
        foreach ($config['interfaces'] as $zone => $interface) if (($interface['if'] ?? '') === $range[1]) $dhcp[] = $zone;
    }
    $ra = preg_match('/^enable-ra\s*$/m', $dns) || rdc_exec(['/bin/pgrep', '-x', 'radvd'], true) !== '' ? ['unknown'] : [];
    $rules = rdc_exec(['/sbin/pfctl', '-sr']); $nat = rdc_exec(['/sbin/pfctl', '-sn']);
    $version = json_decode(rdc_read('/usr/local/opnsense/version/core', 65536, false), true, 16, JSON_THROW_ON_ERROR);
    return ['schema' => 1, 'plan_id' => $manifest['plan_id'], 'vmid' => $manifest['vmid'], 'boot_id' => $boot,
        'config_xml' => $xml, 'config_digest' => hash('sha256', $xml), 'root_kind' => $rootKind, 'root_device' => $rootDevice,
        'os_version' => $version['product_version'] ?? '', 'interface_map' => $ifmap,
        'stage' => $config['rdcappliance']['stage'] ?? 'unknown', 'listeners' => $listeners,
        'dhcp_interfaces' => array_values(array_unique($dhcp)), 'ra_interfaces' => $ra,
        'ipv6_enabled' => empty($config['OPNsense']['Interfaces']['settings']['disableipv6']), 'ssh_restricted' => rdc_sshd_restricted(),
        'guard_installed' => true, 'guard_blocking' => rdc_guard_loaded($manifest, rdc_guard_token($manifest, $boot), $rules),
        'rules_id' => hash('sha256', $rules), 'nat_id' => hash('sha256', $nat), 'upstream' => rdc_upstream(),
        'last_operation' => is_file(RDC_DIR . '/last-operation.json') ? rdc_json(RDC_DIR . '/last-operation.json') : null,
        'pending_operation' => is_file(RDC_DIR . '/pending.json') ? rdc_json(RDC_DIR . '/pending.json') : null,
        'packet_tests' => 'not-performed'];
}

function rdc_dispatch(): void {
    rdc_assert(PHP_SAPI === 'cli' && posix_geteuid() === 0 && ($_SERVER['SSH_ORIGINAL_COMMAND'] ?? '') === 'rdc-router');
    umask(0077);
    $raw = stream_get_contents(STDIN, 524289); rdc_assert(is_string($raw) && strlen($raw) <= 524288);
    $request = rdc_request(json_decode($raw, true, 32, JSON_THROW_ON_ERROR));
    $manifest = rdc_manifest(); rdc_assert($request['plan_id'] === $manifest['plan_id']);
    require_once('config.inc'); require_once('interfaces.inc'); require_once('filter.inc');
    global $config;
    rdc_assert(($config['rdcappliance']['plan_id'] ?? '') === $manifest['plan_id']);
    $lockpath = RDC_DIR . '/operation.lock'; rdc_assert(!is_link($lockpath));
    $lock = fopen($lockpath, 'c+b'); rdc_assert($lock !== false && chmod($lockpath, 0600) && flock($lock, LOCK_EX | LOCK_NB));
    try {
        $result = rdc_inspect($manifest);
        if ($request['action'] !== 'inspect') {
            rdc_assert($request['expected_digest'] === $result['config_digest'] && $request['expected_boot_id'] === $result['boot_id']);
        }
        if ($request['action'] === 'export-config') {
            $result = array_intersect_key($result, array_flip(['config_xml', 'config_digest', 'boot_id']));
        } elseif ($request['action'] === 'apply-policy') {
            $pending = RDC_DIR . '/pending.json';
            rdc_assert(!file_exists($pending));
            $op = RDC_DIR . '/operations/' . $request['operation_id'] . '.json';
            rdc_assert(!file_exists($op));
            $policy = RDC_DIR . '/' . $request['stage'] . '.xml';
            rdc_assert(hash('sha256', rdc_read($policy)) === $manifest['policies'][$request['stage']]);
            if ($request['stage'] === 'transit') rdc_assert(rdc_upstream_allowed($manifest, $result['upstream']));
            rdc_write($op, ['status' => 'pending', 'request' => $request]);
            rdc_write($pending, ['operation_id' => $request['operation_id']]);
            // First install a deny guard while transport/forwarding are down.
            // The hook runs before pfctl loads rules, so its return alone is not
            // evidence that the new guard exists in the kernel.
            rdc_revoke($manifest);
            filter_configure_sync();
            rdc_restore_guarded_links();
            if ($request['stage'] === 'transit') {
                $upstream = rdc_upstream();
                rdc_assert($upstream === $result['upstream'] && rdc_upstream_allowed($manifest, $upstream));
                rdc_write(RDC_DIR . '/permit.json', ['plan_id' => $manifest['plan_id'],
                    'boot_id' => $result['boot_id'], 'upstream' => $upstream]);
            }
            $config = load_config_from_file($policy);
            rdc_assert(is_array($config) && ($config['rdcappliance']['plan_id'] ?? '') === $manifest['plan_id']);
            rdc_assert(write_config('Appliance policy stage', true) !== -1);
            // Only firewall policy differs. Reloading every service would tear down
            // the management session and turn a successful change into uncertainty.
            filter_configure_sync();
            $after = rdc_inspect($manifest);
            rdc_assert($after['stage'] === $request['stage'] && $after['boot_id'] === $result['boot_id']);
            rdc_assert($request['stage'] === 'bootstrap' ? $after['guard_blocking'] : !$after['guard_blocking']);
            $completed = ['status' => 'complete', 'operation_id' => $request['operation_id'],
                'plan_id' => $manifest['plan_id'], 'stage' => $request['stage'],
                'config_digest' => $after['config_digest'], 'boot_id' => $after['boot_id']];
            rdc_write($op, $completed);
            rdc_write(RDC_DIR . '/last-operation.json', $completed);
            rdc_assert(unlink($pending));
            $result = ['operation_id' => $request['operation_id'], 'applied' => true];
        }
        $result['nonce'] = $request['nonce'];
        $encoded = json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        rdc_assert(strlen($encoded) <= 1048576); echo $encoded;
    } finally { flock($lock, LOCK_UN); fclose($lock); }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try { rdc_dispatch(); } catch (Throwable $e) {
        // Fixed diagnostic only: never expose config, keys, paths or command output.
        fwrite(STDERR, "router-operation-refused\n"); exit(64);
    }
}
