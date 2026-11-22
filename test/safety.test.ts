import { describe, it, expect } from 'vitest';
import { checkCommand } from '../src/safety.js';
import type { GuardOptions } from '../src/safety.js';

const WINDOWS_SSH: GuardOptions = { refuseSelfSevering: true, transport: 'ssh', platform: 'windows' };
const WINDOWS_RDP: GuardOptions = { refuseSelfSevering: true, transport: 'rdp', platform: 'windows' };
const LINUX_SSH: GuardOptions = { refuseSelfSevering: true, transport: 'ssh', platform: 'linux' };
const LINUX_RDP: GuardOptions = { refuseSelfSevering: true, transport: 'rdp', platform: 'linux' };
const WINDOWS_PERMITTING: GuardOptions = { refuseSelfSevering: false, transport: 'ssh', platform: 'windows' };

describe('checkCommand', () => {
  const SEVERING: Array<{ why: string; cmd: string; ctx: GuardOptions }> = [
    { why: 'stopping the sshd service on the ssh transport', cmd: 'Stop-Service sshd', ctx: WINDOWS_SSH },
    { why: 'the named-argument form of the same cmdlet', cmd: 'Stop-Service -Name sshd', ctx: WINDOWS_SSH },
    { why: 'extra whitespace survives normalization', cmd: 'Stop-Service   sshd', ctx: WINDOWS_SSH },
    { why: 'lowercase survives normalization', cmd: 'stop-service sshd', ctx: WINDOWS_SSH },
    { why: 'restarting is as severing as stopping', cmd: 'Restart-Service sshd', ctx: WINDOWS_SSH },
    { why: 'restarting the OpenSSH service by its display name', cmd: 'Restart-Service "OpenSSH SSH Server"', ctx: WINDOWS_SSH },
    { why: 'starting it is refused as well', cmd: 'Start-Service sshd', ctx: WINDOWS_SSH },
    { why: 'cmd.exe service control', cmd: 'net stop sshd', ctx: WINDOWS_SSH },
    { why: 'case and quotes survive normalization', cmd: 'NET STOP "SSHD"', ctx: WINDOWS_SSH },
    { why: 'run-together whitespace survives normalization', cmd: 'net    stop     sshd', ctx: WINDOWS_SSH },
    { why: 'starting it through cmd.exe is refused too', cmd: 'net start sshd', ctx: WINDOWS_SSH },
    { why: 'SC stops the service', cmd: 'sc stop sshd', ctx: WINDOWS_SSH },
    { why: 'SC reconfigures it', cmd: 'sc config sshd restart=false', ctx: WINDOWS_SSH },
    { why: 'SC deletes the service definition', cmd: 'sc delete sshd', ctx: WINDOWS_SSH },
    { why: 'making it a manual service leaves it stopped after boot', cmd: 'Set-Service sshd -StartupType Disabled', ctx: WINDOWS_SSH },
    { why: 'manual services do not start on their own', cmd: 'Set-Service sshd -StartupType Manual', ctx: WINDOWS_SSH },
    { why: 'killing the ssh server process', cmd: 'taskkill /IM sshd.exe', ctx: WINDOWS_SSH },
    { why: 'the forced kill form', cmd: 'taskkill /F /IM sshd.exe', ctx: WINDOWS_SSH },
    { why: 'quoted process image survives normalization', cmd: 'taskkill /im "sshd.exe"', ctx: WINDOWS_SSH },
    { why: 'wrapped in powershell -Command', cmd: 'powershell -Command "Stop-Service sshd"', ctx: WINDOWS_SSH },
    { why: 'wrapped in cmd /c', cmd: 'cmd /c "net stop sshd"', ctx: WINDOWS_SSH },
    { why: 'a compound command whose second half severs', cmd: 'Get-Service sshd; Stop-Service sshd', ctx: WINDOWS_SSH },
    { why: 'a compound command whose first half severs', cmd: 'net stop sshd && net start spooler', ctx: WINDOWS_SSH },
    { why: 'the service carrying the rdp transport', cmd: 'Stop-Service TermService', ctx: WINDOWS_RDP },
    { why: 'cmd.exe form of the rdp transport service', cmd: 'net stop termservice', ctx: WINDOWS_RDP },
    { why: 'SC against the rdp transport service', cmd: 'sc stop TermService', ctx: WINDOWS_RDP },
    { why: 'turning the rdp transport service off at boot', cmd: 'Set-Service Termservice -StartupType Disabled', ctx: WINDOWS_RDP },
    { why: 'the ssh transport is refused even when we are talking over rdp', cmd: 'Stop-Service sshd', ctx: WINDOWS_RDP },
    { why: 'the guard always protects both services regardless of the calling transport', cmd: 'Stop-Service TermService', ctx: WINDOWS_SSH },
    { why: 'net stop termservice severs rdp even when issued over ssh', cmd: 'net stop termservice', ctx: WINDOWS_SSH },
    { why: 'systemd stops the daemon we are logged into', cmd: 'systemctl stop sshd', ctx: LINUX_SSH },
    { why: 'restarting the daemon drops our connection', cmd: 'systemctl restart ssh', ctx: LINUX_SSH },
    { why: 'disabling the unit leaves it stopped at next boot', cmd: 'systemctl disable ssh.service', ctx: LINUX_SSH },
    { why: 'killing the daemon by name', cmd: 'pkill sshd', ctx: LINUX_SSH },
    { why: 'a sudo prefix does not hide the unit', cmd: 'sudo systemctl stop sshd', ctx: LINUX_SSH },
    { why: 'the service form stops the daemon', cmd: 'service ssh restart', ctx: LINUX_SSH },
    { why: 'killall on the daemon token', cmd: 'killall -9 sshd', ctx: LINUX_SSH },
    { why: 'pkill -x targets exactly the daemon', cmd: 'pkill -x sshd', ctx: LINUX_SSH },
    { why: '--now disables and stops in one go', cmd: 'systemctl disable --now sshd', ctx: LINUX_SSH },
    { why: 'sc config start= disabled disables the service at boot', cmd: 'sc config sshd start= disabled', ctx: WINDOWS_SSH },
    { why: 'the reversed parameter order is the same call', cmd: 'Set-Service -StartupType Disabled -Name sshd', ctx: WINDOWS_SSH },
    { why: 'the dashed option spelling is the same call', cmd: 'Set-Service -Name sshd -startup-type disabled', ctx: WINDOWS_SSH },
    { why: 'the reversed form still names the OpenSSH display name', cmd: 'Set-Service -StartupType manual -Name "OpenSSH SSH Server"', ctx: WINDOWS_SSH },
    { why: 'sc start of the rdp service is refused even over the ssh transport', cmd: 'sc start TermService', ctx: WINDOWS_SSH },
    { why: 'sc start of the sshd service is refused symmetrically', cmd: 'sc start sshd', ctx: WINDOWS_SSH },
    { why: 'a per-connection instance name still stops the ssh service family', cmd: 'Stop-Service sshd@1', ctx: WINDOWS_SSH },
    { why: 'Stop-Process kills the daemon process directly', cmd: 'Stop-Process -Name sshd -Force', ctx: WINDOWS_SSH },
    { why: 'Stop-Process with the image name in a filter', cmd: 'Get-Process | Stop-Process -Name sshd', ctx: WINDOWS_SSH },
    { why: 'taskkill by image name without the .exe suffix', cmd: 'taskkill /im sshd', ctx: WINDOWS_SSH },
    { why: 'taskkill with an image-name filter', cmd: 'taskkill /fi "imagename eq sshd.exe"', ctx: WINDOWS_SSH },
    { why: 'sc.exe (explicit image) stopping the daemon', cmd: 'sc.exe stop sshd', ctx: WINDOWS_SSH },
    { why: 'systemctl kill signals the daemon unit', cmd: 'systemctl kill sshd', ctx: LINUX_SSH },
  ];

  it.each(SEVERING)('$why: refuses $cmd with TRANSPORT_SEVERED_RISK', (row) => {
    const verdict = checkCommand(row.cmd, row.ctx);
    expect(verdict.allowed).toBe(false);
    expect(verdict.code).toBe('TRANSPORT_SEVERED_RISK');
  });

  const HARMLESS: Array<{ why: string; cmd: string; ctx: GuardOptions }> = [
    { why: 'inspecting a service changes nothing', cmd: 'Get-Service sshd', ctx: WINDOWS_SSH },
    { why: 'querying the service state', cmd: 'sc query sshd', ctx: WINDOWS_SSH },
    { why: 'querying the rdp transport service over the ssh transport', cmd: 'sc query TermService', ctx: WINDOWS_SSH },
    { why: 'listing processes', cmd: 'tasklist', ctx: WINDOWS_SSH },
    { why: 'listing the sshd process without touching it', cmd: 'tasklist /svc /fi "imagename=sshd.exe"', ctx: WINDOWS_SSH },
    { why: 'a different service by name', cmd: 'net stop spooler', ctx: WINDOWS_SSH },
    { why: 'starting a different service', cmd: 'net start PrintSpooler', ctx: WINDOWS_SSH },
    { why: 'restarting a different service', cmd: 'Restart-Service Wsearch', ctx: WINDOWS_SSH },
    { why: 'killing an unrelated process', cmd: 'taskkill /PID 123 /F', ctx: WINDOWS_SSH },
    { why: 'killing an unrelated image', cmd: 'taskkill /IM notepad.exe /F', ctx: WINDOWS_SSH },
    { why: 'Automatic services still start themselves', cmd: 'Set-Service sshd -StartupType Automatic', ctx: WINDOWS_SSH },
    // The dashed/-StartupType forms are in SEVERING above: the guard must refuse them.
    { why: 'reading a process', cmd: 'Get-Process sshd', ctx: WINDOWS_SSH },
    { why: 'an unrelated command', cmd: 'ipconfig /all', ctx: WINDOWS_SSH },
    { why: 'powering the machine down is a different kind of risk', cmd: 'shutdown /s /t 0', ctx: WINDOWS_SSH },
    { why: 'a compound command that touches neither transport', cmd: 'net stop spooler && net start PrintSpooler', ctx: WINDOWS_SSH },
    { why: 'systemd starts the daemon instead of stopping it', cmd: 'systemctl start sshd', ctx: LINUX_SSH },
    { why: 'reading unit status', cmd: 'systemctl status sshd', ctx: LINUX_SSH },
    { why: 'killing a name that is not the daemon', cmd: 'killall -9 sshdx', ctx: LINUX_SSH },
    { why: 'a filtered pkill targets a pattern, not the daemon token', cmd: 'pkill -f "ssh session"', ctx: LINUX_SSH },
    { why: 'the per-connection instance unit is not the daemon itself', cmd: 'systemctl stop sshd.socket', ctx: LINUX_SSH },
    { why: 'a differently-named unit is not the daemon', cmd: 'systemctl stop sshd-junk', ctx: LINUX_SSH },
    { why: 'a service name that merely starts like the daemon is a different service', cmd: 'sc stop sshd.socket', ctx: WINDOWS_SSH },
    { why: 'a mention in a file path is not a service command', cmd: 'echo hi > stop-service-sshd.log', ctx: WINDOWS_SSH },
    { why: 'searching for the string does not run it', cmd: 'findstr sshd C:\\deploy\\run.cmd', ctx: WINDOWS_SSH },
    { why: 'Windows service names are not how a linux host stops sshd', cmd: 'Stop-Service sshd', ctx: LINUX_SSH },
    { why: 'the linux guard only applies to the transport we are using', cmd: 'systemctl stop sshd', ctx: LINUX_RDP },
    { why: 'the operator opted out of the guard', cmd: 'Stop-Service sshd', ctx: WINDOWS_PERMITTING },
    { why: 'the operator opted out of the guard', cmd: 'sc delete sshd', ctx: WINDOWS_PERMITTING },
  ];

  it.each(HARMLESS)('$why: allows $cmd', (row) => {
    const verdict = checkCommand(row.cmd, row.ctx);
    expect(verdict.allowed).toBe(true);
    expect(verdict.code).toBeUndefined();
  });

  describe('the refusal says what is at risk and how to override it', () => {
    it('names the transport the guard was asked about', () => {
      const verdict = checkCommand('Stop-Service sshd', WINDOWS_SSH);
      expect(verdict.reason).toContain('transport is ssh');
      expect(verdict.reason).toContain('sever-transport');
    });

    it('names the rdp transport when that is the transport at risk', () => {
      const verdict = checkCommand('Stop-Service TermService', WINDOWS_RDP);
      expect(verdict.reason).toContain('transport is rdp');
    });

    it('uses the shorter linux explanation', () => {
      const verdict = checkCommand('systemctl stop sshd', LINUX_SSH);
      expect(verdict.reason).toContain('carries the current transport');
      expect(verdict.reason).toContain('sever-transport');
    });
  });
});
