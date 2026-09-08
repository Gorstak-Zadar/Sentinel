[Setup]
AppName=Sentinel
AppVersion=2.5.6
AppPublisher=Gorstak
AppPublisherURL=https://gorstak.eu
AppCopyright=Copyright (C) 2026 Gorstak
VersionInfoVersion=2.5.6.0
VersionInfoCompany=Gorstak
VersionInfoDescription=Sentinel Endpoint Detection and Response Setup
VersionInfoCopyright=Copyright (C) 2026 Gorstak
VersionInfoProductName=Sentinel EDR
VersionInfoProductVersion=2.5.6.0
VersionInfoOriginalFileName=SentinelSetup-2.5.6.exe
SourceDir=.
DefaultDirName={autopf}\Sentinel
DefaultGroupName=Sentinel
SetupIconFile=assets\Sentinel.ico
LicenseFile=assets\disclaimer.txt
UninstallDisplayIcon={app}\Sentinel.ico
Compression=lzma/max
SolidCompression=no
OutputDir=.
OutputBaseFilename=SentinelSetup-2.5.6
PrivilegesRequired=admin
SetupMutex=Global\SentinelSetupMutex
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no

[Files]
Source: "assets\Sentinel.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\disclaimer.txt"; DestDir: "{app}"; DestName: "DISCLAIMER.txt"; Flags: ignoreversion
Source: "..\publish\service\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Sentinel Agent"; Filename: "{app}\Sentinel.Agent.exe"; IconFilename: "{app}\Sentinel.ico"

[Run]
Filename: "{app}\Sentinel.Service.exe"; Parameters: "--install"; Flags: runhidden waituntilterminated; StatusMsg: "Starting Sentinel..."
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"" 2>nul & exit /b 0"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{commonpf32}\Sentinel"

[Code]
function IsDotNet48OrHigher(): Boolean;
var
  Release: Cardinal;
begin
  Result := False;
  if IsWin64 then
  begin
    if RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    begin
      Result := Release >= 528040;
      Exit;
    end;
  end;
  if RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    Result := Release >= 528040;
end;

function OfferDotNet48Download(): Boolean;
var
  ErrCode: Integer;
begin
  Result := False;
  if MsgBox(
    'Sentinel requires .NET Framework 4.8.' + #13#10#13#10 +
    'Yes = open the Microsoft download page' + #13#10 +
    'No  = cancel Setup',
    mbConfirmation, MB_YESNO) = IDYES then
  begin
    ShellExec('open',
      'https://dotnet.microsoft.com/download/dotnet-framework/net48',
      '', '', SW_SHOWNORMAL, ewNoWait, ErrCode);
    MsgBox('After installing .NET Framework 4.8, run SentinelSetup again.', mbInformation, MB_OK);
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsDotNet48OrHigher() then
    Result := OfferDotNet48Download();
end;

function SysNative(const FileName: String): String;
begin
  Result := ExpandConstant('{sysnative}\') + FileName;
  if not FileExists(Result) then
    Result := ExpandConstant('{sys}\') + FileName;
end;

// Restore v2.3.7 upgrade unlock. Hardened installs add a Users Deny-Write on
// {app}; admin accounts are in Users, so Inno cannot overwrite unins000.exe
// (Access is denied). Window is admin Setup only; the service re-locks on start.
procedure ResetInstallDirAcls(const DirPath: String);
var
  ResultCode: Integer;
  Icacls, Takeown: String;
begin
  if not DirExists(DirPath) then
    Exit;

  Icacls := SysNative('icacls.exe');
  Takeown := SysNative('takeown.exe');

  if FileExists(DirPath + '\unins000.exe') then
  begin
    Exec(Takeown, '/A /F "' + DirPath + '\unins000.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.exe" /remove:d *S-1-5-32-545 /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.exe" /grant Administrators:F /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if FileExists(DirPath + '\unins000.dat') then
  begin
    Exec(Takeown, '/A /F "' + DirPath + '\unins000.dat"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.dat" /remove:d *S-1-5-32-545 /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.dat" /grant Administrators:F /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  Exec(Icacls, '"' + DirPath + '" /grant Administrators:(OI)(CI)F /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Icacls, '"' + DirPath + '" /remove:d *S-1-5-32-545 /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure StopExistingService();
var
  ResultCode: Integer;
  Svc, Taskkill: String;
begin
  Svc := ExpandConstant('{app}\Sentinel.Service.exe');
  if FileExists(Svc) then
  begin
    Exec(Svc, '--prepare-upgrade', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(800);
  end;

  Taskkill := SysNative('taskkill.exe');
  Exec(Taskkill, '/F /IM "Sentinel.Service.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Taskkill, '/F /IM "Sentinel.Agent.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);

  ResetInstallDirAcls(ExpandConstant('{app}'));
  ResetInstallDirAcls(ExpandConstant('{commonpf}\Sentinel'));
  ResetInstallDirAcls(ExpandConstant('{commonpf32}\Sentinel'));
  ResetInstallDirAcls(ExpandConstant('{autopf}\Sentinel'));

  if FileExists(ExpandConstant('{app}\Sentinel.Service.exe')) then
    RenameFile(ExpandConstant('{app}\Sentinel.Service.exe'), ExpandConstant('{app}\Sentinel.Service.exe.old'));
  if FileExists(ExpandConstant('{app}\Sentinel.Agent.exe')) then
    RenameFile(ExpandConstant('{app}\Sentinel.Agent.exe'), ExpandConstant('{app}\Sentinel.Agent.exe.old'));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  NeedsRestart := False;

  if RegValueExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent') or
     RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\Sentinel') or
     DirExists(ExpandConstant('{app}')) or
     DirExists(ExpandConstant('{commonpf32}\Sentinel')) then
  begin
    StopExistingService();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  Taskkill, Svc: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Stop and kill service + agent before files are removed.
    // Without this the processes stay running and file deletion fails silently,
    // leaving both binaries on disk and the service registered.
    Svc := ExpandConstant('{app}\Sentinel.Service.exe');
    if FileExists(Svc) then
    begin
      Exec(Svc, '--uninstall-cleanup', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Sleep(800);
    end;

    Taskkill := SysNative('taskkill.exe');
    Exec(Taskkill, '/F /IM "Sentinel.Service.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Taskkill, '/F /IM "Sentinel.Agent.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000);

    // Remove IPSec policy and firewall rule created by Sentinel
    Exec(ExpandConstant('{sys}\netsh.exe'), 'ipsec static delete policy name=GSecurity', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="Sentinel-Block-Remote-RPC-Ephemeral"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Remove agent autorun key
    RegDeleteValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent');
  end;
end;
