; NexLog Professional Inno Setup Script
; Compatible with Inno Setup 6.4+

#define MyAppName "NexLog"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "NexLog Contributors"
#define MyAppURL "https://github.com/nexlog/nexlog"
#define MyAppExeName "NexLog.exe"
#define MyCliExeName "nexlog.exe"
#define MyAppId "{{7C4B926F-80B7-48E8-8EB8-FB3AF2C18A10}}"
#define MyAppAssoc ".nexlog"
#define MyAppAssocName "NexLog Case File"
#define MyAppAssocDesc "NexLog Forensic Analysis Case"
#define SourcePath "."

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=no
OutputBaseFilename=NexLog-v{#MyAppVersion}-windows-x64-setup
Compression=lzma2/ultra64
SolidCompression=yes
InternalCompressLevel=ultra64
WizardStyle=modern
WizardImageFile=compiler:WizModernImage-IS.bmp
WizardSmallImageFile=compiler:WizModernSmallImage-IS.bmp
WizardImageAlphaFormat=defined
WizardSmallImageAlphaFormat=defined
AppCopyright=Copyright (C) 2025-2026 NexLog Contributors
SetupIconFile={#SourcePath}\..\..\nexlog\interface\gui\assets\nexlog-icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
ShowLanguageDialog=no
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} — Local-First DFIR Log Analyzer
VersionInfoTextVersion={#MyAppVersion}
VersionInfoCopyright=Copyright (C) 2025-2026 NexLog Contributors
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
MinVersion=6.1sp1
AllowNoIcons=no
AlwaysShowDirOnReadyPage=yes
AlwaysShowGroupOnReadyPage=yes
CloseApplications=yes
RestartApplications=yes
ChangesAssociations=yes
ChangesEnvironment=yes
SetupLogging=yes
; For code signing: uncomment and update with your certificate details
; SignTool=signtool sha1 $f
; SignTool=signtool sha256 /fd sha256 /tr http://timestamp.digicert.com /td sha256 $f
; SignToolMinimumVersion=10.0.22000

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=Welcome to the {#MyAppName} Setup Wizard
WelcomeLabel2=This will install {#MyAppName} {#MyAppVersion} on your computer.%n%nIt is recommended that you close all other applications before continuing.

[Files]
; Main application files
Source: "{#SourcePath}\..\..\release\NexLog\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; License and documentation
Source: "{#SourcePath}\..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}\..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}\..\..\docs"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu shortcuts
Name: "{group}\{#MyAppName} (GUI)"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\{#MyAppName} (System Tray)"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--tray"; WorkingDir: "{app}"
Name: "{group}\{#MyAppName} (CLI)"; Filename: "{app}\{#MyCliExeName}"; WorkingDir: "{app}"
Name: "{group}\Documentation"; Filename: "{app}\README.md"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
; Desktop shortcut
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon
; Startup shortcut
Name: "{commonstartup}\{#MyAppName} Tray"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--tray"; WorkingDir: "{app}"; Tasks: startuptray

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "startuptray"; Description: "Run in system &tray on login"; GroupDescription: "Additional options:"; Flags: unchecked
Name: "addtopath"; Description: "Add NexLog to &system PATH"; GroupDescription: "Additional options:"; Flags: unchecked

[Registry]
; File association
Root: "HKCR"; Subkey: "{#MyAppAssoc}"; ValueType: "string"; ValueData: "{#MyAppAssocName}"; Flags: uninsdeletekey
Root: "HKCR"; Subkey: "{#MyAppAssocName}"; ValueType: "string"; ValueData: "{#MyAppAssocDesc}"; Flags: uninsdeletekey
Root: "HKCR"; Subkey: "{#MyAppAssocName}\DefaultIcon"; ValueType: "string"; ValueData: "{app}\{#MyAppExeName},0"; Flags: uninsdeletekey
Root: "HKCR"; Subkey: "{#MyAppAssocName}\shell\open\command"; ValueType: "string"; ValueData: """{app}\{#MyAppExeName}"" --case ""%1"""; Flags: uninsdeletekey

; PATH environment variable
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: DoesPathExist()

[Run]
Filename: "{app}\{#MyCliExeName}"; Parameters: "--help"; Description: "Verify CLI installation"; Flags: nowait postinstall skipifsilent
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent unchecked

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: files; Name: "{commonappdata}\NexLog"
Type: files; Name: "{userappdata}\NexLog"

[Code]
// Check if application path already exists in PATH variable
function DoesPathExist(): Boolean;
var
  Path: String;
begin
  Result := False;
  Path := GetEnv('PATH');
  if Pos(ExpandConstant('{app}'), UpperCase(Path)) > 0 then Result := True;
end;

// Remove application path from PATH on uninstall
procedure RemovePath();
var
  Path: String;
  NewPath: String;
  QueryPos: Integer;
begin
  Path := GetEnv('PATH');
  QueryPos := Pos(ExpandConstant('{app}'), UpperCase(Path));
  if QueryPos > 0 then
  begin
    NewPath := Copy(Path, 1, QueryPos - 1);
    Delete(Path, 1, Length(ExpandConstant('{app}')));
    if Length(Path) > 0 then
    begin
      if Path[1] = ';' then Delete(Path, 1, 1);
      NewPath := NewPath + Path;
    end;
    SetEnv('PATH', NewPath);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemovePath();
end;
