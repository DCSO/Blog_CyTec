program darkgate_decrypt_keylog;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils, CustApp,
  DCPCrypt2, DCPrijndael, DCPsha1;

type

  { TMyApplication }

  TMyApplication = class(TCustomApplication)
  protected
    procedure DoRun; override;
  public
  end;

{ TMyApplication }

procedure TMyApplication.DoRun;
var
  Contents: TStringList;
  OutFile: TextFile;
  Cipher: TDCP_rijndael;
  Encrypted: String;
  Plain: String;
begin
  Contents := TStringList.Create();
  Contents.LoadFromFile(ParamStr(2));
  Encrypted := Contents.Text;

  Cipher :=  TDCP_rijndael.Create(nil);
  Cipher.InitStr(ParamStr(1),TDCP_sha1);
  Plain := Cipher.DecryptString(Encrypted);

  AssignFile(OutFile,ParamStr(3));
  ReWrite(OutFile);

  WriteLn(OutFile,Plain);
  CloseFile(OutFile);
  Terminate;
end;

var
  Application: TMyApplication;
begin
  Application:=TMyApplication.Create(nil);
  Application.Title:='My Application';
  Application.Run;
  Application.Free;
end.

