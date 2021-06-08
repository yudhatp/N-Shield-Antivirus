object Form1: TForm1
  Left = 403
  Top = 209
  BorderIcons = [biSystemMenu]
  BorderStyle = bsSingle
  Caption = 'N-Shield AntiVirus :: Database Manager'
  ClientHeight = 90
  ClientWidth = 470
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 128
    Top = 32
    Width = 40
    Height = 13
    Caption = 'ddmmyy'
  end
  object Button1: TButton
    Left = 360
    Top = 8
    Width = 105
    Height = 33
    Caption = 'Enkrip'
    TabOrder = 0
    OnClick = Button1Click
  end
  object Button2: TButton
    Left = 360
    Top = 48
    Width = 105
    Height = 33
    Caption = 'Dekrip'
    TabOrder = 1
    OnClick = Button2Click
  end
  object Edit1: TEdit
    Left = 16
    Top = 8
    Width = 337
    Height = 21
    TabOrder = 2
    Text = 'path'
    OnClick = Edit1Click
  end
  object Edit2: TEdit
    Left = 16
    Top = 32
    Width = 105
    Height = 21
    TabOrder = 3
    Text = 'tanggal'
  end
  object OpenDialog1: TOpenDialog
    Left = 232
    Top = 48
  end
end
