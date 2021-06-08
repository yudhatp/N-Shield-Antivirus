object Form1: TForm1
  Left = 350
  Top = 297
  Width = 548
  Height = 106
  Caption = 'Cek apakah URL Valid :: nightmare'
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
    Left = 8
    Top = 40
    Width = 37
    Height = 13
    Caption = 'Status'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object lblstatus: TLabel
    Left = 56
    Top = 40
    Width = 16
    Height = 13
    Caption = 'n/a'
  end
  object Button1: TButton
    Left = 384
    Top = 8
    Width = 137
    Height = 41
    Caption = 'Check URL'
    TabOrder = 0
    OnClick = Button1Click
  end
  object Edit1: TEdit
    Left = 8
    Top = 8
    Width = 369
    Height = 21
    TabOrder = 1
    Text = '-- ketik URL disini -- contoh -> google.com'
  end
end
