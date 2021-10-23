New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 > clsids.txt

$Position  = 1
$inputFilename = "clsids.txt"
$Position = 0

ForEach($CLSID in Get-Content $inputFilename) 
{
      Write-Output "$($Position) - $($CLSID)"
      #Write-Output "------------------------" | Out-File $Filename -Append
      #Write-Output "$($CLSID)" | Out-File $Filename -Append
      powershell.exe   -File C:\Users\hacky\Desktop\GetCOM.ps1 "$CLSID"
      $Position += 1
}