New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 > clsids2.txt

$Filename = "win10-ProgID-members.txt"
$inputFilename = "clsids2.txt"
$Position  = 1
$count = 0
$MethodList = @()

ForEach($CLSID in Get-Content $inputFilename)
{
    #Write-Output "$($Position) - $($CLSID)"
    #$CLSID = "{00024502-0000-0000-C000-000000000046}"
	$CHILD_REG = Get-ChildItem -Path ("HKCR:\CLSID" + "\" + $CLSID) -Name
	if($CHILD_REG -match "ProgID")
	{
	   $ProgID = (Get-ItemProperty ("HKCR:\CLSID" + "\" + $CLSID + '\' + "ProgID"))."(default)"
       Write-Output "$($ProgID) - $($CLSID)"
       if($ProgID.contains("MMC20.Application"))
       {
       		Write-Output "$($ProgID) - $($CLSID)"
       }

	}
	$Position += 1
}

Write-Output "OK"