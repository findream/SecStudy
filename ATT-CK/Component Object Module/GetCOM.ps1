function GetSpecialMethod($MethodList)
{   
    #execute£¬exec£¬spawn£¬launchºÍrun,shell
    ForEach($EachMethod in $MethodList)
    {   
        $MethodName = $EachMethod."Name"
        if(($MethodName -Like "*shell*") -or ($MethodName -Like "*execute*") -or ($MethodName -Like "*exec*") -or ($MethodName -Like "*spawn*") -or ($MethodName -Like "*launch*") -or ($MethodName -Like "*run*") -or($MethodName -Like "*Command*") -or ($MethodName -Like "*send*") -or ($MethodName -Like "*DDE*") -or ($MethodName -Like "*Task*") ) 
        {
           if($MethodName -contains $MethodList)
           {
              return 0
           }
           Write-Output $EachMethod |  Out-File $Filename -Append
           $MethodList += $MethodName 
        }
    }
    return 1
}

function GetInstanceMethod($Instance)
{
    $count = $count + 1
    if(($Instance -eq $null) -or (($count -gt 3)))
    {
        $count = $count - 1
        return 0
    }
    # Print  All Methods Of Current Instance
    if(($Instance | gm -MemberType "Method") -ne $null)
    {
        $Method = $Instance | gm -MemberType "Method"
        GetSpecialMethod($Method)
    }
    

    $PropertyList = $Instance | gm -MemberType "Property"
    if($PropertyList -eq $null)
    {
        $count = $count - 1
        return 0
    }

    ForEach($EachProperty in $PropertyList)
    {
        $Name = $EachProperty."Name"
        if($Name -eq "Application")
        {
            $Name = $EachProperty."Name"
        }
        $NextInstance = $Instance.$Name
        if(($NextInstance -eq $null) -or ($NextInstance.GetType()."Name" -ne "__ComObject"))
        {
           if($NextInstance.GetType()."Name" -eq "ApplicationClass")
           {
              if(GetInstanceMethod($NextInstance) -eq 0)
              {
                 break
              }
           }
           else
           { 
               continue
           }
            
        }
        if(GetInstanceMethod($NextInstance) -eq 0)
        {
            break
        }
    }
    $count = $count - 1
    return 1
}

$Filename = "win10-clsid-members.txt"
$count = 0
$MethodList = @()
$CLSID = $args[0].ToString()
#$CLSID = "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}"
Write-Output "------------------------" | Out-File $Filename -Append
Write-Output $CLSID | Out-File $Filename -Append
$Instance = [activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID))
#$Instance = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.ChartApplication"))
GetInstanceMethod($Instance)

