
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




 
