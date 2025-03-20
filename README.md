
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

    sudo docker-compose pull && sudo [BLOODHOUND_PORT=8888] docker-compose up



    docker-compose down -v
---------
    pipx install bloodhound-ce

    bloodhound-ce-python -c all -ns 10.10.11.5 [-dc freelancer.htb] -d freelancer.htb --zip -u 'mikasaAckerman' -p 'IL0v3ErenY3ager'

admin

so6FYxCyhtO9K6p8VXNcoT4S6oxtk5Wr

Silvercore_21


# WriteOwner


 
