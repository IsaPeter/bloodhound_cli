# Bloodhound CLI
Enumerate Bloodhound generated ZIP files from CLI.

## Note

If you're looking for SpecterOps' version of bloodhound-cli, which helps users install BloodHound Community Edition, you're in the wrong place. Please head over to: https://github.com/specterOps/bloodHound-cli.


## Usage

**Set target Zip File**

```bash
python3 bloodhound_cli.py --zipfile test_data/north.zip
```
Or set multiple Zip files at once.

```bash
python3 bloodhound_cli.py --zipfile test_data/north.zip --zipfile test_data/sevenkingdoms.zip
```

**List Users**

```bash
python3 bloodhound_cli.py --zipfile test_data/north.zip --users
```
```
+-----------------------------------------+---------------------------+-----------------------------------------------+
| Domain                                  | Name                      | SID                                           |
+-----------------------------------------+---------------------------+-----------------------------------------------+
| ADMINISTRATOR@NORTH.SEVENKINGDOMS.LOCAL | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-500  |
| GUEST@NORTH.SEVENKINGDOMS.LOCAL         | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-501  |
| VAGRANT@NORTH.SEVENKINGDOMS.LOCAL       | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1000 |
| KRBTGT@NORTH.SEVENKINGDOMS.LOCAL        | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-502  |
| ARYA.STARK@NORTH.SEVENKINGDOMS.LOCAL    | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1110 |
| EDDARD.STARK@NORTH.SEVENKINGDOMS.LOCAL  | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1111 |
| CATELYN.STARK@NORTH.SEVENKINGDOMS.LOCAL | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1112 |
| ROBB.STARK@NORTH.SEVENKINGDOMS.LOCAL    | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1113 |
| SANSA.STARK@NORTH.SEVENKINGDOMS.LOCAL   | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1114 |
| BRANDON.STARK@NORTH.SEVENKINGDOMS.LOCAL | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1115 |
| RICKON.STARK@NORTH.SEVENKINGDOMS.LOCAL  | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1116 |
| HODOR@NORTH.SEVENKINGDOMS.LOCAL         | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1117 |
| JON.SNOW@NORTH.SEVENKINGDOMS.LOCAL      | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1118 |
| SAMWELL.TARLY@NORTH.SEVENKINGDOMS.LOCAL | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1119 |
| JEOR.MORMONT@NORTH.SEVENKINGDOMS.LOCAL  | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1120 |
| SQL_SVC@NORTH.SEVENKINGDOMS.LOCAL       | NORTH.SEVENKINGDOMS.LOCAL | S-1-5-21-496997871-2047422392-1122532547-1121 |
+-----------------------------------------+---------------------------+-----------------------------------------------+
```

**List Trusts**

```bash
python3 bloodhound_cli.py --zipfile test_data/north.zip --zipfile test_data/sevenkingdoms.zip  --trusts
```
```
+---------------------------+---------------------------+------------+---------------+-----------------+-------------+
| Source Domain             | Target Domain             | Transitive | SID Filtering | Trust Direction | Trust Type  |
+---------------------------+---------------------------+------------+---------------+-----------------+-------------+
| NORTH.SEVENKINGDOMS.LOCAL | SEVENKINGDOMS.LOCAL       | True       | False         | Bidirectional   | ParentChild |
| SEVENKINGDOMS.LOCAL       | ESSOS.LOCAL               | True       | False         | Bidirectional   | Forest      |
| SEVENKINGDOMS.LOCAL       | NORTH.SEVENKINGDOMS.LOCAL | True       | False         | Bidirectional   | ParentChild |
+---------------------------+---------------------------+------------+---------------+-----------------+-------------+
```

**Listing ACL**

Listing Inbound and Outbound ACL's.

```bash
python3 bloodhound_cli.py --zipfile test_data/north.zip --zipfile test_data/sevenkingdoms.zip  --list-acl "S-1-5-21-3215788258-3618580572-1391043384-1114" --translate-sid
```
```
+---------------------+-------------------------------------+------------------------------------------------+
| Domain              | Name                                | SID                                            |
+---------------------+-------------------------------------+------------------------------------------------+
| SEVENKINGDOMS.LOCAL | JAIME.LANNISTER@SEVENKINGDOMS.LOCAL | S-1-5-21-3215788258-3618580572-1391043384-1114 |
+---------------------+-------------------------------------+------------------------------------------------+

[Inbound Access Control List]

+-----------+-------------------------------------------+-------+----------------------+
| Direction | SID                                       | Type  | Right Name           |
+-----------+-------------------------------------------+-------+----------------------+
| INBOUND   | DOMAIN ADMINS@SEVENKINGDOMS.LOCAL         | Group | Owns                 |
| INBOUND   | ACCOUNT OPERATORS@SEVENKINGDOMS.LOCAL     | Group | GenericAll           |
| INBOUND   | DOMAIN ADMINS@SEVENKINGDOMS.LOCAL         | Group | GenericAll           |
| INBOUND   | TYWIN.LANNISTER@SEVENKINGDOMS.LOCAL       | User  | ForceChangePassword  |
| INBOUND   | KEY ADMINS@SEVENKINGDOMS.LOCAL            | Group | AddKeyCredentialLink |
| INBOUND   | ENTERPRISE KEY ADMINS@SEVENKINGDOMS.LOCAL | Base  | AddKeyCredentialLink |
| INBOUND   | ENTERPRISE ADMINS@SEVENKINGDOMS.LOCAL     | Base  | GenericAll           |
| INBOUND   | ADMINISTRATORS@SEVENKINGDOMS.LOCAL        | Group | WriteDacl            |
| INBOUND   | ADMINISTRATORS@SEVENKINGDOMS.LOCAL        | Group | WriteOwner           |
| INBOUND   | ADMINISTRATORS@SEVENKINGDOMS.LOCAL        | Group | AllExtendedRights    |
| INBOUND   | ADMINISTRATORS@SEVENKINGDOMS.LOCAL        | Group | GenericWrite         |
+-----------+-------------------------------------------+-------+----------------------+

[Outbound Access Control List]

+-----------+---------------------------------------+------+--------------+
| Direction | SID                                   | Type | Right Name   |
+-----------+---------------------------------------+------+--------------+
| OUTBOUND  | JOFFREY.BARATHEON@SEVENKINGDOMS.LOCAL | User | GenericWrite |
+-----------+---------------------------------------+------+--------------+
```

