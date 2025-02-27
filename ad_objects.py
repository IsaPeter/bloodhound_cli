import json
from datetime import datetime, timezone
from typing import List, Dict
from datetime import datetime


class ADObject():
    def __init__(self):
        self.aces = []

    def get_aces(self):
        return self.aces
    def get_acl_by_sid(self, sid):
        return [acl for acl in self.aces if acl["PrincipalSID"] == sid ]

class Computer(ADObject):
    def __init__(self, input_dict):
        super().__init__()
        properties = input_dict.get("Properties", {})
        aces = input_dict.get("Aces", [])

        self.object_type = "COMPUTER"
        self.name = properties.get("name")
        self.domain = properties.get("domain")
        self.domain_sid = properties.get("domainsid")
        self.distinguished_name = properties.get("distinguishedname")
        self.sam_account_name = properties.get("samaccountname")
        self.description = properties.get("description")
        self.enabled = properties.get("enabled")
        self.created = properties.get("whencreated")
        self.operatingsystem = properties.get("operatingsystem")
        self.object_identifier = input_dict.get("ObjectIdentifier")
        self.primary_group_sid = input_dict.get("PrimaryGroupSID")
        self.allowed_to_delegate = input_dict.get("AllowedToDelegate",[])
        self.allowed_to_act = input_dict.get("AllowedToAct", [])
        self.has_sid_history = input_dict.get("HasSIDHistory", [])
        self.dump_smsa_password = input_dict.get("DumpSMSAPassword", [])        
        self.sessions = input_dict.get("Sessions")
        self.privileged_sessions = input_dict.get("PrivilegedSessions")
        self.registry_sessions = input_dict.get("RegistrySessions")
        self.user_rights = input_dict.get("UserRights")

        self.unconstrained_delegation = properties.get("unconstraineddelegation", False)
        self.service_principal_names = properties.get("serviceprincipalnames", [])
        self.last_logon = properties.get("lastlogon", 0)
        self.pwd_last_set = properties.get("pwdlastset", 0)
        self.has_laps = properties.get("haslaps", False)
        self.trusted_to_auth = properties.get("trustedtoauth", False)
        self.sidhistory = properties.get("sidhistory", [])
        self.aces = aces
        self.local_groups = properties.get("LocalGroups", [])
        self.is_dc = self.primary_group_sid.endswith("516") # chack if it is a DC
    



    def _convert_epoch(self, epoch_time):
        return datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H:%M:%S')

    # Check if the computer has Uncostrained Delegation rights
    def check_unconstrained_delegation(self):
        return self.unconstrained_delegation
    
    # Check if the computer is vulnerable to kerberoasting
    def check_kerberoasting(self):
        return self.service_principal_names
    

    def check_high_privilege_aces(self):
        return [ace for ace in self.aces if ace["RightName"] == "GenericAll"]
    
    def get_all_aces(self):
        return [ace["RightName"] for ace in self.aces]

    
    def check_old_unused_account(self, threshold_days=180):
        now = int(datetime.now(timezone.utc).timestamp())
        return (now - self.last_logon) > (threshold_days * 86400)
    
    def check_weak_password_policy(self, threshold_days=365):
        now = int(datetime.now(timezone.utc).timestamp())
        return (now - self.pwd_last_set) > (threshold_days * 86400)
    
    def check_laps(self):
        return not self.has_laps
    
    def check_trust_settings(self):
        return self.trusted_to_auth
    
    def check_sid_history(self):
        return len(self.sidhistory) > 0
    
    def analyze(self):
        results = []
        if self.check_unconstrained_delegation():
            results.append(f"[!] {self.name} has Unconstrained Delegation enabled!")
        if self.check_high_privilege_aces():
            results.append(f"[!] {self.name} has high-privilege ACE entries!")
        if self.check_spn_for_kerberoasting():
            results.append(f"[*] {self.name} has SPNs, potential Kerberoasting target.")
        if self.check_old_unused_account():
            results.append(f"[!] {self.name} has not logged in for a long time (inactive account).")
        if self.check_weak_password_policy():
            results.append(f"[!] {self.name} has an old password, potential weak password policy.")
        if self.check_laps():
            results.append(f"[!] {self.name} does not have LAPS enabled, risk of local admin reuse.")
        if self.check_trust_settings():
            results.append(f"[!] {self.name} is Trusted to Authenticate, potential abuse.")
        if self.check_sid_history():
            results.append(f"[*] {self.name} has SID history, potential privilege escalation.")
        return results

class Domain(ADObject):
    def __init__(self, input_data):
        super().__init__()
        properties = input_data.get("Properties", {})
        trusts = input_data.get("Trusts", [])
        aces = input_data.get("Aces", [])
        child_objects = input_data.get("ChildObjects", [])

        self.object_type = "DOMAIN"
        self.name = properties.get("name")
        self.distinguished_name = properties.get("distinguishedname")
        self.domain_sid = properties.get("domainsid")
        self.object_identifier = input_data.get("ObjectIdentifier")
        self.functional_level = properties.get("functionallevel")
        self.when_created = properties.get("whencreated", 0)
        self.high_value = properties.get("highvalue", False)
        self.trusts = trusts
        self.aces = aces
        self.child_objects = child_objects


        self.computers = []
        self.users = []
        self.containers = []
        self.gpos = []
        self.groups = []
        self.ous = []
        self.domain_controllers = []

        self.sid_table = {}
    
    def add_to_sid_table(self, item):
        row = {item.object_identifier:{"name":item.name, "object":item}}
        self.sid_table.update(row)

    def build_sid_table(self):
        #Clear the sid table
        self.sid_table.clear()
        
        self.add_to_sid_table(self)

        # Add Computers 
        for c in self.computers:
            self.add_to_sid_table(c)

        for c in self.users:
            self.add_to_sid_table(c)

        for c in self.gpos:
            self.add_to_sid_table(c)

        for c in self.groups:
            self.add_to_sid_table(c)

        for c in self.ous:
            self.add_to_sid_table(c)

        for c in self.containers:
            self.add_to_sid_table(c)





    def check_high_privilege_aces(self):
        """🔴 Magas jogosultságú ACE ellenőrzése"""
        return [ace for ace in self.aces if ace["RightName"] in ["GenericAll", "WriteDacl", "WriteOwner"]]

    def check_trusts(self):
        """🔴 Bizalmi kapcsolatok elemzése (SID szűrés kikapcsolva)"""
        return [trust for trust in self.trusts if not trust["SidFilteringEnabled"]]

    def check_old_functional_level(self):
        """🟡 Régi domain functional level ellenőrzése"""
        old_levels = ["2003", "2008", "2012"]
        if self.functional_level:
            return any(level in self.functional_level for level in old_levels)

    def check_external_trust(self):
        """🟡 Külső domain trust kapcsolat keresése"""
        return [trust for trust in self.trusts if trust["TrustType"] == 2]

    def check_large_number_of_child_objects(self, threshold=10):
        """🟡 Túl sok OU vagy Container objektum"""
        return len(self.child_objects) > threshold

    def analyze(self):
        """🔍 Összes ellenőrzés futtatása"""
        results = []
        
        if self.check_high_privilege_aces():
            results.append(f"[!] {self.name} has high-privilege ACE entries!")
        if self.check_trusts():
            results.append(f"[!] {self.name} has trusts with disabled SID filtering, potential abuse.")
        if self.check_old_functional_level():
            results.append(f"[!] {self.name} is running an old functional level ({self.functional_level}), consider upgrading.")
        if self.check_external_trust():
            results.append(f"[!] {self.name} has an external trust connection, potential security risk.")
        if self.check_large_number_of_child_objects():
            results.append(f"[!] {self.name} has a high number of OUs/Containers, which may complicate security management.")

        return results

class User(ADObject):
    def __init__(self, input_data):
        super().__init__()
        properties = input_data.get("Properties", {})
        aces = input_data.get("Aces", [])

        self.object_type = "USER"
        self.name = properties.get("name")
        self.sam_account_name = properties.get("samaccountname")
        self.domain = properties.get("domain")
        self.distinguished_name = properties.get("distinguishedname")
        self.domain_sid = properties.get("domainsid")
        self.high_value = properties.get("highvalue", False)
        self.password_not_required = properties.get("passwordnotreqd", False)
        self.password_never_expires = properties.get("pwdneverexpires", False)
        self.unconstrained_delegation = properties.get("unconstraineddelegation", False)
        self.enabled = properties.get("enabled", True)
        self.trusted_to_auth = properties.get("trustedtoauth", False)
        self.last_logon = properties.get("lastlogon", 0)
        self.pwd_last_set = properties.get("pwdlastset", 0)
        self.service_principal_names = properties.get("serviceprincipalnames", [])
        self.description = properties.get("description", "")
        self.dont_req_preauth = properties.get("dontreqpreauth", False)
        self.hasspn = properties.get("hasspn", False)
        self.logonscript = properties.get("logonscript")
        self.sidhistory = properties.get("sidhistory")
        self.has_sidhistory = input_data.get("HasSIDHistory")
        self.allowed_to_delegate = input_data.get("AllowedToDelegate")
        self.primary_group_sid = input_data.get("PrimaryGroupSID")
        self.spn_targets = input_data.get("SPNTargets")
        self.object_identifier = input_data.get("ObjectIdentifier")
        self.user_sid = input_data.get("ObjectIdentifier")
        self.aces = aces

    def check_kerberoasting(self):
        return self.service_principal_names
    
    def check_unconstrained_delegation(self):
        return self.unconstrained_delegation
    
    def check_high_privilege_aces(self):
        return [ace for ace in self.aces if ace["RightName"] in ["GenericAll", "WriteDacl", "WriteOwner"]]
    
    def check_old_password(self, threshold_days=365):
        now = int(datetime.now(timezone.utc).timestamp())
        return (now - self.pwd_last_set) > (threshold_days * 86400)
    
    def check_disabled_account(self):
        return not self.enabled
    
    def check_password_not_required(self):
        return self.password_not_required
    
    def analyze(self):
        results = []
        if self.check_unconstrained_delegation():
            results.append(f"[!] {self.name} has Unconstrained Delegation enabled!")
        if self.check_high_privilege_aces():
            results.append(f"[!] {self.name} has high-privilege ACE entries!")
        if self.check_old_password():
            results.append(f"[!] {self.name} has an old password, potential weak password policy.")
        if self.check_disabled_account():
            results.append(f"[*] {self.name} is disabled, check if it should still exist.")
        if self.check_password_not_required():
            results.append(f"[!] {self.name} does not require a password, security risk!")
        return results

class Container(ADObject):
    def __init__(self, input_data):
        super().__init__()

        properties = input_data.get("Properties", {})
        child_objects = input_data.get("ChildObjects", [])
        aces = input_data.get("Aces", [])


        self.object_type = "CONTAINER"
        self.name = properties.get("name")
        self.domain = properties.get("domain")
        self.distinguished_name = properties.get("distinguishedname")
        self.domain_sid = properties.get("domainsid")
        self.object_identifier = input_data.get("ObjectIdentifier")
        self.is_deleted = properties.get("IsDeleted", False)
        self.is_acl_protected = properties.get("IsACLProtected", False)
        self.child_objects = child_objects
        self.aces = aces
    
    def check_high_privilege_aces(self):
        """🔴 Ellenőrzi, hogy a konténerhez tartozik-e magas jogosultságú ACE."""
        return [ace for ace in self.aces if ace["RightName"] in ["GenericAll", "WriteDacl", "WriteOwner"]]
    
    def check_acl_protection(self):
        """🟡 Megnézi, hogy az ACL védelem engedélyezve van-e."""
        return self.is_acl_protected
    
    def analyze(self):
        """🔍 Elemzést végez a konténer sérülékenységeire."""
        results = []
        if self.check_high_privilege_aces():
            results.append(f"[!] {self.name} has high-privilege ACE entries!")
        if self.check_acl_protection():
            results.append(f"[*] {self.name} has ACL protection enabled.")
        return results

class GPO(ADObject):
    def __init__(self, input_data):
        super().__init__()
        properties = input_data.get("Properties", {})
        aces = input_data.get("Aces", [])

        self.object_type = "GPO"
        self.name = properties.get("name")
        self.domain = properties.get("domain")
        self.distinguished_name = properties.get("distinguishedname")
        self.gpc_path = properties.get("gpcpath")
        self.domain_sid = properties.get("domainsid")
        self.description = properties.get("description", "")
        self.object_identifier = input_data.get("ObjectIdentifier")
        self.is_deleted = properties.get("IsDeleted", False)
        self.is_acl_protected = properties.get("IsACLProtected", False)
        self.when_created = properties.get("whencreated", 0)
        self.aces = aces
    
    def check_high_privilege_aces(self):
        """🔴 Ellenőrzi, hogy a GPO-hoz tartozik-e magas jogosultságú ACE."""
        return [ace for ace in self.aces if ace["RightName"] in ["GenericAll", "WriteDacl", "WriteOwner", "GenericWrite"]]
    
    def check_acl_protection(self):
        """🟡 Megnézi, hogy az ACL védelem engedélyezve van-e."""
        return self.is_acl_protected
    
    def check_old_gpo(self, threshold_days=365):
        """🟡 Ellenőrzi, hogy a GPO nagyon régi-e."""
        now = int(datetime.now(timezone.utc).timestamp())
        return (now - self.when_created) > (threshold_days * 86400)
    
    def analyze(self):
        """🔍 Elemzést végez a GPO sérülékenységeire."""
        results = []
        if self.check_high_privilege_aces():
            results.append(f"[!] {self.name} has high-privilege ACE entries!")
        if self.check_acl_protection():
            results.append(f"[*] {self.name} has ACL protection enabled.")
        if self.check_old_gpo():
            results.append(f"[*] {self.name} is an old GPO, consider reviewing it.")
        return results

class Group(ADObject):
    def __init__(self, input_data):
        super().__init__()
        properties = input_data.get("Properties", {})
        members = input_data.get("Members", [])
        aces = input_data.get("Aces", [])

        self.object_type = "GROUP"
        self.name = properties.get("name")
        self.sam_account_name = properties.get("samaccountname","")
        self.domain = properties.get("domain")
        self.distinguished_name = properties.get("distinguishedname")
        self.domain_sid = properties.get("domainsid")
        self.object_identifier = input_data.get("ObjectIdentifier")
        self.is_deleted = properties.get("IsDeleted", False)
        self.is_acl_protected = properties.get("IsACLProtected", False)
        self.high_value = properties.get("highvalue", False)
        self.admin_count = properties.get("admincount", False)
        self.description = properties.get("description", "No description")
        self.members = members
        self.aces = aces
    
    def get_object_rid(self):
        domain_sid,rid = self.object_identifier.rsplit('-',1)
        return int(rid)

    def check_high_privilege_aces(self):
        """🔴 Magas jogosultságú ACE bejegyzések keresése."""
        return [ace for ace in self.aces if ace["RightName"] in ["GenericAll", "WriteDacl", "WriteOwner", "GenericWrite"]]
    
    def check_acl_protection(self):
        """🟡 ACL védelem ellenőrzése."""
        return self.is_acl_protected
    
    def check_high_value(self):
        """🔴 Magas értékű csoportok (pl. Domain Admins)."""
        return self.high_value
    
    def check_nested_privileged_group(self):
        """🔴 Beágyazott magas jogosultságú csoportok keresése."""
        privileged_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins"]
        return any(member["Name"] in privileged_groups for member in self.members)
    
    def check_empty_high_privilege_group(self):
        """🔴 Üres, de magas jogosultságú csoportok keresése."""
        return self.high_value and len(self.members) == 0
    
    def check_large_group(self, threshold=50):
        """🟡 Nagyon nagy csoportok keresése."""
        return len(self.members) > threshold
    
    def check_admin_count(self):
        """🟡 AdminCount érték ellenőrzése."""
        return self.admin_count
    
    def check_deleted_group(self):
        """🟡 Töröltként megjelölt csoportok ellenőrzése."""
        return self.is_deleted
    
    def analyze(self):
        """🔍 Elemzés végrehajtása."""
        results = []
        if self.check_high_privilege_aces():
            results.append(f"[!] {self.name} has high-privilege ACE entries!")
        if self.check_acl_protection():
            results.append(f"[*] {self.name} has ACL protection enabled.")
        if self.check_high_value():
            results.append(f"[!] {self.name} is a high-value group (e.g., Domain Admins), monitor carefully!")
        if self.check_nested_privileged_group():
            results.append(f"[!] {self.name} contains a nested privileged group!")
        if self.check_empty_high_privilege_group():
            results.append(f"[!] {self.name} is a high-privilege group but has no members!")
        if self.check_large_group():
            results.append(f"[*] {self.name} has a very large number of members, consider reviewing its usage.")
        if self.check_admin_count():
            results.append(f"[!] {self.name} has AdminCount set to 1, potential security risk.")
        if self.check_deleted_group():
            results.append(f"[!] {self.name} is marked as deleted but still exists!")
        return results

class OrganizationalUnit(ADObject):
    def __init__(self, input_data):
        super().__init__()
        properties = input_data.get("Properties", {})
        child_objects = input_data.get("ChildObjects", [])
        aces = input_data.get("Aces", [])
        gpo_changes = input_data.get("GPOChanges", {})

        self.object_type = "OU"
        self.name = properties.get("name")
        self.domain = properties.get("domain")
        self.distinguished_name = properties.get("distinguishedname")
        self.domain_sid = properties.get("domainsid")
        self.description = properties.get("description")
        self.object_identifier = input_data.get("ObjectIdentifier")
        self.is_deleted = properties.get("IsDeleted", False)
        self.is_acl_protected = properties.get("IsACLProtected", False)
        self.blocks_inheritance = properties.get("blocksinheritance", False)
        self.child_objects = child_objects
        self.aces = aces
        self.gpo_changes = gpo_changes
    
    def check_high_privilege_aces(self):
        """🔴 Magas jogosultságú ACE bejegyzések keresése."""
        return [ace for ace in self.aces if ace["RightName"] in ["GenericAll", "WriteDacl", "WriteOwner", "GenericWrite"]]
    
    def check_acl_protection(self):
        """🟡 ACL védelem ellenőrzése."""
        return self.is_acl_protected
    
    def check_blocks_inheritance(self):
        """🟡 Ellenőrzi, hogy az öröklődés le van-e tiltva az OU-nál."""
        return self.blocks_inheritance
    
    def check_high_privilege_objects(self):
        """🔴 Magas jogosultságú objektumokat tartalmazó OU keresése."""
        privileged_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins"]
        return any(obj["ObjectType"] == "Group" and obj["ObjectIdentifier"] in privileged_groups for obj in self.child_objects)
    
    def check_large_ou(self, threshold=100):
        """🟡 Túl sok objektumot tartalmazó OU."""
        return len(self.child_objects) > threshold
    
    def check_deleted_ou(self):
        """🟡 Töröltként megjelölt, de még létező OU-k ellenőrzése."""
        return self.is_deleted
    
    def check_gpo_changes(self):
        """🔴 Veszélyes GPO módosításokat tartalmazó OU."""
        return any(self.gpo_changes[key] for key in ["LocalAdmins", "RemoteDesktopUsers", "DcomUsers", "PSRemoteUsers"])

    def analyze(self):
        """🔍 Elemzés végrehajtása."""
        results = []
        if self.check_high_privilege_aces():
            results.append(f"[!] {self.name} has high-privilege ACE entries!")
        if self.check_acl_protection():
            results.append(f"[*] {self.name} has ACL protection enabled.")
        if self.check_blocks_inheritance():
            results.append(f"[*] {self.name} has inheritance blocked, review permissions carefully.")
        if self.check_high_privilege_objects():
            results.append(f"[!] {self.name} contains privileged accounts/groups!")
        if self.check_large_ou():
            results.append(f"[*] {self.name} contains a large number of objects, consider reviewing its structure.")
        if self.check_deleted_ou():
            results.append(f"[!] {self.name} is marked as deleted but still exists!")
        if self.check_gpo_changes():
            results.append(f"[!] {self.name} has GPO modifications that affect security (e.g., Local Admins changes).")
        return results

# This Dictionary contains the Mapped SID values

SID_MAP = {
    # Beépített helyi fiókok
    "500": "Administrator",
    "501": "Guest",
    "502": "KRBTGT",  # Kerberos Ticket Granting Ticket Account

    # Csoportok
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-only Domain Controllers (RODC)",
    "522": "Cloneable Domain Controllers",
    "525": "Protected Users",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
    "528": "RAS and IAS Servers",

    # Helyi csoportok és jogosultságok
    "544": "Administrators",
    "545": "Users",
    "546": "Guests",
    "547": "Power Users",
    "548": "Account Operators",
    "549": "Server Operators",
    "550": "Print Operators",
    "551": "Backup Operators",
    "552": "Replicator",
    "553": "RAS Servers",

    # RODC (Read-Only Domain Controller) specifikus csoportok
    "1101": "Allowed RODC Password Replication Group",
    "1102": "Denied RODC Password Replication Group",

    # Speciális beépített SID-ek
    "498": "Enterprise Read-Only Domain Controllers",
}

trust_direction = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional"
}

trust_type = {
    0:"ParentChild",
    1:"CrossLink",
    2:"Forest",
    3:"External",
    4:"Unknown"
}