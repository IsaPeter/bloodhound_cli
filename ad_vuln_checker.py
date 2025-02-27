import json, os
from typing import List, Dict
from ad_objects import Computer, Domain, User, Container, GPO, Group, OrganizationalUnit as OU, ADObject, trust_direction, trust_type
import zipfile
from terminaltables import AsciiTable

class ADVulnerabilityChecker():
    def __init__(self):
        self.domains = []
        self.tmp_data = []

        self.translate_sid_value = False
        
    def open_zipfile(self, filepath):
        if os.path.isfile(filepath) and filepath.endswith(".zip"):
            input_zip = zipfile.ZipFile(filepath)
            zipfiles = {name: input_zip.read(name) for name in input_zip.namelist()}
        
            #for name,json_data in zipfiles.items():
            #    #print(f"Loading {name}")
            #    json_parsed = json.loads(json_data)
            #    self.parse_data_source(json_parsed)    
            self.parse_data_source(zipfiles)          
    def parse_data_source(self, zipfiles):

        computers = []
        domains = []
        users = []
        gpos = []
        groups = []
        ous = []
        containers = []

        for name,data in zipfiles.items():
            json_data = json.loads(data)

            source_meta = json_data.get("meta", [])

            if "type" in source_meta:
                source_type = source_meta["type"]

                # Parse computer objects
                if source_type == "computers":
                    computers = self.parse_computers(json_data)
                elif source_type == "domains":
                    domains = self.parse_domains(json_data)
                elif source_type == "users":
                    users = self.parse_users(json_data)
                elif source_type == "gpos":
                    gpos = self.parse_gpos(json_data)
                elif source_type == "groups":
                    groups = self.parse_groups(json_data)
                elif source_type == "ous":
                    ous = self.parse_ous(json_data)
                elif source_type == "containers":
                    containers = self.parse_containers(json_data)
                    

            else:
                pass # itt kellene valami errort raiseolni.
        

        if domains:
            self.domains.extend(domains)
        
        
        for domain in domains:
            for computer in computers:
                if computer.domain_sid == domain.domain_sid:
                    domain.computers.append(computer)
                if computer.primary_group_sid.endswith("516"):
                    domain.domain_controllers.append(computer)
                    
            for user in users:
                if user.domain_sid == domain.domain_sid:
                    domain.users.append(user)
            for group in groups:
                if group.domain_sid == domain.domain_sid:
                    domain.groups.append(group)
            for gpo in gpos:
                if gpo.domain_sid == domain.domain_sid:
                    domain.gpos.append(gpo)
            for ou in ous:
                if ou.domain_sid == domain.domain_sid:
                    domain.ous.append(ou)
            for container in containers:
                if container.domain_sid == domain.domain_sid:
                    domain.containers.append(container)
            
            domain.build_sid_table()

    def parse_groups(self, json_data):
        groups = []
        for entry in json_data.get("data", []):
            #print(json.dumps(entry))
            groups.append(Group(entry))
        return groups
    def parse_computers(self, json_data):
        computers = []
        for entry in json_data.get("data", []):
            #print(json.dumps(entry))
            computers.append(Computer(entry))
        return computers
    def parse_domains(self, json_data):
        domains = []
        for entry in json_data.get("data", []):
            #print(json.dumps(entry))
            props = entry.get("Properties", {})
            # Check if it is not an enpty domain
            if "name" in props and "domain" in props:
                domains.append(Domain(entry))
        return domains
    def parse_users(self, json_data):
        users = []
        for entry in json_data.get("data", []):
            users.append(User(entry))
        return users
    def parse_containers(self, json_data):
        containers = []
        for entry in json_data.get("data", []):
            containers.append(Container(entry))
        return containers
    def parse_gpos(self, json_data):
        gpos = []
        for entry in json_data.get("data", []):
            gpos.append(GPO(entry))
        return gpos
    def parse_ous(self, json_data):
        ous = []
        for entry in json_data.get("data", []):
            ous.append(OU(entry))
        return ous



    # Print methods        
    def print_objects(self,objects,headers=[],values=[]):
        table_data = []
        table_data.append(headers)
        for item in objects:
            data_dict = {key: value for key, value in vars(item).items() if key in values}
            data = [v for k,v in data_dict.items()]
            table_data.append(data)
        table = AsciiTable(table_data)
        print(table.table)

    def print_object_brief(self, o):
        table_data = [["Domain", "Name", "SID"]]
        table_data.append([o.domain, o.name, o.object_identifier])
        print(AsciiTable(table_data).table)

    def translate_sid(self, sid):
        if not self.translate_sid_value:
            return sid
        else:
            item = self.get_object_by_sid(sid)
            if item:
                return item.name
            else:
                return sid
        
    def get_object_by_sid(self, sid):
        objects = [d.sid_table[sid] for d in self.domains if sid in d.sid_table]
        if objects: return objects[0]["object"]

    def list_computers(self):
        computers = [c for d in self.domains for c in d.computers]
        if computers:
           headers = ["Domain","Name", "SID"]
           values = ["domain","name", "object_identifier"]
           self.print_objects(computers, headers, values )

    def list_users(self):
        users = [u for d in self.domains for u in d.users]
        if users: 
            headers = ["Domain","Name", "SID"]
            values = ["domain","name", "object_identifier"]
            self.print_objects(users, headers, values)

    def list_groups(self):
        items = [item for d in self.domains for item in d.groups]
        if items:
            table_data = [["Domain","Name", "SID","Members Count"]]
            for item in items:
                table_data.append([item.domain,item.name, item.object_identifier, len(item.members)])
            print(AsciiTable(table_data).table)

    def list_ous(self):
        items = [item for d in self.domains for item in d.ous]
        if items:
            headers = ["Domain","Name", "SID"]
            values = ["domain","name", "object_identifier"]
            self.print_objects(items, headers, values)

    def list_containers(self):
        items = [item for d in self.domains for item in d.containers]
        if items:
            headers = ["Domain","Name", "SID"]
            values = ["domain","name", "object_identifier"]
            self.print_objects(items, headers, values)
    def list_gpos(self):
        items = [item for d in self.domains for item in d.gpos]
        if items:
            headers = ["Domain","Name", "SID"]
            values = ["domain","name", "object_identifier"]
            self.print_objects(items, headers, values)

    def list_dcs(self):
        dcs = [dc for d in self.domains for dc in d.domain_controllers]
        if dcs:
            headers = ["Domain","Name", "SID"]
            values = ["domain","name", "object_identifier"]
            self.print_objects(dcs, headers, values)

    def list_object_descriptions(self):
        users = [u for d in self.domains for u in d.users if u.description]
        computers = [c for d in self.domains for c in d.computers if c.description]

        items = computers+users
        table_data = [["Domain", "Name", "Type", "Description"]]
        for item in items:
            table_data.append([item.domain, item.name, item.object_type, item.description])
        print(AsciiTable(table_data).table)

    def check_uncontrained(self):
        computers = [c for d in self.domains for c in d.computers if c.unconstrained_delegation]
        if computers:
            headers = ["Domain","Name", "SID"]
            values = ["domain","name", "object_identifier"]
            self.print_objects(computers, headers, values)
    
    def check_kerberoasting(self):
        computers = [c for d in self.domains for c in d.computers if c.check_kerberoasting()]
        users = [u for d in self.domains for u in d.users if u.check_kerberoasting()]
        kerberoast = computers+users

        if kerberoast:
            table_data = [["Domain","Name", "Type", "SID"]]
            for k in kerberoast:
                table_data.append([k.domain, k.name, k.object_type, k.object_identifier])
            print(AsciiTable(table_data).table)
            
    def check_asrep_roast(self):
        users = [u for d in self.domains for u in d.users if u.dont_req_preauth]
        if users:
            table_data = [["Domain","Name","SID"]]
            for u in users:
                table_data.append([u.domain, u.name, u.object_identifier])
            print(AsciiTable(table_data).table)
    
    def check_constrained_delegations(self):
        users = [u for d in self.domains for u in d.users if u.allowed_to_delegate]
        comp = [c for d in self.domains for c in d.computers if c.allowed_to_delegate]

        items = users + comp
        table_data = [["Domain","Name", "SID", "Delegate to"]]
        for item in items:
            delegate_sids = [i["ObjectIdentifier"] for i in item.allowed_to_delegate]
            table_data.append([item.domain, item.name, item.object_identifier, ', '.join(delegate_sids)])
        print(AsciiTable(table_data).table)

    def find_object_by_sid(self, sid):

        for d in self.domains:
            
            if sid in d.sid_table:
                table_data = [["Property","Value"]]
                item = d.sid_table[sid]
                ad_object = item["object"]
                for k,v in vars(ad_object).items():
                    if k not in ["aces"]:
                        table_data.append([k,str(v)[:100]])
                print(AsciiTable(table_data).table)

                    # Print the associated ACE-s
                print("\n[Inbound Access Control List]\n")
                table_data = [["Direction","SID","Group", "Right"]]
                for acl in ad_object.aces:
                    table_data.append(["INBOUND", acl["PrincipalSID"], acl["PrincipalType"], acl["RightName"]])
                print(AsciiTable(table_data).table)
                break

    def list_group_members(self, sid):
       
        for d in self.domains:
                for group in d.groups:
                    if sid == group.object_identifier:
                        table_data = [["Domain", "Name", "SID"]]
                        table_data.append([group.domain, group.name, group.object_identifier])
                        print(AsciiTable(table_data).table)
                        print("\n[Group Members]\n")
                        table_data = [["SID", "Object Type"]]
                        for member in group.members:
                            table_data.append([member["ObjectIdentifier"], member["ObjectType"]])
                        print(AsciiTable(table_data).table)

    def list_spns(self, sid):
        item = self.get_object_by_sid(sid)
        if item:
            if "service_principal_names" in vars(item):
                self.print_object_brief(item)
                print("\n[Service Principal Names]\n")
                table_data = [["SPN"]]
                for spn in item.service_principal_names:
                    table_data.append([spn])
                print(AsciiTable(table_data).table)

    def list_acl(self, sid):
        inbound_acls = self.get_inbound_acls(sid)
        outbound_acls = self.get_outbound_acls(sid)
        obj = self.get_object_by_sid(sid)


        inbound_table = [["Direction", "SID", "Type", "Right Name"]]
        for i in inbound_acls:
            inbound_table.append(["INBOUND", self.translate_sid(i["PrincipalSID"]), i["PrincipalType"], i["RightName"]])

        outbound_table = [["Direction", "SID", "Type", "Right Name"]]
        for o in outbound_acls:
            outbound_table.append(["OUTBOUND", self.translate_sid(o["ForeignSid"]), o["PrincipalType"], o["RightName"]])

        self.print_object_brief(obj)


        print("\n[Inbound Access Control List]\n")
        print(AsciiTable(inbound_table).table)
        
        print("\n[Outbound Access Control List]\n")
        print(AsciiTable(outbound_table).table)

    def list_domains(self):
        table_data = [["Name","SID","Computers", "Users", "Containers", "GPO's", "Groups", "OU's"]]
        for d in self.domains:
            table_data.append([d.name, d.domain_sid, len(d.computers), len(d.users), len(d.containers), len(d.gpos),len(d.groups),len(d.ous)])
        print(AsciiTable(table_data).table)
    
    def get_inbound_acls(self, sid):
        obj = self.get_object_by_sid(sid)
        return obj.aces

    def get_outbound_acls(self, sid):
        outbound_acls = []
        
        for domain in self.domains:
            for key,data in domain.sid_table.items():
                acls = data["object"].get_acl_by_sid(sid)
                if acls:
                    for a in acls: a["ForeignSid"] = key
                    outbound_acls.extend(acls)
        return outbound_acls

    def list_trusts(self):
        table_data = [["Source Domain", "Target Domain", "Transitive","SID Filtering", "Trust Direction", "Trust Type"]]
        for domain in self.domains:
            for trust in domain.trusts:
                table_data.append([domain.name, trust["TargetDomainName"], str(trust["IsTransitive"]).title(),str(trust["SidFilteringEnabled"]).title(),trust_direction[int(trust["TrustDirection"])],trust_type[int(trust["TrustType"])]])
        print(AsciiTable(table_data).table)





