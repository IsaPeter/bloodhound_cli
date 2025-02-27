from ad_vuln_checker import ADVulnerabilityChecker
from argparse import ArgumentParser
from terminaltables import AsciiTable



def print_objects(objects):
    table_data = []
    table_header = ["Domain", "Name", "SID"]
    table_data.append(table_header)

    for o in objects:
        table_data.append([o.domain, o.name, o.object_identifier])

    table = AsciiTable(table_data)
    print(table.table)

def parse_arguments():
    parser = ArgumentParser()
    
    import_group = parser.add_argument_group("Import Options")
    import_group.add_argument("--zipfile", action="extend", metavar="", nargs='+', help="Set a ZIP file to be parse")


    vuln_group = parser.add_argument_group("AD Vulnerabilities")
    vuln_group.add_argument("--kerberoast", dest="kerberoast", action="store_true", help="List kerberoastable accounts")
    vuln_group.add_argument("--asrep", dest="asrep", action="store_true", help="List ASREP Roastable accounts")
    vuln_group.add_argument("--unconstrained", dest="unconstrained", action="store_true", help="List Uncontrained Delegation Computers")
    vuln_group.add_argument("--constrained", dest="constrained", action="store_true", help="List Constrained Delegations")
    
    enumeration_group = parser.add_argument_group("Enumeration Options")
    enumeration_group.add_argument("--computers", dest="list_computers", action="store_true", help="List computers in the domain(s)")
    enumeration_group.add_argument("--dcs", dest="list_dcs", action="store_true", help="List Domain Controllers in the domain(s)")
    enumeration_group.add_argument("--users", dest="list_users", action="store_true", help="List available users")
    enumeration_group.add_argument("--groups", dest="list_groups", action="store_true", help="List available groups")
    enumeration_group.add_argument("--containers", dest="list_containers", action="store_true", help="List available containers")
    enumeration_group.add_argument("--domains", dest="list_domains", action="store_true", help="List available domains")
    enumeration_group.add_argument("--ous", dest="list_ous", action="store_true", help="List available ous")
    enumeration_group.add_argument("--descriptions", dest="list_descriptions", action="store_true", help="List object descriptions")
    enumeration_group.add_argument("--object-sid", dest="object_sid", metavar="", help="Obtain Object Data")
    enumeration_group.add_argument("--group-members", dest="group_sid", metavar="", help="List group members")
    enumeration_group.add_argument("--list-spns", dest="list_spns", metavar="", help="List Computer SPN's")
    enumeration_group.add_argument("--list-acl", dest="list_acl", metavar="", help="List ACL of an object")
    enumeration_group.add_argument("--trusts", dest="list_trusts", action="store_true", help="List Domain Trusts")
    
    
    other_group = parser.add_argument_group("Other Options")
    other_group.add_argument("--translate-sid", dest="translate_sid", action="store_true", help="Translate SID value to Name")
    other_group.add_argument("--sid-table", dest="sid_table", action="store_true", help="List SID Table")
    other_group.add_argument("--test", dest="testing", action="store_true")

    return parser.parse_args()

def main():
    args = parse_arguments()

    ad = ADVulnerabilityChecker()
    zipfiles = []


    if args.zipfile:
        #print(args.zipfile)
        zipfiles = args.zipfile

    if zipfiles:
        for z in zipfiles:
            ad.open_zipfile(z)

    
    if args.translate_sid:
        ad.translate_sid_value = True

    # Listing elements
   
    if args.list_computers:
        ad.list_computers()
    if args.list_dcs:
        ad.list_dcs()
    if args.list_users:
        ad.list_users()
    if args.list_groups:
        ad.list_groups()
    if args.list_ous:
        ad.list_ous()
    if args.list_containers:
        ad.list_containers()
    if args.list_descriptions:
        ad.list_object_descriptions()
    if args.object_sid:
        ad.find_object_by_sid(args.object_sid)
    if args.group_sid:
        ad.list_group_members(args.group_sid)
    if args.list_spns:
        ad.list_spns(args.list_spns)
    if args.list_acl:
        ad.list_acl(args.list_acl)
    if args.list_domains:
        ad.list_domains()
    if args.list_trusts:
        ad.list_trusts()

    # Vulnerabilities

    if args.unconstrained:
        ad.check_uncontrained()
        
    if args.kerberoast:
        ad.check_kerberoasting()

    if args.asrep:
        ad.check_asrep_roast()

    if args.constrained:
        ad.check_constrained_delegations()


    if args.sid_table:

        #[k for l in items for k in l.lista.keys()]
        sids = [f"{k} {d.sid_table[k]["name"]}" for d in ad.domains for k in d.sid_table.keys()]
        for sid in sids: print(sid)


    
    if args.testing:    

        sid = "S-1-5-21-3215788258-3618580572-1391043384-1118"
        o_acls = ad.get_outbound_acls(sid)
        i_acls = ad.get_inbound_acls(sid)
        for a in o_acls: print("OUTBOUND ",a)
        for i in i_acls: print("INBOUND ", i)



if __name__ == '__main__':
    main()




  
