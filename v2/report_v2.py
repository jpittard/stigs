import xml.etree.ElementTree as ET
import csv
import os
from dataclasses import dataclass, asdict

CHECKLIST_EXTENSION = 'ckl'


@dataclass
class Vuln:
    vuln_id: str
    rule_id: str
    severity: str
    group_title: str
    rule_title: str
    discussion: str
    check_content: str
    fix_text: str
    cci: str
    status: str
    comments: str
    finding_details: str



def get_vulnerabilities(tree):
    vulns: list[Vuln] = []
    for vuln in tree.getroot().findall('STIGS/iSTIG/VULN'):
        v = Vuln(
            vuln_id=get_stig_data(vuln, 'Vuln_Num'),
            rule_id=get_stig_data(vuln, 'Rule_ID'),
            severity=get_stig_data(vuln, 'Severity'),
            group_title=get_stig_data(vuln, 'Group_Title'),
            rule_title=get_stig_data(vuln, 'Rule_Title'),
            discussion=get_stig_data(vuln, 'Discussion'),
            check_content=get_stig_data(vuln, 'Check_Content'),
            fix_text=get_stig_data(vuln, 'Fix_Text'),
            cci=get_stig_data(vuln, 'CCI_REF'),
            status=vuln.find('STATUS'),
            comments=vuln.find('FINDING_DETAILS'),
            finding_details=vuln.find('COMMENTS')
            )
        vulns.append(v)
    return vulns


def write_csv(vulns):
    with open('vulns.csv', 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=asdict(vulns[0]).keys())
        writer.writeheader()
        for vuln in vulns:
            writer.writerow(asdict(vuln))


def get_stig_data(vuln, key):
    return vuln.find(f'STIG_DATA[VULN_ATTRIBUTE="{key}"]/ATTRIBUTE_DATA').text


def report(directory, fcn):
    total = 0
    for filename in os.listdir(directory):
        if filename.endswith('.ckl'):
            tree = ET.parse(f'{directory}/{filename}')
            vulns = get_vulnerabilities(tree)
            found = fcn(vulns)
            total += len(found)
            print(f'{directory}/{filename}: {len(found)}')
            write_csv(f'{directory}/{filename}', found)
    print(f'Total: {total}')


def contains_fips(vulns):
    return [v for v in vulns if 'FIPS' in v.check_content]


report('.', "contains_fips")