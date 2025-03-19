import xml.etree.ElementTree as ET
import csv
import os
from dataclasses import dataclass, asdict, field
from typing import Callable

CHECKLIST_EXTENSION = 'ckl'
SEVERITIES = {'low': 'CAT I', 'medium': 'CAT II', 'high': 'CAT III'}
CAT_LEVELS = {'CAT III': '3', 'CAT II': '2', 'CAT I': '1'}
FIELDLIST = ['severity', 'vuln_id', 'rule_ver', 'file', 'rule_title', 'comments', 'finding_details']
REPORT_NAME = 'report.csv'


@dataclass(order=True, frozen=True)
class Vuln:
    sort_index: int = field(init=False, repr=False)
    file: str
    vuln_id: str
    rule_id: str
    severity: str
    group_title: str
    rule_ver: str
    rule_title: str
    discussion: str
    check_content: str
    fix_text: str
    cci: str
    status: str
    comments: str
    finding_details: str
    def __post_init__(self):
        object.__setattr__(self, 'sort_index', CAT_LEVELS[self.severity] + self.rule_ver)



def get_vulnerabilities(tree: ET, filename: str) -> list[Vuln]:
    vulns: list[Vuln] = []
    for vuln in tree.getroot().findall('STIGS/iSTIG/VULN'):
        v = Vuln(
            file=os.path.basename(filename),
            vuln_id=get_stig_data(vuln, 'Vuln_Num'),
            rule_id=get_stig_data(vuln, 'Rule_ID'),
            severity=SEVERITIES[get_stig_data(vuln, 'Severity')],
            group_title=get_stig_data(vuln, 'Group_Title'),
            rule_ver=get_stig_data(vuln, 'Rule_Ver'),
            rule_title=get_stig_data(vuln, 'Rule_Title'),
            discussion=get_stig_data(vuln, 'Vuln_Discuss'),
            check_content=get_stig_data(vuln, 'Check_Content'),
            fix_text=get_stig_data(vuln, 'Fix_Text'),
            cci=get_stig_data(vuln, 'CCI_REF'),
            status=get_element(vuln, 'STATUS'),
            comments=get_element(vuln, 'FINDING_DETAILS'),
            finding_details=get_element(vuln, 'COMMENTS')
            )
        vulns.append(v)
    return vulns


def write_csv(vulns: list[Vuln]) -> None:
    print(f'Writing {len(vulns)} vulnerabilities to {REPORT_NAME}')
    
    with open(REPORT_NAME, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDLIST)
        writer.writeheader()
        for vuln in vulns:
            fields_to_print = {key: asdict(vuln).get(key) for key in FIELDLIST}
            writer.writerow(fields_to_print)


def get_stig_data(vuln: Vuln, key: str) -> str:
    attr = vuln.find(f'STIG_DATA[VULN_ATTRIBUTE="{key}"]/ATTRIBUTE_DATA')
    if attr is None:
        print(f'No key found for \'{key}\'')
        return ''
    return attr.text

def get_element(vuln: Vuln, key: str) -> str:
    attr = vuln.find(key)
    if attr is None:
        print(f'No key found for \'{key}\'')
        return ''
    return attr.text

def get_filtered_vulns(filename: str, filter_fcn: Callable) -> list[Vuln]:
    tree = ET.parse(f'{filename}')
    vulns = get_vulnerabilities(tree, filename)
    found = filter_fcn(vulns)
    print(f'{filename}: {len(found)}')
    return found


def create_vuln_filter(conditions: list[Callable]) -> Callable:
    def filter_vulns(vulns):
        return [v for v in vulns 
               if all(condition(v) for condition in conditions)]
    return filter_vulns


def is_open(v: Vuln) -> bool:
    return v.status == 'Open'


def report(dirname: str, conditions: list[Callable]) -> None:
    '''Run report against file or directory of checklists using list of vulnerability criteria stated as functions'''
    filter = create_vuln_filter(conditions)
    vulns = []
    if os.path.isdir(dirname):
        print(f'Reporting on directory {dirname}')
        for filename in os.listdir(dirname):
            if not filename.endswith('.ckl'):
                print(f'Skipping file {filename}')
                continue
            filtered = get_filtered_vulns(f'{dirname}/{filename}', filter)
            if filtered:
                vulns.extend(filtered)
    else:
        vulns = get_filtered_vulns(f'{dirname}/{filename}', filter)
    
    if len(vulns) == 0:
        print('No vulnerabilities found')
        return
    write_csv(sorted(vulns))
    print('Done')


report('../ckl', [is_open])