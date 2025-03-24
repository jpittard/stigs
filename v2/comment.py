import xml.etree.ElementTree as ET
import os
import datetime
import re


def get_formatted_date():
    today = datetime.date.today()
    return f'{today.month:02d}/{today.day:02d}/{today.year}'

FORMATTED_DATE = get_formatted_date()
FINDING_STMT = f'Erik Jensen validated on {FORMATTED_DATE} that the finding is'
CKL_EXTENSION = 'ckl'
OUT_DIR = 'out'
AC2SP_SEPERATOR = '******** AC2SP Notations ********'
QUESTIONS_FOR_OPEN = '''1. Why is it a finding?
  
2. What is the estimated fix date?
  
3. What resources are required to fix it?
  
4. How is this vulnerability mitigated?
  
5. What is the impact of this vulnerability?
  '''


def get_status_text(status):
    if status == 'NotAFinding':
        return 'NOT A FINDING'
    elif status == 'Not_Applicable':
        return 'NOT APPLICABLE'
    elif status == 'Open':
        return 'OPEN'
    elif status == 'Not_Reviewed':
        return 'NOT REVIEWED'
    else:
        raise ValueError(f'Unknown status: {status}')


def prepend_comment(tree):
    '''Add a duplicate of the latest comment with an updated finding statement.
    This is useful if not much has changed.'''
    for vuln in tree.getroot().findall('STIGS/iSTIG/VULN'):
        status = vuln.findall('STATUS')[0].text
        english_status = get_status_text(status)     

        comment_node = vuln.find('COMMENTS')
        latest_comment = get_latest_comment(comment_node.text)
        revised = f'{FINDING_STMT} {english_status}.\n{latest_comment}\n{comment_node.text}'
        comment_node.text = revised
    return tree


def prepend_finding_statement(tree):
    '''Add finding statement to file with no previous finding statements'''
    for vuln in tree.getroot().findall('STIGS/iSTIG/VULN'):
        comment_node = vuln.find('COMMENTS')
        vuln_id = get_stig_data(vuln, 'Vuln_Num')
        status = vuln.find('STATUS').text
        english_status = get_status_text(status)
        if comment_node is None or comment_node.text is None:
            print(f'No comment for {vuln_id}')
            revised = f'{FINDING_STMT} {english_status}.'
        else:
            lines = comment_node.text.split('\n')
            noblanks = [line for line in lines if line and line.strip()]
            if english_status == 'OPEN':
                revised = f'{FINDING_STMT} {english_status}.\n{'\n'.join(noblanks)}\n{QUESTIONS_FOR_OPEN}'
            else:
                revised = f'{FINDING_STMT} {english_status}.\n{'\n'.join(noblanks)}'
        comment_node.text = revised
    return tree


def get_latest_comment(text):
    if text is None:
        return None
    lines = text.split('\n')
    if len(lines) <= 1:
        return text
    pos = 1
    for line in lines[1:]:
        if ' validated on ' in line:
            break
        else:
            pos += 1
    return '\n'.join(lines[1:pos])


def get_stig_data(vuln, key):
    return vuln.find(f'STIG_DATA[VULN_ATTRIBUTE="{key}"]/ATTRIBUTE_DATA').text


def update_latest_comment(tree):
    '''Update the date in first line to current date'''
    date_pattern_1 = r'\d{2}/\d{2}/\d{4}'
    date_pattern_2 = r'\d{4}/\d{2}/\d{2}'
    for vuln in tree.getroot().findall('STIGS/iSTIG/VULN'):
        status = vuln.findall('STATUS')[0].text
        vuln_id = get_stig_data(vuln, 'Vuln_Num')   
        english_status = get_status_text(status)
        if english_status == 'NOT REVIEWED':
            print(f'  {vuln_id} not reviewed (skipping)')
            continue
     
        comment_node = vuln.findall('COMMENTS')[0]
        if comment_node is None or comment_node.text is None:
            raise ValueError(f'No comment found for {vuln_id}')

        lines = comment_node.text.split('\n')
        # Remove blank lines from top
        nonblank_lines = []
        first_line_found = False
        for line in lines:
            if line is None or line.strip() == '' or first_line_found:
                continue
            else:
                first_line_found = True
                nonblank_lines.append(line)

        if len(nonblank_lines) < 1 or len(nonblank_lines[0]) == 0:
            raise ValueError(f'No comment text found for {vuln_id}')
        top_line = nonblank_lines[0]
        # Check that status is reflected in top line
        if english_status not in top_line:
            raise ValueError(f'Status {english_status} not found in first line for {vuln_id}')
        # Update date to current date
        if re.search(date_pattern_1, top_line):
            nonblank_lines[0] = re.sub(date_pattern_1, FORMATTED_DATE, top_line)
        elif re.search(date_pattern_2, top_line):
            nonblank_lines[0] = re.sub(date_pattern_2, FORMATTED_DATE, top_line)
        else:
            raise ValueError(f'No date found in first line for {vuln_id}')

        comment_node.text = '\n'.join(nonblank_lines)
    return tree


def combine_rhel_ami_ckl(ac2sp_ckl, rhel_ckl):
    ac2sp_vulns = map()
    for vuln in ac2sp_ckl.getroot().findall('STIGS/iSTIG/VULN'):
        vuln_id = get_stig_data(vuln, 'Vuln_Num')
        ac2sp_vulns[vuln_id] = vuln.find('COMMENTS').text

    for vuln in rhel_ckl.getroot().findall('STIGS/iSTIG/VULN'):
        vuln_id = get_stig_data(vuln, 'Vuln_Num')
        comment_node = vuln.find('COMMENTS')
        comment_node.text = f'{comment_node.text}\n\n{AC2SP_SEPERATOR}\n{ac2sp_vulns[vuln_id]}'
    
    return rhel_ckl


def write_revised_file(filename, fcn):
    try:
        tree = ET.parse(filename)
        revised_tree = fcn(tree)
    except (ET.ParseError, ValueError) as e:
        print(f'  ERROR: {filename}:\n  {str(e)}')
        return
    
    new_filename = os.path.splitext(f'{OUT_DIR}/{os.path.basename(filename)[0]}.{CKL_EXTENSION}')
    print(f'Writing {new_filename}')
    ET.indent(tree, space='\t', level=0)
    revised_tree.write(new_filename, encoding='utf-8', xml_declaration=True)


def write_all(dirname, fcn):
    if os.path.isdir(dirname):
        print(f'Processing directory {dirname}')
        for filename in os.listdir(dirname):
            if not filename.endswith('.' + CKL_EXTENSION)):
                print(f'Skipping file {filename}')
                continue
            write_revised_file(f'{dirname}/{filename}', fcn)
    else:
        print(f'Processing file {dirname}')ß
        write_revised_file(dirname, fcn)
    print('Done')


# write_all('../ckl/CUI_NA2P_connected_RHEL_7_v3r14_20240327_ami.ckl', update_latest_comment)
write_all('../ckl/i2ar-test-jboss-web-0-ej_rhel8_V2R2_20250214.ckl', prepend_finding_statement)




