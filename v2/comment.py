import xml.etree.ElementTree as ET
import os


COMMENT = 'Darrell Baldridge validated on 09/20/2024 that the finding is'
FILENAME_EXTENSION = 'ckl'
FILENAME_PARTICLE = '_jp'

def prepend_comment(tree):
    for vuln in tree.getroot().findall('STIGS/iSTIG/VULN'):
        status = vuln.findall('STATUS')[0].text
        english_status = 'OPEN'
        if status == 'NotAFinding':
            english_status = 'NOT A FINDING'
        elif status == 'Not_Applicable':
            english_status = 'NOT APPLICABLE'
        

        comment_node = vuln.findall('COMMENTS')[0]
        latest_comment = get_latest_comment(comment_node.text)
        revised = f'{COMMENT} {english_status}.\n{latest_comment}\n{comment_node.text}'
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


def write_revised_file(filename, fcn):
    tree = ET.parse(filename) 
    revised_tree = fcn(tree)
    new_filename = os.path.splitext(os.path.basename(filename))[0] + f'{FILENAME_PARTICLE}.{FILENAME_EXTENSION}'
    print(f'Writing {new_filename}')
    ET.indent(tree, space='\t', level=0)
    revised_tree.write(new_filename, encoding='utf-8', xml_declaration=True)


def write_all(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.ckl') and not filename.endswith(f'{FILENAME_PARTICLE}.{FILENAME_EXTENSION}'):
            write_revised_file(f'{directory}/{filename}')


write_all('.')

