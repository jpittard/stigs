import json
import os


COMMENT = 'Darrell Baldridge validated on 09/20/2024 that the finding is'
FILENAME_PARTICLE = '_db'
FILE_EXTENSION = 'cklb'


def get_status_text(status):
    if status == 'not_a_finding':
        return 'NOT A FINDING'
    elif status == 'not_applicable':
        return 'NOT APPLICABLE'
    else:
        return 'OPEN'


def prepend_comment(tree):
    for stig in tree['stigs']:
        for rule in stig['rules']:
            finding = rule['finding_details']
            status = rule['status']
            revised = f'{COMMENT} {get_status_text(status)}.\n{get_latest_comment(finding)}\n{finding}'
            rule['finding_details'] = revised
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


def move_comment_to_finding_details(tree):
    for stig in tree['stigs']:
        for rule in stig['rules']:
            comment = rule['comments']
            rule['finding_details'] = comment
            rule['comments'] = ''
    return tree


def write_revised_file(filename, fcn):
    with open(filename) as infile:
        tree = json.load(infile)
    revised_tree = fcn(tree)
    new_filename = os.path.splitext(os.path.basename(filename))[0] + f'{FILENAME_PARTICLE}.{FILE_EXTENSION}'
    print(f'Writing {new_filename}')
    with open(new_filename, 'w') as f:
        json.dump(revised_tree, f, indent=2)


def write_all(directory, fcn):
    for filename in os.listdir(directory):
        if filename.endswith('.' + FILE_EXTENSION) and not filename.endswith(f'{FILENAME_PARTICLE}.{FILE_EXTENSION}'):
            write_revised_file(f'{directory}/{filename}', fcn)

write_all('.', move_comment_to_finding_details)
