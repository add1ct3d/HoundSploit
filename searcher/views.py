from django.shortcuts import render
from searcher.search_engine import search_vulnerabilities_in_db
from searcher.search_engine import is_valid_input
from searcher.models import Exploit, Shellcode
import os
import re


def get_results_table(request):
    if request.POST and is_valid_input(request.POST['search_item']):
        search_text = request.POST['search_item']
        return render(request, "results_table.html", {'searched_item': str(search_text),
                                                      'exploits_results': search_vulnerabilities_in_db(search_text, 'searcher_exploit'),
                                                      'n_exploits_results': len(search_vulnerabilities_in_db(search_text, 'searcher_exploit')),
                                                      'shellcodes_results': search_vulnerabilities_in_db(search_text, 'searcher_shellcode'),
                                                      'n_shellcodes_results': len(search_vulnerabilities_in_db(search_text, 'searcher_shellcode'))
                                                      })
    else:
        return render(request, 'home.html')


def view_exploit_code(request, exploit_id):
    exploit = Exploit.objects.get(id=exploit_id)
    exploit_description = exploit.description
    exploit_file = exploit.file
    exploit_author = exploit.author
    exploit_date = exploit.date
    exploit_type = exploit.vulnerability_type
    exploit_platform = exploit.platform
    exploit_port = exploit.port

    pwd = os.path.dirname(__file__)
    file_path = '/static/vulnerability/' + exploit.file
    with open(pwd + '/static/vulnerability/' + exploit.file, 'r') as f:
        content = f.readlines()
        vulnerability_code = ''.join(content)
    return render(request, 'code_viewer.html', {'vulnerability_code': vulnerability_code,
                                                'vulnerability_description': exploit_description,
                                                'vulnerability_file': exploit_file,
                                                'vulnerability_author': exploit_author,
                                                'vulnerability_date': exploit_date,
                                                'vulnerability_type': exploit_type,
                                                'vulnerability_platform': exploit_platform,
                                                'vulnerability_port': exploit_port,
                                                'file_path': file_path,
                                                'file_name': exploit_description + get_vulnerability_extension(exploit_file),
                                                })


def view_shellcode_code(request, shellcode_id):
    shellcode = Shellcode.objects.get(id=shellcode_id)
    shellcode_description = shellcode.description
    shellcode_file = shellcode.file
    shellcode_author = shellcode.author
    shellcode_date = shellcode.date
    shellcode_type = shellcode.vulnerability_type
    shellcode_platform = shellcode.platform
    pwd = os.path.dirname(__file__)
    file_path = '/static/vulnerability/' + shellcode.file
    with open(pwd + '/static/vulnerability/' + shellcode.file, 'r') as f:
        content = f.readlines()
        vulnerability_code = ''.join(content)

    return render(request, 'code_viewer.html', {'vulnerability_code': vulnerability_code,
                                                'vulnerability_description': shellcode_description,
                                                'vulnerability_file': shellcode_file,
                                                'vulnerability_author': shellcode_author,
                                                'vulnerability_date': shellcode_date,
                                                'vulnerability_type': shellcode_type,
                                                'vulnerability_platform': shellcode_platform,
                                                'file_path': file_path,
                                                'file_name': shellcode_description + get_vulnerability_extension(shellcode_file),
                                                })


def show_help(request):
    return render(request, 'help.html')


def show_info(request):
    return render(request, 'about.html')


def get_vulnerability_extension(vulnerability_file):
    regex = re.search(r'\.(?P<extension>\w+)', vulnerability_file)
    extension = '.' + regex.group('extension')
    return extension




