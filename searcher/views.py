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
    pwd = os.path.dirname(__file__)
    file_path = '/static/vulnerability/' + exploit.file
    with open(pwd + '/static/vulnerability/' + exploit.file, 'r') as f:
        content = f.readlines()
        vulnerability_code = ''.join(content)
    return render(request, 'code_viewer.html', {'vulnerability_code': vulnerability_code,
                                                'vulnerability_description': exploit.description,
                                                'vulnerability_file': exploit.file,
                                                'vulnerability_author': exploit.author,
                                                'vulnerability_date': exploit.date,
                                                'vulnerability_type': exploit.vulnerability_type,
                                                'vulnerability_platform': exploit.platform,
                                                'vulnerability_port': exploit.port,
                                                'file_path': file_path,
                                                'file_name': exploit.description + get_vulnerability_extension(exploit.file),
                                                })


def view_shellcode_code(request, shellcode_id):
    shellcode = Shellcode.objects.get(id=shellcode_id)
    pwd = os.path.dirname(__file__)
    file_path = '/static/vulnerability/' + shellcode.file
    with open(pwd + '/static/vulnerability/' + shellcode.file, 'r') as f:
        content = f.readlines()
        vulnerability_code = ''.join(content)
    return render(request, 'code_viewer.html', {'vulnerability_code': vulnerability_code,
                                                'vulnerability_description': shellcode.description,
                                                'vulnerability_file': shellcode.file,
                                                'vulnerability_author': shellcode.author,
                                                'vulnerability_date': shellcode.date,
                                                'vulnerability_type': shellcode.vulnerability_type,
                                                'vulnerability_platform': shellcode.platform,
                                                'file_path': file_path,
                                                'file_name': shellcode.description + get_vulnerability_extension(shellcode.file),
                                                })


def show_help(request):
    return render(request, 'help.html')


def show_info(request):
    return render(request, 'about.html')


def get_vulnerability_extension(vulnerability_file):
    regex = re.search(r'\.(?P<extension>\w+)', vulnerability_file)
    extension = '.' + regex.group('extension')
    return extension


def show_advanced_search(request):
    # todo alphabetic order and remove repetitions
    exploit_type_items = Exploit.objects.order_by().values('vulnerability_type').distinct().exclude(vulnerability_type__exact='')
    shellcode_type_items = Shellcode.objects.order_by().values('vulnerability_type').distinct().exclude(vulnerability_type__exact='')
    exploit_platform_items = Exploit.objects.order_by().values('platform').distinct().exclude(platform__exact='')
    shellcode_platform_items = Shellcode.objects.order_by().values('platform').distinct().exclude(platform__exact='')
    exploit_port_items = Exploit.objects.order_by().values('port').distinct().exclude(port__exact='')
    return render(request, 'advanced_searcher.html', {'exploit_type_items': exploit_type_items,
                                                      'shellcode_type_items': shellcode_type_items,
                                                      'exploit_platform_items': exploit_platform_items,
                                                      'shellcode_platform_items': shellcode_platform_items,
                                                      'exploit_port_items': exploit_port_items})




