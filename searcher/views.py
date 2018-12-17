from django.shortcuts import render
from searcher.search_engine import search_vulnerabilities_in_db, is_valid_input, search_vulnerabilities_advanced
from searcher.models import Exploit, Shellcode
import os
import re
from searcher.forms import AdvancedSearchForm
from searcher.forms import OPERATOR_CHOICES


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
    file_path = '/static/vulnerabilities/' + exploit.file
    try:
        with open(pwd + '/static/vulnerabilities/' + exploit.file, 'r') as f:
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
    except FileNotFoundError:
        error_msg = 'Sorry! This file does not exist :('
        return render(request, 'error_page.html', {'error': error_msg})


def view_shellcode_code(request, shellcode_id):
    shellcode = Shellcode.objects.get(id=shellcode_id)
    pwd = os.path.dirname(__file__)
    file_path = '/static/vulnerabilities/' + shellcode.file
    try:
        with open(pwd + '/static/vulnerabilities/' + shellcode.file, 'r') as f:
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
    except FileNotFoundError:
        error_msg = 'Sorry! This file does not exist :('
        return render(request, 'error_page.html', {'error': error_msg})


def show_help(request):
    return render(request, 'help.html')


def show_info(request):
    return render(request, 'about.html')


def get_vulnerability_extension(vulnerability_file):
    regex = re.search(r'\.(?P<extension>\w+)', vulnerability_file)
    extension = '.' + regex.group('extension')
    return extension


def get_results_table_advanced(request):
    if request.POST:
        form = AdvancedSearchForm(request.POST)
        print('POST')
        if form.is_valid():
            search_text = form.cleaned_data['search_text']
            operator_filter_index = int(form.cleaned_data['operator']) - 1
            print(operator_filter_index)
            operator_filter = OPERATOR_CHOICES.__getitem__(operator_filter_index)[1]
            print(operator_filter)
            return render(request, 'results_table.html', {'searched_item': str(search_text),
                                                      'exploits_results': search_vulnerabilities_advanced(search_text,'searcher_exploit', operator_filter),
                                                      'n_exploits_results': len(search_vulnerabilities_advanced(search_text,'searcher_exploit', operator_filter)),
                                                      'shellcodes_results': search_vulnerabilities_advanced(search_text,'searcher_shellcode', operator_filter),
                                                      'n_shellcodes_results': len(search_vulnerabilities_advanced(search_text,'searcher_shellcode', operator_filter))
                                                      })
        else:
            form = AdvancedSearchForm()
            return render(request, 'advanced_searcher.html', {'form': form})
    else:
        form = AdvancedSearchForm()
        return render(request, 'advanced_searcher.html', {'form': form})
