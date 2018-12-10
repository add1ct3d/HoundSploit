from searcher.models import Exploit, Shellcode
import re
from django.db.models import Q
from distutils.version import LooseVersion
from pkg_resources import parse_version


def search_vulnerabilities_in_db(search_text, db_table):
    words = (str(search_text).upper()).split()
    if (words[0] == '--EXACT' and '--IN' in words) and db_table == 'searcher_exploit':
        return search_exploits_exact(words[1:])

    if (words[0] == '--EXACT' and '--IN' in words) and db_table == 'searcher_shellcode':
        return search_shellcodes_exact(words[1:])

    if str(search_text).isnumeric():
        return search_vulnerabilities_numerical(search_text, db_table)
    elif str_is_num_version(str(search_text)) and not str(search_text).__contains__('<'):
        return search_vulnerabilities_version(search_text, db_table)
    else:
        queryset = search_vulnerabilities_for_description(search_text, db_table)
        if len(queryset) > 0:
            return queryset
        else:
            queryset = search_vulnerabilities_for_file(search_text, db_table)
            if len(queryset) > 0:
                return queryset
            else:
                return search_vulnerabilities_for_author_platform_type(search_text, db_table)


def search_vulnerabilities_numerical(search_text, db_table):
    if db_table == 'searcher_exploit':
        return Exploit.objects.filter(Q(id__exact=int(search_text)) | Q(file__contains=search_text) | Q(description__contains=search_text) | Q(port__exact=int(search_text)))
    else:
        return Shellcode.objects.filter(Q(id__exact=int(search_text)) | Q(file__contains=search_text) | Q(description__contains=search_text))


def search_vulnerabilities_for_description(search_text, db_table):
    words_list = str(search_text).split()
    search_string = 'select * from ' + db_table + ' where (description like \'%' + words_list[0].upper() + '%\''
    for word in words_list[1:]:
        search_string = search_string + ' and description like \'%' + word.upper() + '%\''
    search_string = search_string + ') or ((id like \'%' + words_list[0].upper() + '%\''
    for word in words_list[1:]:
        search_string = search_string + ' or id like \'%' + word.upper() + '%\''
    search_string = search_string + ') and (description like \'%' + words_list[0].upper() + '%\''
    for word in words_list[1:]:
        search_string = search_string + ' or description like \'%' + word.upper() + '%\''
    search_string = search_string + '))'
    print(search_string)
    if db_table == 'searcher_exploit':
        return Exploit.objects.raw(search_string)
    else:
        return Shellcode.objects.raw(search_string)


def search_vulnerabilities_for_file(search_text, db_table):
    words_list = str(search_text).split()
    search_string = 'select * from ' + db_table + ' where (file like \'%' + words_list[0].upper() + '%\''
    for word in words_list[1:]:
        search_string = search_string + ' or file like \'%' + word.upper() + '%\''
    search_string = search_string + ')'
    print(search_string)
    if db_table == 'searcher_exploit':
        return Exploit.objects.raw(search_string)
    else:
        return Shellcode.objects.raw(search_string)


def search_vulnerabilities_for_author_platform_type(search_text, db_table):
    words_list = str(search_text).split()
    search_string = 'select * from ' + db_table + ' where (author like \'%' + words_list[0].upper() + '%\''
    for word in words_list[1:]:
        search_string = search_string + ' or author like \'%' + word.upper() + '%\''
    search_string = search_string + ') or (platform like \'%' + words_list[0].upper() + '%\''
    for word in words_list[1:]:
        search_string = search_string + ' or platform like \'%' + word.upper() + '%\''
    search_string = search_string + ') or (vulnerability_type like \'%' + words_list[0].upper() + '%\''
    for word in words_list[1:]:
        search_string = search_string + ' or platform like \'%' + word.upper() + '%\''
    search_string = search_string + ')'
    print(search_string)
    if db_table == 'searcher_exploit':
        return Exploit.objects.raw(search_string)
    else:
        return Shellcode.objects.raw(search_string)


def search_exploits_exact(words):
    accepted_fileds = ['FILE', 'DESCRIPTION', 'AUTHOR', 'TYPE', 'PLATFORM', 'PORT']
    search_string = words[0]
    words_index = 1
    for word in words[1:]:
        if word != '--IN':
            search_string = search_string + ' ' + word
            words_index = words_index + 1
        else:
            if words[words_index + 1] not in accepted_fileds:
                words[words_index + 1] = 'DESCRIPTION'
                search_string = 'blablabla'
            if words[words_index + 1] == 'TYPE':
                words[words_index + 1] = 'VULNERABILITY_TYPE'
            if words[words_index + 1] == 'PORT' and search_string.isnumeric():
                return Exploit.objects.raw('select * from searcher_exploit where port = ' + search_string.upper())

            else:
                return Exploit.objects.raw('select * from searcher_exploit where ' + words[words_index + 1] + ' like \'%' + search_string.upper() + '%\'')


def search_shellcodes_exact(words):
    accepted_fileds = ['FILE', 'DESCRIPTION', 'AUTHOR', 'TYPE', 'PLATFORM']
    search_string = words[0]
    words_index = 1
    for word in words[1:]:
        if word != '--IN':
            search_string = search_string + ' ' + word
            words_index = words_index + 1
        else:
            if words[words_index + 1] not in accepted_fileds:
                words[words_index + 1] = 'DESCRIPTION'
                search_string = 'blablabla'
            if words[words_index + 1] == 'TYPE':
                words[words_index + 1] = 'VULNERABILITY_TYPE'
            return Exploit.objects.raw('select * from searcher_shellcode where ' + words[words_index + 1] + ' like \'%' + search_string.upper() + '%\'')


def is_valid_input(string):
    if not string.isspace() and string != '' and not str(string).__contains__('\''):
        return True
    else:
        return False


def str_contains_numbers(str):
    return bool(re.search(r'\d', str))


def str_is_num_version(str):
    return bool(re.search(r'(\d\.\d\.\d\.\d|\d\.\d\.\d|\d\.\d|\d)', str))


def get_num_version(software_name, description):
    software_name = software_name.upper()
    description = description.upper()
    regex = re.search(software_name + r' (\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+|\d+)', description)
    try:
        software = regex.group(0)
        regex = re.search(r'(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+|\d+)', software)
        try:
            return regex.group(0)
        except AttributeError:
            return
    except AttributeError:
        return


def get_num_version_with_comparator(software_name, description):
    software_name = software_name.upper()
    description = description.upper()
    regex = re.search(software_name + r' < (\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+|\d+)', description)
    try:
        software = regex.group(0)
        regex = re.search(r'(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+|\d+)', software)
        try:
            return regex.group(0)
        except AttributeError:
            return
    except AttributeError:
        return


def search_vulnerabilities_version(search_text, db_table):
    words = str(search_text).upper().split()
    software_name = words[0]
    for word in words[1:]:
        if not str_is_num_version(word):
            software_name = software_name + ' ' + word
        else:
            num_version = word
    # print(software_name, num_version)
    if db_table == 'searcher_exploit':
        return search_exploits_version(software_name, num_version)
    else:
        return search_shellcodes_version(software_name, num_version)


def search_exploits_version(software_name, num_version):
    queryset = Exploit.objects.filter(description__icontains=software_name)
    for exploit in queryset:
        if not str(exploit.description).__contains__('<'):
            try:
                if parse_version(num_version) != parse_version(get_num_version(software_name, exploit.description)):
                    queryset = queryset.exclude(description__exact=exploit.description)
            except TypeError:
                queryset = queryset.exclude(description__exact=exploit.description)
        else:
            try:
                if parse_version(num_version) > parse_version(get_num_version_with_comparator(software_name, exploit.description)):
                    queryset = queryset.exclude(description__exact=exploit.description)
            except TypeError:
                queryset = queryset.exclude(description__exact=exploit.description)
    return queryset


def search_shellcodes_version(software_name, num_version):
    queryset = Shellcode.objects.filter(description__icontains=software_name)
    for shellcode in queryset:
        if not str(shellcode.description).__contains__('<'):
            if num_version != get_num_version(software_name, shellcode.description) or get_num_version(software_name, shellcode.description) is None:
                print(get_num_version(software_name, shellcode.description))
                queryset = queryset.exclude(description__exact=shellcode.description)
        else:
            try:
                if LooseVersion(num_version) > LooseVersion(get_num_version_with_comparator(software_name, shellcode.description)):
                    queryset = queryset.exclude(description__exact=shellcode.description)
            except AttributeError:
                queryset = queryset.exclude(description__exact=shellcode.description)
    return queryset
