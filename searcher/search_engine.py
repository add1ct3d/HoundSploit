from functools import reduce
from searcher.models import Exploit, Shellcode
import re
from django.db.models import Q
import operator
from pkg_resources import parse_version


def search_vulnerabilities_in_db(search_text, db_table):
    words = (str(search_text).upper()).split()
    if str(search_text).isnumeric():
        queryset = search_vulnerabilities_numerical(search_text, db_table)
        queryset = highlight_keywords_in_file(words, queryset)
        queryset = highlight_keywords_in_description(words, queryset)
        if db_table == 'searcher_exploit':
            queryset = highlight_keywords_in_port(words, queryset)
        return queryset
    elif str_is_num_version(str(search_text)) and str(search_text).__contains__(' ') and not str(search_text).__contains__('<'):
        queryset = search_vulnerabilities_version(search_text, db_table)
        return highlight_keywords_in_description(words, queryset)
    else:
        queryset = search_vulnerabilities_for_description(search_text, db_table)
        if len(queryset) > 0:
            return highlight_keywords_in_description(words, queryset)
        else:
            queryset = search_vulnerabilities_for_file(search_text, db_table)
            if len(queryset) > 0:
                return highlight_keywords_in_file(words, queryset)
            else:
                queryset = search_vulnerabilities_for_author(search_text, db_table)
                return highlight_keywords_in_author(words, queryset)


def search_vulnerabilities_numerical(search_text, db_table):
    if db_table == 'searcher_exploit':
        return Exploit.objects.filter(Q(id__exact=int(search_text)) | Q(file__contains=search_text) | Q(description__contains=search_text) | Q(port__exact=int(search_text)))
    else:
        return Shellcode.objects.filter(Q(id__exact=int(search_text)) | Q(file__contains=search_text) | Q(description__contains=search_text))


def search_vulnerabilities_for_description(search_text, db_table):
    # I have installed reduce
    words_list = str(search_text).split()
    query = reduce(operator.and_, (Q(description__icontains=word) for word in words_list))
    if db_table == 'searcher_exploit':
        queryset = Exploit.objects.filter(query)
    else:
        queryset = Shellcode.objects.filter(query)
    return queryset


def search_vulnerabilities_for_file(search_text, db_table):
    words_list = str(search_text).split()
    query = reduce(operator.or_, (Q(file__icontains=word) for word in words_list))
    if db_table == 'searcher_exploit':
        queryset = Exploit.objects.filter(query)
    else:
        queryset = Shellcode.objects.filter(query)
    return queryset


def search_vulnerabilities_for_author(search_text, db_table):
    words_list = str(search_text).split()
    query = reduce(operator.and_, (Q(author__icontains=word) for word in words_list))
    if db_table == 'searcher_exploit':
        queryset = Exploit.objects.filter(query)
    else:
        queryset = Shellcode.objects.filter(query)
    return queryset


def is_valid_input(string):
    if not string.isspace() and string != '' and not str(string).__contains__('\''):
        return True
    else:
        return False


def str_contains_numbers(str):
    return bool(re.search(r'\d', str))


def str_is_num_version(str):
    return bool(re.search(r'(\d\.\d\.\d\.\d|\d\.\d\.\d|\d\.\d|\d)', str))


def str_contains_num_version_range(str):
    return bool(re.search(r'(\d\.\d\.\d\.\d|\d\.\d\.\d|\d\.\d|\d) < (\d\.\d\.\d\.\d|\d\.\d\.\d|\d\.\d|\d)', str))


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


def is_in_version_range(num_version, software_name, description):
    software_name = software_name.upper()
    description = description.upper()
    regex = re.search(software_name + r' (\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+|\d+) < (\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+|\d+)', description)
    try:
        software = regex.group(0)
        regex = re.search(r'(?P<from_version>(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+|\d+)) < (?P<to_version>(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+|\d+))', software)
        if parse_version(num_version) >= parse_version(regex.group('from_version')) and parse_version(num_version) <= parse_version(regex.group('to_version')):
            return True
        else:
            return False
    except AttributeError:
        return False


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
            if str_contains_num_version_range(str(exploit.description)):
                if not is_in_version_range(num_version, software_name, exploit.description):
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
            try:
                if parse_version(num_version) != parse_version(get_num_version(software_name, shellcode.description)):
                    queryset = queryset.exclude(description__exact=shellcode.description)
            except TypeError:
                queryset = queryset.exclude(description__exact=shellcode.description)
        else:
            if str_contains_num_version_range(str(shellcode.description)):
                if not is_in_version_range(num_version, software_name, shellcode.description):
                    queryset = queryset.exclude(description__exact=shellcode.description)
            else:
                try:
                    if parse_version(num_version) > parse_version(get_num_version_with_comparator(software_name, shellcode.description)):
                        queryset = queryset.exclude(description__exact=shellcode.description)
                except TypeError:
                    queryset = queryset.exclude(description__exact=shellcode.description)
    return queryset


def highlight_keywords_in_description(keywords_list, queryset):
    for vulnerability in queryset:
        for keyword in keywords_list:
            description = str(vulnerability.description).upper()
            if description.__contains__(keyword):
                regex = re.compile(re.escape(keyword), re.IGNORECASE)
                vulnerability.description = regex.sub("<span class='keyword'>" + keyword + '</span>', vulnerability.description)
    return queryset


def highlight_keywords_in_file(keywords_list, queryset):
    for vulnerability in queryset:
        for keyword in keywords_list:
            file = str(vulnerability.file).upper()
            if file.__contains__(keyword):
                regex = re.compile(re.escape(keyword), re.IGNORECASE)
                vulnerability.file = regex.sub("<span class='keyword'>" + keyword + '</span>', vulnerability.file)
    return queryset


def highlight_keywords_in_author(keywords_list, queryset):
    for vulnerability in queryset:
        for keyword in keywords_list:
            file = str(vulnerability.author).upper()
            if file.__contains__(keyword):
                regex = re.compile(re.escape(keyword), re.IGNORECASE)
                vulnerability.author = regex.sub("<span class='keyword'>" + keyword + '</span>', vulnerability.author)
    return queryset


def highlight_keywords_in_port(keywords_list, queryset):
    for exploit in queryset:
        for keyword in keywords_list:
            file = str(exploit.port).upper()
            if file.__contains__(keyword):
                regex = re.compile(re.escape(keyword), re.IGNORECASE)
                exploit.port = regex.sub("<span class='keyword'>" + keyword + '</span>', exploit.port)
    return queryset


def search_vulnerabilities_advanced(search_text, db_table, operator_filter, type_filter, platform_filter, author_filter):
    words_list = str(search_text).upper().split()
    if operator_filter == 'AND':
        query = reduce(operator.and_, (Q(description__icontains=word) for word in words_list))
    else:
        query = reduce(operator.or_, (Q(description__icontains=word) for word in words_list))
    if db_table == 'searcher_exploit':
        queryset = Exploit.objects.filter(query)
    else:
        queryset = Shellcode.objects.filter(query)
    if type_filter != 'All':
        queryset = queryset.filter(vulnerability_type__exact=type_filter)
    if platform_filter != 'All':
        queryset = queryset.filter(platform__exact=platform_filter)
    if author_filter != '':
        queryset = queryset.filter(author__iexact=author_filter)
    return highlight_keywords_in_description(words_list, queryset)
