from searcher.models import Exploit, Shellcode
import re


def search_vulnerabilities_in_db(search_text, db_table):
    words = (str(search_text).upper()).split()
    if (words[0] == '--EXACT' and '--IN' in words) and db_table == 'searcher_exploit':
        return search_exploits_exact(words[1:])

    if (words[0] == '--EXACT' and '--IN' in words) and db_table == 'searcher_shellcode':
        return search_shellcodes_exact(words[1:])

    if str(search_text).isnumeric():
        return search_vulnerabilities_numerical(search_text, db_table)
    elif str_contains_numbers(str(search_text)):
        # todo temporary code
        queryset = search_vulnerabilities_for_description(search_text, db_table)
        if len(queryset) > 0:
            return queryset
        else:
            queryset = search_vulnerabilities_for_file(search_text, db_table)
            if len(queryset) > 0:
                return queryset
            else:
                return search_vulnerabilities_for_author_platform_type(search_text, db_table)
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
        search_string = 'select * from searcher_exploit where ' + 'id = ' + search_text + ' or file like \'%' + search_text + '%\' or description like \'%' + search_text + '%\' or port = ' + search_text
        return Exploit.objects.raw(search_string)
    else:
        search_string = 'select * from searcher_shellcode where ' + 'id = ' + search_text + ' or file like \'%' + search_text + '%\' or description like \'%' + search_text + '\''
        return Shellcode.objects.raw(search_string)


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