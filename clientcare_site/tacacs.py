import re

from django_auth_tacacs import TACACSPLUS_AUTOCREATE_USERS

def custom_sync_user_relations(user, tacacs_attributes):
    tacacs_groups = list(tacacs_attributes.get(TACACSPLUS_AUTOCREATE_USERS, ()))
    print(tacacs_groups)

    # # print(user)
    # # print(ldap_attributes)
    # SYS = r'SYS-.*.(L2|L3)'
    # NET = r'NET-.*.(L2|L3)'
    # WS = r'(WANSI\-SGN|Client\-care|CC2\-SGN)'
    # for group_dict in groups:
    #     if re.match(SYS, group_dict['CN']):
    #         group_name = 'SYS'
    #         setattr(user, 'is_staff', True)
    #         setattr(user, 'is_superuser', True)
    #     elif re.match(NET, group_dict['CN']):
    #         group_name = 'NET'
    #         setattr(user, 'is_staff', True)
    #     elif re.match(WS, group_dict['CN']):
    #         group_name = 'ClientCare'
    #     else: continue
    #     group, created = Group.objects.get_or_create(name=group_name)

    #     # if 'OU' in group_dict.keys():
    #     #     for privilege in LDAP_AUTH_GROUP_ATTRS[group_dict['OU']]:
    #     #         setattr(user, privilege, True)

    #     user.save()
    #     user.groups.add(group)

    return

if __name__ == '__main__':
    custom_sync_user_relations()

