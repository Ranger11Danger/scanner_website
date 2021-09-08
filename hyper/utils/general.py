import json
from hyper.dashboard.models import scan, port_info, asset_group, asset
from .process_scan import read_scan
import ipaddress
class GenericObject(dict):
    """
    A dict subclass that provides access to its members as if they were
    attributes.
    Note that an attribute that has the same name as one of dict's existing
    method (``keys``, ``items``, etc.) will not be accessible as an attribute.
    """
    @classmethod
    def from_json(cls, json_string):
        """
        Parses the given json_string, returning GenericObject instances instead
        of dicts.
        """
        return json.loads(json_string, object_hook=cls)

    def __setattr__(self, prop, val):
        if prop[0] == '_' or prop in self.__dict__:
            return super(GenericObject, self).__setattr__(prop, val)
        else:
            self[prop] = val

    def __getattr__(self, prop):
        """
        Provides access to the members of the dict as attributes.
        """
        if prop in self:
            return self[prop]
        else:
            raise AttributeError
    
    def __delitem__(self, prop):
        # on delete, setting value to None
        if prop in self:
            self[prop] = None
    '''
    def __repr__(self):
        ident_parts = [type(self).__name__]
        if isinstance(self, dict):
            ident_parts.append('id=%s' % (self.get('id'),))
        elif isinstance(self.get('id'), dict):
            sid = self.get('id').get('id')
            ident_parts.append('id=%s' % (sid,))
        elif isinstance(self.get('id'), basestring):
            ident_parts.append('id=%s' % (self.get('id'),))
        unicode_repr = '<%s at %s> : %s' % (
            ' '.join(ident_parts), hex(id(self)), str(self))
        if sys.version_info[0] < 3:
            return unicode_repr.encode('utf-8')
        else:
            return unicode_repr
    '''
    def __str__(self):
        if isinstance(self.get('id'), dict):
            self = self.get('id')
        data = self.copy()
        return json.dumps(data, sort_keys=True, indent=2)

def list_of_dict_to_list_to_obj(list_of_dict):
    list_of_obj = []
    for data in list_of_dict:
        list_of_obj.append(GenericObject(data))
    return list_of_obj

def make_chuncks_of_number_of_elements(element_per_chunk, data_list):
    return [data_list[i:i + element_per_chunk] for i in range(0, len(data_list), element_per_chunk)]


def get_scan_data(slug,user):
    data = port_info.objects.filter(scan_id=slug).filter(user=user)
    return(data)

def select_scans(uid):
    scans = scan.objects.filter(user=uid)
    return(scans)

def list_scans():
    scans = scan.objects.all()
    return(scans)

def add_scan(user, name, address):
    new_scan = scan()
    new_scan.user = user
    new_scan.name = name
    new_scan.slug = f"scan-{new_scan.uuid}"
    new_scan.address = address
    new_scan.save()
    return new_scan.slug

def clear_scans(user, uuid):
    scan.objects.all().filter(user=user).filter(uuid=uuid).delete()

def clear_ports(user, slug):
    port_info.objects.all().filter(user=user).filter(scan_id=slug).delete()

def clear_all_ports():
    port_info.objects.all().delete()

def clear_all_scans():
    scan.objects.all().delete()

def select_slug(uuid, user):
    my_scan = scan.objects.filter(user=user).filter(uuid=uuid)
    return(my_scan)

def num_cves(user):
    cves = port_info.objects.filter(user=user)
    return(cves)

def get_cve(slug, cve, user):
    cve = port_info.objects.filter(user=user).filter(scan_id = slug).filter(cve=cve)
    return cve

def convert_scan_to_model(file, slug):
    task = read_scan.delay(f'/workspaces/scanner_website/hyper/scans/{file}', slug)
    return task



def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        return True
    except ipaddress.AddressValueError:
        return False

def clense_ips(ips):
    temp = []
    for x in ips.split():
        if is_ipv4(x):
            temp.append(x)
    return temp

def get_ips(user):
    ip_list = [ip['ip'] for ip in port_info.objects.filter(user=user).values('ip').distinct()]
    return ip_list

def get_address_data(user, address):
    data = port_info.objects.filter(user=user, ip=address)
    return data

def get_address_cve(address, user, cve):
    cve = port_info.objects.filter(user=user).filter(ip = address).filter(cve=cve)
    return cve

def get_asset_groups(user):
    groups = asset_group.objects.filter(user=user)
    return groups

def get_assets(user, group):
    asset_list  = [asset['address'] for asset in asset.objects.filter(user=user, group=group).values('address').distinct()]
    return asset_list

def create_asset_group(user, name):
    group = asset_group(user=user, name=name)
    group.save()

def change_group_name(gid, name):
    asset_group.objects.filter(id = gid).update(name = name)

def add_asset_to_group(ip, user, group):
    group_obj = asset_group.objects.filter(id=group)
    new_asset = asset(address=ip, user=user, group=group_obj[0])
    new_asset.save()

def del_asset_from_group(user, gid, address):
    asset.objects.filter(user=user, group = gid, address=address).delete()

def get_top_ten(user):
    ip_list = get_ips(user)
    ip_stats = {}
    for ip in ip_list[:10]:
        ip_stats[ip] = len(get_address_data(user, ip))
    return sorted(ip_stats.items(), key=lambda x:x[1], reverse=True)