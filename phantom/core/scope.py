import ipaddress
from typing import List

def is_in_scope(target: str, scope_list: List[str]) -> bool:
    """
    return true if the target is allowed by the scope
    - empty scope = everything allowed.
    - scope can contain single ips ora CIDR subnets
    - domain names are always allowed
    """
    if not scope_list:
        return True

    # if target is not an ip adress = treat as in scope
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
            return True
    
    for entry in scope_list:
        entry = entry.strip()
        try:
            if '/' in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if ip in network:
                    return True
            else:
                if ip == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            # invalid entry = skip
            continue
    return False