import ipaddress
from typing import List

def is_in_scope(target: str, scope_list: List[str]) -> bool:
    if not scope_list:
        return True
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # Domain names always allowed
        return True

    for entry in scope_list:
        entry = entry.strip()
        try:
            if '/' in entry:
                network = ipaddress.ip_network(entry, strict=True)
                if ip in network:
                    return True
            else:
                if ip == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False