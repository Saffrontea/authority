"""Canonical interval construction at test input boundaries; no range expansion."""
import ipaddress

def ports(values):
    result = []
    for value in sorted(set(values)):
        if not 1 <= value <= 65535:
            raise ValueError('invalid test port')
        if result and result[-1]['end'] == value:
            result[-1]['end'] += 1
        else:
            result.append({'start': value, 'end': value + 1})
    return result

def host(value):
    address = int(ipaddress.IPv4Address(value))
    return [{'start': address, 'end': address + 1}]
