# parse capa's json to ghidra's bookmark
# @author sumirou
# @category Data
#

import json

# ghidra
from ghidra.program.model.listing import CodeUnit

class ProcessError(RuntimeError):
    pass

class CapaMatchData:
    def __init__(self, pn, nm, al):
        self.pattern_name = pn
        self.namespace = nm
        self.addr_list = al

def int_to_addr(v):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v)

def parse_json(file_path):
    with open(file_path) as fp:
        j = json.load(fp)
    if not isinstance(j['rules'], dict):
        raise ProcessError()
    match_result = []
    for k in j['rules'].keys():
        pattern_name = k
        if 'namespace' in j['rules'][k]['meta']:
            space = j['rules'][k]['meta']['namespace']
        else:
            space = 'none'
        addr_list = []
        for match in j['rules'][k]['matches']:
            if match[0]['type'] == 'no address':
                continue
            addr_list.append(match[0]['value'])
        match_result.append(CapaMatchData(pattern_name, space, addr_list))

    return match_result

def set_to_ghidra(data):
    # set bookmark
    for d in data:
        bookmark = currentProgram.getBookmarkManager()
        for addr in d.addr_list:
            a = int_to_addr(addr)
            bookmark.setBookmark(a, "Info", d.namespace, d.pattern_name)
    # set EOL comment
    for d in data:
        for addr in d.addr_list:
            a = int_to_addr(addr)
            currentProgram.getListing().setComment(a, CodeUnit.EOL_COMMENT, d.pattern_name)

def main():
    log_path = askFile("Drltrace log", "Choose file:")
    log_path = str(log_path)
    match_list = parse_json(log_path)
    set_to_ghidra(match_list)

if __name__ == '__main__':
    main()
