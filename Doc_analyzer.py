import oletools
import oletools.oleid
import olefile
import sys




filename = input("Input file name to analysis: ")
oid = oletools.oleid.OleID(filename)
indicators = oid.check()
for i in indicators:
    print('Indicator id=%s name="%s" type=%s value=%s' % (i.id, i.name, i.type, repr(i.value)))
    print('description:', i.description)
    print('')


input()
