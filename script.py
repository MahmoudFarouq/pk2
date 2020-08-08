import os
import pk2

def print_data(entry, content):
    print(entry.to_string)
    with open('tmp/'+entry.name, 'wb') as f:
        f.write(bytes(content[1]))

extractor = pk2.Extractor("/home/sorcerer/Desktop/Media.pk2")

path = "server_dep/silkroad/textdata"

entries = extractor.list(path)

for entry in entries:
    if entry.entry_type == 2:
        content = extractor.extract(os.path.join(path, entry.name))[1]
        print_data(entry, content)
