import os

# point to the source sig/ repo
src_path = "../"
code_docs_path = "docusaurus/docs/code"

# dirs which not to search
exclude_dirs = [
    src_path + "docs", # dont search yourself
    src_path + "data", # this should only include data
]

# iterate over all files in sig repo
doc_files = []
for root, dirs, files in os.walk(src_path):

    # check for exclusion
    should_exclude = False
    for exclude in exclude_dirs:
        if exclude in root:
            should_exclude = True
            break
    if should_exclude: continue

    # add all markdown files to list
    for file in files:
        if file.endswith(".md"):
            dir_name = os.path.basename(root)
            if dir_name == "":
                # this is the root readme.md -- we dont include
                # it in the docs for now
                continue
            doc_files.append([
                dir_name,
                os.path.join(root, file)
            ])

for name, path in doc_files:
    # copy the file to the docs/code directory
    new_path = os.path.join(code_docs_path, name + ".md")
    with open(path, "r") as f:
        with open(new_path, "w") as nf:
            nf.write(f.read())
