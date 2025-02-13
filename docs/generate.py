import os

# get all the markdown files in the source repo
# returns a list of tuples with the directory name and the path to the file
# e.g., [("accountsdb", "src/accountsdb/readme.md")]
def get_markdown_files(
    src_path: str,
    exclude_dirs: list[str]
):
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

    return doc_files

# generate the docs from the source files
if __name__ == "__main__":
    # point to the source sig/ repo
    # (should be run from the docs/ directory)
    src_path = "../"
    code_docs_path = "docusaurus/docs/code"

    # dirs which not to search
    exclude_dirs = [
        src_path + "docs", # dont search yourself
        src_path + "data", # this should only include data
    ]

    for name, path in get_markdown_files(src_path, exclude_dirs):
        # copy the file to the docs/code directory
        new_path = os.path.join(code_docs_path, name + ".md")
        with open(path, "r") as f:
            with open(new_path, "w") as nf:
                # fix image paths for docusaurus
                for line in f:
                    if "/docs/docusaurus/static/img" in line:
                        line = line.replace("/docs/docusaurus/static/img", "/img")
                    nf.write(line)
