import subprocess

def get_file_path_from_inode(inode, search_path='/home/sharma/509'):
    try:
        # Use the 'find' command to locate the file by inode
        result = subprocess.check_output(
            ['find', search_path, '-inum', str(inode), '-print'],
            stderr=subprocess.DEVNULL,
        ).decode('utf-8').strip()

        if result:
            return result
        else:
            return f"No file found with inode {inode}."
    except subprocess.CalledProcessError as e:
        return f"Error finding inode: {str(e)}"

# Example usage
inode_number = 6816839  # Replace with your inode number
path = get_file_path_from_inode(inode_number)
print(f"The file path is: {path}")
