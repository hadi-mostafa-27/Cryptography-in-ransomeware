import os
import shutil


def list_plain_files(folder_path: str):
    """List non-encrypted files (no .enc_demo extension)."""
    return [
        os.path.join(folder_path, f)
        for f in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, f))
        and not f.endswith(".enc_demo")
    ]


def list_encrypted_files(folder_path: str):
    """List encrypted files (*.enc_demo)."""
    return [
        os.path.join(folder_path, f)
        for f in os.listdir(folder_path)
        if f.endswith(".enc_demo")
    ]


def create_backup(folder_path: str):
    """
    Create a full backup of the folder next to it: <folder>_backup.
    If it exists, it is overwritten.
    """
    backup = folder_path + "_backup"

    if os.path.exists(backup):
        shutil.rmtree(backup)

    shutil.copytree(folder_path, backup)
    return backup


def restore_backup(folder_path: str):
    """
    Restore files from <folder>_backup into <folder>.
    """
    backup = folder_path + "_backup"

    if not os.path.exists(backup):
        return False

    # Clear current folder
    for f in os.listdir(folder_path):
        full = os.path.join(folder_path, f)
        if os.path.isfile(full):
            os.remove(full)

    # Copy back from backup
    for f in os.listdir(backup):
        shutil.copy(os.path.join(backup, f), os.path.join(folder_path, f))

    return True
