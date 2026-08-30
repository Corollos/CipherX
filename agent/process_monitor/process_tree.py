"""
CIPHER-X Process Tree

Builds a parent-child representation of processes
running on the Windows endpoint.
"""

import psutil


def collect_process_tree():
    """Collect running processes and organize them by parent PID."""

    processes = {}

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username"]
    ):
        try:
            info = process.info

            processes[info["pid"]] = {
                "pid": info["pid"],
                "parent_pid": info["ppid"],
                "name": info["name"],
                "executable": info["exe"],
                "username": info["username"],
                "children": [],
            }

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Build parent → child relationships.
    for pid, process in processes.items():
        parent_pid = process["parent_pid"]

        # PID 0 is a special Windows system process.
        # Prevent it from becoming its own child.
        if pid == 0:
            continue

        if parent_pid in processes:
            processes[parent_pid]["children"].append(pid)

    return processes


def print_process_tree(processes, pid, depth=0):
    """Recursively print a process and its descendants."""

    process = processes.get(pid)

    if process is None:
        return

    indent = "    " * depth

    print(
        f"{indent}{process['name']} "
        f"(PID: {process['pid']})"
    )

    for child_pid in process["children"]:
        print_process_tree(processes, child_pid, depth + 1)


if __name__ == "__main__":
    process_tree = collect_process_tree()

    print(
        f"CIPHER-X collected "
        f"{len(process_tree)} processes.\n"
    )

    # Display a few root processes.
    root_processes = [
        process
        for process in process_tree.values()
        if process["parent_pid"] not in process_tree
    ]

    for process in root_processes[:5]:
        print(f"\nProcess tree starting at {process['name']}:")
        print_process_tree(process_tree, process["pid"])