# Uses python-hcl2 to convert Terraform to JSON
import hcl2

def parse_hcl(file_path):
    """Converts a Terraform file into a Python dictionary."""
    try:
        with open(file_path, "r") as f:
            return hcl2.load(f)
    except Exception as e:
        return {"error": str(e)}