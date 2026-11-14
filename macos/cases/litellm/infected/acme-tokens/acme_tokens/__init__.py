"""acme-tokens: a rough count of the tokens in a prompt."""
import re


def count(text):
    return len(re.findall(r"\w+|[^\w\s]", text))
