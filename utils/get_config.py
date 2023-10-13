import json

def fetch_config(type_list: list):
    try:
        with open("config.json", "r") as config_obj:
            data = json.load(config_obj)
    except FileNotFoundError as e:
        print(e)

    fetch_bag = {}
    
    for item in type_list:
        if item in data.keys():
            fetch_bag[item] = data[item]
    return fetch_bag

# result = fetch_config(["asci_size", "sha_iters"])

# print(result)