import json
import os
from secrets import token_urlsafe
from time import sleep

from cryptography.fernet import Fernet,InvalidToken


def print_menu():
    print(r"""
 ____                                     _   __  __                                   
|  _ \ __ _ ___ _____      _____  _ __ __| | |  \/  | __ _ _ __   __ _  __ _  ___ _ __ 
| |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` | | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|
|  __/ (_| \__ \__ \\ V  V / (_) | | | (_| | | |  | | (_| | | | | (_| | (_| |  __/ |   
|_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_| |_|  |_|\__,_|_| |_|\__,_|\__, |\___|_|   
                                                                        |___/           
        """)


def choose_an_option():
    print("    MENU:")
    print("    1) Search stored passwords")
    print("    2) Add a new password")
    print("    3) Update a password")
    print("    4) Show all stored passwords")
    print("    5) Delete a stored password")
    print("    6) Change the vault's password")
    print("    7) Quit")
    return input("    Choose on of the above options:")


def search_passwords():
    site_to_find = input("    Enter the site or app of the account you want to find:")
    found = False
    print("\n                           Search Results:                           ")
    print("\n**********************************************************************\n")
    for i in range(len(passwords)):
        if site_to_find.lower() in passwords[i]["site/app"].lower():
            found = True
            print("    Site/App:", passwords[i]["site/app"])
            print("    Username:", passwords[i]["username"])
            print("    Password:", passwords[i]["password"])
            print("\n**********************************************************************\n")
    if not found:
        print("    No such site/app account in the vault.")
        print("\n**********************************************************************\n")


def add_password():
    print("\n**********************************************************************\n")
    username = input("    Enter the username of the account to add:")
    want_suggestion = input("    Want to use a suggested password? [yes/no]:")
    while want_suggestion != "yes" and want_suggestion != "no":
        want_suggestion = input("    Enter yes or no:")
    if want_suggestion == "yes":
        custom_password = token_urlsafe(9)
        print("    Setting this randomly generated password as the new password:" + custom_password)
        password = custom_password
    else:
        password = input("    Enter the password of the account to add:")

    site = input("    Enter the site or app this account is for:")
    pre_existing = False
    for i in range(len(passwords)):
        if passwords[i]["site/app"] == site and passwords[i]["username"] == username:
            pre_existing = True
            print("    There's already a stored password for this site and username.")
            update = input("    Do you want to update it? [yes/no]:")
            while update != "yes" and update != "no":
                update = input("    Enter yes or no:")
            if update == "yes":
                new_pass = input("    Enter the new password:")
                passwords[i] = new_pass
            else:
                print("    The password was not changed.")

    if not pre_existing:
        password_json = {
            "site/app": site,
            "username": username,
            "password": password
        }
        passwords.append(password_json)
        print("\n    Password was added successfully.")
    print("\n**********************************************************************\n")


def update_password():
    print("\n**********************************************************************\n")
    site_to_update = input("    Enter the site or app of the account you want to update:")
    username_to_update = input("    Enter the username of the account you want to update:")
    found = False
    for i in range(len(passwords)):
        if passwords[i]["site/app"] == site_to_update and passwords[i]["username"] == username_to_update:
            found = True
            sure = input("    Are you sure you want to update this password? [yes/no]:")
            while sure != "yes" and sure != "no":
                sure = input("    Enter yes or no:")
            if sure == "yes":
                want_suggestion = input("    Want to use a suggested password? [yes/no]:")
                while want_suggestion != "yes" and want_suggestion != "no":
                    want_suggestion = input("    Enter yes or no:")
                if want_suggestion == "yes":
                    custom_password = token_urlsafe(9)
                    print("    Setting this randomly generated password as the new password:" + custom_password)
                    passwords[i]["password"] = custom_password
                else:
                    new_pass = input("    Enter the new password:")
                    passwords[i]["password"] = new_pass
            else:
                print("    The password was not changed.")
    if not found:
        print("    No such site/app account and username in the vault.")
    print("\n**********************************************************************\n")


def decrypt_password(password_to_decrypt, recreated_key):
    decrypted_pass = {
        "site/app": Fernet(recreated_key.encode()).decrypt(password_to_decrypt["site/app"].encode()).decode(),
        "username": Fernet(recreated_key.encode()).decrypt(password_to_decrypt["username"].encode()).decode(),
        "password": Fernet(recreated_key.encode()).decrypt(password_to_decrypt["password"].encode()).decode()
    }

    return decrypted_pass


def encrypt_password(password_to_encrypt, recreated_key):
    encrypted_pass = {
        "site/app": Fernet(recreated_key.encode()).encrypt(password_to_encrypt["site/app"].encode()).decode(),
        "username": Fernet(recreated_key.encode()).encrypt(password_to_encrypt["username"].encode()).decode(),
        "password": Fernet(recreated_key.encode()).encrypt(password_to_encrypt["password"].encode()).decode()
    }

    return encrypted_pass


def show_stored_passwords():
    if len(passwords) == 0:
        print("\n**********************************************************************\n")
        print("    The vault is still empty. No passwords to display yet.")
        print("\n**********************************************************************\n")
    else:
        print("\n                        Stored passwords:                           ")
        print("**********************************************************************\n")
        for i in range(len(passwords)):
            print("    Site/App:", passwords[i]["site/app"])
            print("    Username:", passwords[i]["username"])
            print("    Password:", passwords[i]["password"])
            print("\n**********************************************************************\n")


def save_changes(pass_phrase, vault_part):
    print("Pass phrase:", pass_phrase)
    encrypted_passwords = []
    for i in range(len(passwords)):
        encrypted_passwords.append(encrypt_password(passwords[i], pass_phrase))

    vault = {
        "User_part": Fernet(pass_phrase.encode()).encrypt(user_part.encode()).decode(),
        "Vault_part": vault_part,
        "Passwords": encrypted_passwords
    }
    with open('password_vault.vault', 'w') as json_file:
        json.dump(vault, json_file, sort_keys=True, indent=4)
    print("\n**********************************************************************\n")
    print("    Your changes have been saved successfully.")
    print("\n**********************************************************************\n")


def quit_the_app():
    global full_pass_phrase
    global vault_part
    save_changes(full_pass_phrase, vault_part)
    input("    Press Enter to exit the vault...")
    quit()


def auth_vault(user_part):
    if os.path.isfile('password_vault.vault'):
        with open('password_vault.vault', 'r') as json_file:
            data = json.load(json_file)
            loaded_vault_part = data['Vault_part']
            encrypted_user_part = data['User_part']
        recreated_key = user_part + loaded_vault_part
        if len(recreated_key) != 44:
            print("    Validation failed. Wrong password.")
            return None
        try:
            recreated_user_part = Fernet(recreated_key.encode()).decrypt(encrypted_user_part.encode()).decode()
        except InvalidToken:
            recreated_user_part = None
        if recreated_user_part == user_part:
            print("    Validation completed successfully.")
            return recreated_key
        else:
            print("    Validation failed. Wrong password.")
            return None
    else:
        print("    There's no password vault in this directory.")
        return None


def generate_password():
    pass_bytes = Fernet.generate_key()
    pass_phrase = pass_bytes.decode()
    size = int(input("    Choose how long you want your password-vault's password to be [7 - 44]:"))
    while size < 7 or size > 44:
        print("    Choose how long you want your password-vault's password to be.")
        size = int(input("    You have to choose a number between 7 and 44:"))
    user_part = pass_phrase[:size]
    vault_part = pass_phrase[size:]
    passwords = []

    print("    Your random generated code:", pass_phrase[:size])
    print("    DO NOT lose it or else you will not be able to recover your password-vault.")
    return pass_bytes, user_part, vault_part


def load_vault():
    passwords = None
    vault_part = None
    global user_part
    if os.path.isfile('password_vault.vault'):
        with open('password_vault.vault', 'r') as json_file:
            passwords = []
            data = json.load(json_file)
            passwords = data['Passwords']
            vault_part = data['Vault_part']

    if passwords is None:
        print("    You have no password-vault file in this directory. Making a new password-vault..")
        pass_bytes, user_part, vault_part = generate_password()
        encoded_user_part = Fernet(pass_bytes).encrypt(user_part.encode()).decode()
        # print(encoded_user_part)
        passwords = []
        vault = {
            "User_part": encoded_user_part,
            "Vault_part": vault_part,
            "Passwords": passwords
        }
        pass_phrase = user_part + vault_part
        with open('password_vault.vault', 'w') as json_file:
            json.dump(vault, json_file, sort_keys=True, indent=4)
        print("    Your vault has been created successfully.")
    else:
        user_part = input("----Enter your vault password:")
        print("\n**********************************************************************\n")
        pass_phrase = auth_vault(user_part)
        print("\n**********************************************************************\n")
        if pass_phrase is not None:
            for i in range(len(passwords)):
                passwords[i] = decrypt_password(passwords[i], pass_phrase)
    return passwords, vault_part, user_part, pass_phrase


def delete_a_password():
    print("\n**********************************************************************\n")
    site_to_delete = input("    Enter the site or app of the account you want to delete:")
    username_to_delete = input("    Enter the username of the account you want to delete:")
    found = False
    for i in range(len(passwords)):
        if passwords[i]["site/app"] == site_to_delete and passwords[i]["username"] == username_to_delete:
            found = True
            sure = input("    Are you sure you want to delete this password? [yes/no]:")
            while sure != "yes" and sure != "no":
                sure = input("    Enter yes or no:")
            if sure == "yes":
                passwords.pop(i)
                print("    The password has been removed from the vault.")
            else:
                print("    The password was not deleted.")
    if not found:
        print("    No such site/app account and username in the vault.")
    print("\n**********************************************************************\n")


def change_vault_password():
    print("\n**********************************************************************\n")
    current_user_part = input("    Enter the current password:")
    global user_part, full_pass_phrase, vault_part
    if current_user_part == user_part:
        sure = input("    Are you sure you want to change the password? [yes or no]:")
        while sure != "yes" and sure != "no":
            sure = input("    Enter yes or no to select an option:")
        if sure == "yes":
            print("    You can set a new secure random password [option 1] or choose one on your own [ option 2].")
            pass_option = input("    Choose between the two options above [1 or 2]:")
            while pass_option != "1" and pass_option != "2":
                pass_option = input("    Enter 1 or 2 to select an option:")
            if pass_option == "1":
                pass_bytes, user_part, vault_part = generate_password()
                full_pass_phrase = user_part+vault_part

            else:
                new_user_part = input("    Enter the new password [at least 7 characters]:")
                while len(new_user_part) < 7 or len(new_user_part) > 44:
                    print("    The new password must be between 7 and 44 characters long. ")
                    new_user_part = input("    Enter the new password:")
                pass_bytes = Fernet.generate_key()
                random_pass_phrase = pass_bytes.decode()
                user_part = new_user_part
                size = len(user_part)
                vault_part = random_pass_phrase[size:]
                full_pass_phrase = user_part + vault_part
            save_changes(full_pass_phrase, vault_part)
            print(full_pass_phrase)
        else:
            print("Password update cancelled.")
            print("\n**********************************************************************\n")
    else:
        print("Wrong password.")
        print("\n**********************************************************************\n")


global passwords, vault_part, user_part, full_pass_phrase


def main():
    option_dict = {
        "1": search_passwords,
        "2": add_password,
        "3": update_password,
        "4": show_stored_passwords,
        "5": delete_a_password,
        "6": change_vault_password,
        "7": quit_the_app
    }
    print_menu()
    global passwords, vault_part, user_part, full_pass_phrase
    passwords, vault_part, user_part, full_pass_phrase = load_vault()
    if full_pass_phrase is None:
        sleep(4)
        quit()
    while True:
        option = choose_an_option()
        while option not in option_dict.keys():
            option = choose_an_option()
        option_dict[option]()


if __name__ == "__main__":
    main()
