import json
import os
from time import sleep
from secrets import token_urlsafe
from cryptography.fernet import Fernet
try:
    from pyfiglet import Figlet
except ImportError:
    Figlet = None


def print_menu():
    if Figlet is not None:
        f = Figlet(width=100)
        print(f.renderText('Password Manager'))
    else:
        print("\n**********************************************************************")
        print("*                          Password Manager                          *")
        print("**********************************************************************\n")


def choose_an_option():
    print("    MENU:")
    print("    1) Search stored passwords")
    print("    2) Add a new password")
    print("    3) Update a password")
    print("    4) Show all stored passwords")
    print("    5) Delete a stored password")
    print("    6) Quit")
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
        print("    Setting this randomly generated password as the new password:"+custom_password)
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
                    print("    Setting this randomly generated password as the new password:"+custom_password)
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


def quit_the_app():
    for i in range(len(passwords)):
        passwords[i] = encrypt_password(passwords[i], full_pass_phrase)

    vault = {
        "User_part": Fernet(full_pass_phrase.encode()).encrypt(user_part.encode()).decode(),
        "Vault_part": vault_part,
        "Passwords": passwords
    }
    with open('password_vault.vault', 'w') as json_file:
        json.dump(vault, json_file, sort_keys=True, indent=4)
    print("\n**********************************************************************\n")
    print("    Your changes have been saved successfully.")
    print("\n**********************************************************************\n")
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

        recreated_user_part = Fernet(recreated_key.encode()).decrypt(encrypted_user_part.encode()).decode()
        if recreated_user_part == user_part:
            print("    Validation completed successfully.")
            return recreated_key
        else:
            print("    Validation failed. Wrong password.")
            return None
    else:
        print("    There's no password vault in this directory.")
        return None


def load_vault():
    passwords = None
    vault_part = None
    if os.path.isfile('password_vault.vault'):
        with open('password_vault.vault', 'r') as json_file:
            passwords = []
            data = json.load(json_file)
            passwords = data['Passwords']
            vault_part = data['Vault_part']

    if passwords is None:
        print("    You have no password-vault file in this directory. Making a new password-vault..")
        pass_bytes = Fernet.generate_key()
        full_pass_phrase = pass_bytes.decode()
        size = int(input("    Choose how long you want your password-vault's password to be [7 - 44]:"))
        while size < 7 or size > 44:
            print("    Choose how long you want your password-vault's password to be.")
            size = int(input("    You have to choose a number between 7 and 44:"))
        user_part = full_pass_phrase[:size]
        vault_part = full_pass_phrase[size:]
        passwords = []
        encoded_user_part = Fernet(pass_bytes).encrypt(user_part.encode()).decode()
        print(encoded_user_part)
        print("    Your random generated code:", full_pass_phrase[:size])
        print("    DO NOT lose it or else you will not be able to recover your password-vault.")
        vault = {
            "User_part": encoded_user_part,
            "Vault_part": vault_part,
            "Passwords": []
        }
        with open('password_vault.vault', 'w') as json_file:
            json.dump(vault, json_file, sort_keys=True, indent=4)
        print("    Your vault has been created successfully.")
    else:
        user_part = input("----Enter your vault password:")
        print("\n**********************************************************************\n")
        full_pass_phrase = auth_vault(user_part)
        print("\n**********************************************************************\n")
        if full_pass_phrase is not None:
            for i in range(len(passwords)):
                passwords[i] = decrypt_password(passwords[i], full_pass_phrase)
    return passwords, vault_part, user_part, full_pass_phrase


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


def main():
    option_dict = {
        "1": search_passwords,
        "2": add_password,
        "3": update_password,
        "4": show_stored_passwords,
        "5": delete_a_password,
        "6": quit_the_app
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
