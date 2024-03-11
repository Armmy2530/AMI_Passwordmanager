import os
import time
from cryptography.fernet import Fernet 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
import base64
import json

class password_manager_system:
    __auth = False
    def is_newuser(self):
        return not(os.path.exists(data_folder))
    
    def get_master_password(self):
        master_password = getpass("Enter your master password: ")
        return master_password
    
    def setup_newuser(self):
        os.makedirs(data_folder)       
        self.__master_password = self.get_master_password()
        key = self.hash_data(self.__master_password,salt=self.__master_password)

        fernet = Fernet(key) 
        Key_File = open("E:/Documents/Project/AMI_python_sec2/final project/PasswordManager/data/.key" , "wb")
        Key_File.write(fernet.encrypt(key))
        Key_File.close()

        self.load_key()
        self.write_encrypt_data("{}")

    def hash_data(self,master_password, salt = "salt"):
        # Convert the password and salt to bytes
        password = master_password.encode('utf-8')
        salt = salt.encode('utf-8')
            
        # Use PBKDF2 to derive the key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,  # Adjust the number of iterations based on your security requirements
            salt=salt,
            length=32  # The length of the derived key in bytes
        )
            
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def set_masterpassword(self,__password):
        self.__master_password = __password

    def login_system(self,__master_password):
        loging_pass_hashed = self.hash_data(__master_password,salt=__master_password)

        Key_File = open("E:/Documents/Project/AMI_python_sec2/final project/PasswordManager/data/.key" , "rb")
        encpt_Key = Key_File.read()
        Key_File.close()

        try:
            login_fernet = Fernet(loging_pass_hashed) 
            decpt_key = login_fernet.decrypt(encpt_Key)
            if(loging_pass_hashed == decpt_key):
                self.__auth = True
                self.set_masterpassword(__master_password)
                pm_screen.clear()
            else:
                self.__auth = False
        except:
            pm_screen.clear()
            print("Incorect password")
            

    def login_sucess(self):
        return self.__auth

    def load_key(self):
        Key_File = open("E:/Documents/Project/AMI_python_sec2/final project/PasswordManager/data/.key" , "rb")
        encpt_key = Key_File.read()
        Key_File.close()

        fernet_decpt_key = self.hash_data(self.__master_password,salt=self.__master_password)

        decpt_fernet = Fernet(fernet_decpt_key)
        decpt_key = decpt_fernet.decrypt(encpt_key).decode()
        self.fernet = Fernet(decpt_key) 

    def write_encrypt_data(self,_src):
        encrypt_file = open("E:/Documents/Project/AMI_python_sec2/final project/PasswordManager/data/.encrypt_data" , "wb") 
        encrypt_file.write(self.fernet.encrypt(_src.encode()))
        encrypt_file.close()

    def decrypt_data(self):
        encrypt_file = open("E:/Documents/Project/AMI_python_sec2/final project/PasswordManager/data/.encrypt_data" , "rb") 
        encrypt_data = encrypt_file.read()
        encrypt_file.close()
        return self.fernet.decrypt(encrypt_data).decode()

    def load_data(self):
        src = self.decrypt_data()
        self.__data = json.loads(src)
        return json.loads(src)
    
    def filter_data(self,filter_word):
        self.load_data()
        if filter_word in self.__data:
            return self.__data[str(filter_word)]
        else:
            return "404"

    def update_data(self,title = None, username = None , password = None , old_title = None):
        if(title is not None):
            if(title in self.__data):
                pm_screen.titleexist()
            else:
                self.__data[title] = self.__data.pop(old_title)
                self.save_data()
        elif(username is not None):
                self.add_data(title=old_title,username=username,password=password)
        else:
                self.add_data(title=old_title,username=username,password=password)

    def add_data(self,title,username,password):
        if(title in self.__data):
            pm_screen.titleexist()
        else:
            tmp_data = {title : {"username" : username,"password": password }}
            self.__data.update(tmp_data)
            self.save_data()
    
    def delete_data(self,__target):
        del self.__data[__target]
        self.save_data()

    def save_data(self):
        final_data = str(self.__data).replace("\'", "\"")
        self.write_encrypt_data(final_data)

    def list_titles(self):
        return [key for key , __ in self.__data.items()]
    
    def edit_data(self,_title,_key):
        match _key:
            case "1":
                print("Enter new title: ",end="")
                user_input = input()
                if(user_input in self.__data):
                    pm_screen.titleexist()
                else:
                    self.__data[user_input] = self.__data.pop(_title)
            case "2":
                print("Enter new username: ",end="")
                user_input = input()
                self.__data[_title]["username"] = user_input
            case "3":
                print("Enter new password: ",end="")
                user_input = input()
                self.__data[_title]["password"] = user_input
            case _: 
                pm_screen.error_print()
        self.save_data()

class passsword_manager_print:
    newline = "\n"
    separator = newline+'-' * 100 + newline
    def titleexist(self):
        print("Title already exists")
    def clear(self):
        os.system("cls")
    def waituntilpress(self):
        print("\nPress any key to continue....")
        input()
    def error_print(self):
        text= f"{'-'*40}\nUnknow operation, Please try again!!\n{'-'*40}\n"
        print(text,end="")

    def firstsetup_print(self):
        print(f"Not detecting any data folder")
        print(f"Setup require files")

    def master_login_print(self):
        print(f"Please Enter Master Password: ",end="")

    def main_menu(self):
        # Print Main Menu Text
        menu_options = [
            "1. Get    Username and Password",
            "2. Add    Username and Password",
            "3. Edit   Username and Password",
            "4. Delete Username and Password",
            "5. Exit Program"
        ]
        welcome_text = "Welcome to my password manager"
        menu_options_text = ""
        for i in menu_options[:-1]:
            menu_options_text += i + self.newline
        menu_options_text += menu_options[-1]

        text = f"{self.separator}{welcome_text}{self.separator}{menu_options_text}{self.separator}"

        print(text)
    
    def search_print(self):
        text= f"Enter program/website name: "
        print(text, end="")

    def get_menu(self):
        self.search_print()
        
    def add_menu(self):
        pass

    def edit_menu(self,sel_title,data):
        print(self.separator)
        print(f"1) Title: {sel_title}")
        print(f"2) Username: {data["username"]}")
        print(f"3) Password: {data["password"]}")
        print(self.separator)
        print(f"Please enter 1-3 to select: " , end="")
    
    def delete_menu(self):
        self.search_print()

    def title_print(self,_src):
        padding = 20
        header = "*** Available title ***"
        title_text = ""
        for index,value in enumerate(_src, start=1):
            if(index % 4 == 0):
                title_text += f"- {value:<{padding}} \n"
            else:
                title_text += f"- {value:<{padding}}"
        text = f"{self.separator}{header}{self.separator}{title_text}{self.separator}"
        print(text)

def main():
    if(pm_system.is_newuser()):
            pm_screen.firstsetup_print()
            pm_system.setup_newuser()
    else:
        running = True
        while(running):
            if(not(pm_system.login_sucess())):
                entered_password = getpass("Master Password: ")
                pm_system.login_system(entered_password)
            else:
                pm_system.load_key()
                pm_system.load_data()
                pm_screen.main_menu()
                user_input = input("Enter 1-5 to select: ")
                pm_screen.clear()
                match user_input:
                    case "1":
                        title = pm_system.list_titles()
                        pm_screen.title_print(title)
                        pm_screen.get_menu()
                        data = pm_system.filter_data(input(""))
                        if (data == "404"):
                            print("not found")
                        else:
                            print(f"Username: {data["username"]}")
                            print(f"Password: {data["password"]}")
                        pm_screen.waituntilpress()
                    case "2":
                        title = pm_system.list_titles()
                        pm_screen.title_print(title)
                        title = input("Enter new title: ")
                        username = input("Enter new username: ")
                        password = input("Enter new pasword: ")
                        pm_system.add_data(title,username,password)
                        pm_screen.waituntilpress()
                    case "3":
                        title = pm_system.list_titles()
                        pm_screen.title_print(title)
                        pm_screen.search_print()
                        sel_title = input("")
                        data = pm_system.filter_data(sel_title)
                        if (data == "404"):
                            print("not found")
                        else:
                            pm_screen.edit_menu(sel_title,data)
                            sel_n = input()
                            pm_system.edit_data(sel_title,sel_n)
                        pm_screen.waituntilpress()
                    case "4":
                        title = pm_system.list_titles()
                        pm_screen.title_print(title)
                        pm_screen.delete_menu()
                        target = input("")
                        data = pm_system.filter_data(target)
                        if (data == "404"):
                            print("not found")
                        else:
                            print(f"Are you sure to delete this account(y/n default: no): ",end="")
                            ans = input().lower()
                            if(ans in ["yes","y"]):
                                print("Deleting Account")
                                pm_system.delete_data(target)
                            else:
                                print("Delete cancled")
                        pm_screen.waituntilpress()
                    case "5":
                        running = False
                    case _  : 
                        pm_screen.error_print()
                        input("Please any key to continue")
                pm_screen.clear()
        
        print("Exiting Program......",end="")
        time.sleep(1)
        pm_screen.clear()

data_folder = "E:/Documents/Project/AMI_python_sec2/final project/PasswordManager/data"
if __name__ == "__main__":
    pm_screen = passsword_manager_print()
    pm_system = password_manager_system()
    main() 