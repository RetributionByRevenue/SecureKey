from kivy.app import App
from androidtoast import toast
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.image import Image
from kivy.uix.scrollview import ScrollView
from kivy.core.clipboard import Clipboard
from kivy.uix.popup import Popup
from kivy.utils import platform
import os
from datetime import datetime,timezone
import bcrypt
import pysos
import json

#######################
####ENCRYPT/DECRYPT####
import base64
import binascii
import hmac
import time
import os
import struct
from pyaes import AESModeOfOperationCBC, Encrypter, Decrypter

__all__ = [
    "InvalidSignature",
    "InvalidToken",
    "Fernet"
]
_MAX_CLOCK_SKEW = 60


class InvalidToken(Exception):
    pass


class InvalidSignature(Exception):
    pass


log = []

class Fernet:
    """
    Pure python Fernet module
    see https://github.com/fernet/spec/blob/master/Spec.md
    """
    def __init__(self, key):
        if not isinstance(key, bytes):
            self._log_error("init function - raise #1 - key must be bytes")
            raise TypeError("key must be bytes.")

        try:
            key = base64.urlsafe_b64decode(key)
        except Exception as e:
            self._log_error(f"init function - raise #2 - {str(e)}")
            raise ValueError("Invalid base64-encoded key.")

        if len(key) != 32:
            self._log_error("init function - raise #3 - Fernet key must be 32 url-safe base64-encoded bytes.")
            raise ValueError("Fernet key must be 32 url-safe base64-encoded bytes.")

        self._signing_key = key[:16]
        self._encryption_key = key[16:]

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        try:
            encrypter = Encrypter(AESModeOfOperationCBC(self._encryption_key, iv))
            ciphertext = encrypter.feed(data)
            ciphertext += encrypter.feed()
        except Exception as e:
            self._log_error(f"_encrypt_from_parts function - raise #1 - {str(e)}")
            raise

        basic_parts = (b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext)

        hmactext = hmac.new(self._signing_key, digestmod='sha256')
        hmactext.update(basic_parts)

        return base64.urlsafe_b64encode(basic_parts + hmactext.digest())

    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            self._log_error("decrypt function - raise #1 - token must be bytes")
            raise TypeError("token must be bytes.")

        current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error) as e:
            self._log_error(f"decrypt function - raise #2 - {str(e)}")
            raise InvalidToken("Invalid base64-encoded token.")

        if not data or data[0] != 0x80:
            self._log_error("decrypt function - raise #3 - Invalid token header")
            raise InvalidToken("Invalid token header.")

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error as e:
            self._log_error(f"decrypt function - raise #4 - {str(e)}")
            raise InvalidToken("Invalid token timestamp.")

        if ttl is not None:
            if timestamp + ttl < current_time:
                self._log_error("decrypt function - raise #5 - Token expired")
                raise InvalidToken("Token expired.")

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                self._log_error("decrypt function - raise #6 - Token from the future")
                raise InvalidToken("Token from the future.")

        hmactext = hmac.new(self._signing_key, digestmod='sha256')
        hmactext.update(data[:-32])
        if not hmac.compare_digest(hmactext.digest(), data[-32:]):
            self._log_error("decrypt function - raise #7 - HMAC check failed")
            raise InvalidToken("HMAC check failed.")

        iv = data[9:25]
        ciphertext = data[25:-32]
        try:
            decryptor = Decrypter(AESModeOfOperationCBC(self._encryption_key, iv))
            plaintext = decryptor.feed(ciphertext)
            plaintext += decryptor.feed()
        except ValueError as e:
            self._log_error(f"decrypt function - raise #8 - {str(e)}")
            raise InvalidToken("Decryption failed.")

        return plaintext

    @staticmethod
    def _log_error(error_message):
        """
        Log an error message if it's not already in the global log.
        """
        global log
        if error_message not in log:
            log.append(error_message)
            
def generate_fernet_key_from_password(password):
    """
    Convert a password of any length into a valid Fernet key.
    Uses padding or truncation to ensure 32 bytes before base64 encoding.
    """
    password_bytes = password.encode()
    
    # If password is too short, pad it with repeating pattern
    if len(password_bytes) < 32:
        # Calculate how many times to repeat the password
        multiplier = (32 // len(password_bytes)) + 1
        password_bytes = password_bytes * multiplier
    
    # Take exactly 32 bytes
    password_bytes = password_bytes[:32]
    
    return base64.urlsafe_b64encode(password_bytes)

def encrypt_message(encryption_key, message):
    """Encrypt a message using the given encryption key."""
    fernet_key = generate_fernet_key_from_password(encryption_key)
    fernet = Fernet(fernet_key)
    return (fernet.encrypt(message.encode())).decode()

def decrypt_message(encryption_key, encrypted_message):
    nl='''
'''
    """Decrypt a message using the given encryption key."""
    #global aes_key
    #aes_key = encryption_key+"__"+encrypted_message[:5]+"..."+encrypted_message[-5:]
    if 'str' in str(type(encrypted_message)):
        encrypted_message = encrypted_message.encode()
    try:
        #global log

        #log.append(f"Decrypting with key: {encryption_key}")
        #log.append((f"encrypted message: {encrypted_message}"))
        fernet_key = generate_fernet_key_from_password(encryption_key)
        #log.append((f"fernet key: {fernet_key}"))
        fernet = Fernet(fernet_key)
        #log.append(f"fernet instance: {fernet}")
        decrypted_message = fernet.decrypt(encrypted_message)
        #log.append(f"decrypt message: {decrypted_message}")
        return decrypted_message.decode()
    except Exception as e:
        #return str(e)+nl+str(log)
        return "invalid key"
#######################
#######################

# Global variables
aes_key = ""
counter = 0

class PasswordScreen(Screen):
    # [Previous PasswordScreen code remains the same]
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        self.label = Label(text="Enter numeric password")
        self.text_input = TextInput(password=True, multiline=False, hint_text="Password", input_filter="int")
        self.submit_button = Button(text="Submit", on_press=self.validate_password)

        layout.add_widget(self.label)
        layout.add_widget(self.text_input)
        layout.add_widget(self.submit_button)
        self.add_widget(layout)

        self.hashed_password = "$2a$10$0yppMCWyL19gZwTIi5Hm1OdbttdkEHSglxk5yJ3KINHhlHGtsANXm"

    def validate_password(self, instance):
        password = self.text_input.text.encode()
        if bcrypt.checkpw(password, self.hashed_password.encode()):
            self.manager.current = "fetch_aes_key"
        else:
            self.label.text = "Incorrect password. Try again."

class FetchAESKeyScreen(Screen):
    # [Previous FetchAESKeyScreen code remains the same]
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        self.label = Label(text="Enter AES Key")
        self.text_input = TextInput(password=False, multiline=False, hint_text="AES Key")
        self.submit_button = Button(text="Submit", on_press=self.store_aes_key)

        layout.add_widget(self.label)
        layout.add_widget(self.text_input)
        layout.add_widget(self.submit_button)
        self.add_widget(layout)

    def store_aes_key(self, instance):
        global aes_key
        aes_key = self.text_input.text
        self.manager.current = "protected"

class ProtectedContentScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Get the export directory path
        if platform == 'android':
            self.storage_path = os.getenv('EXTERNAL_STORAGE') or '/storage/emulated/0'
            self.export_dir = os.path.join(self.storage_path, 'Documents')
        else:
            self.export_dir = os.path.expanduser('~')
            
        # Rest of __init__ remains the same
        self.messages = []
        self.main_layout = BoxLayout(orientation='vertical')
        
        # Top bar with menu and back button
        top_bar = BoxLayout(orientation='horizontal', size_hint_y=None, height=100)
        banner_bar = BoxLayout(orientation='vertical', padding=20, spacing=10, size_hint_y=None, height=400)
        menu_button = Button(text="Menu", size_hint_x=0.5, on_press=self.show_menu_popup)
        back_button = Button(text="Back", size_hint_x=0.5, on_press=self.go_back)
        
        top_bar.add_widget(menu_button)
        top_bar.add_widget(back_button)
        
        # Content layout
        self.content_layout = BoxLayout(orientation='vertical', padding=20, spacing=10, size_hint_y=None)
        self.content_layout.bind(minimum_height=self.content_layout.setter('height'))
        
        label = Label(text="Encrypt/Decrypt Keys", font_size='20sp', size_hint_y=None, height=50)
        image = Image(source="data/legal_icons/pepehacker.png", size_hint_y=None, height=200)
        
        # AES button layout
        aesbutton_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=90, padding=10)
        global aes_key
        aescopy_button = Button(text="View AES Key", size_hint_x=0.5,
                              on_press=lambda instance: toast(aes_key, True, 80, 200, 0))
        aesbutton_layout.add_widget(aescopy_button)

        # Add initial widgets to content layout
        banner_bar.add_widget(label)
        banner_bar.add_widget(image)
        banner_bar.add_widget(aesbutton_layout)
        
        # Add default message
        #self.add_message_to_ui("Copy Me")

        # Scroll view for content
        self.scroll_view = ScrollView()
        self.scroll_view.add_widget(self.content_layout)
        
        # Add everything to main layout
        self.main_layout.add_widget(top_bar)
        self.main_layout.add_widget(banner_bar)
        self.main_layout.add_widget(self.scroll_view)
        
        self.add_widget(self.main_layout)

    def get_available_files(self):
        """Get list of available export files"""
        try:
            os.makedirs(self.export_dir, exist_ok=True)
            files = [f for f in os.listdir(self.export_dir)]
            return sorted(files, reverse=True)  # Most recent first
        except Exception as e:
            toast(f'Error listing files: {str(e)}', True, 80, 200, 0)
            return []

    def read_file_content(self, filename):
        """Read and return the content of a file"""
        try:
            filepath = os.path.join(self.export_dir, filename)
            db = pysos.Dict(filepath)
            return db
        except Exception as e:
            toast(f'Error reading file: {str(e)}', True, 80, 200, 0)
            return None

    def show_file_selection_popup(self, *args):
    
        storage_path = os.getenv('EXTERNAL_STORAGE') or '/storage/emulated/0'
        export_dir = os.path.join(storage_path, 'Documents')
        
        files = os.listdir(export_dir)
        files = [i for i in files if ".trashed-" not in i]
        
        #Clipboard.copy(str(files))
        if not files:
            toast('No exported files found', True, 80, 200, 0)
            return
            
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)
        
        # Create scrollable layout for file buttons
        scroll_layout = BoxLayout(orientation='vertical', spacing=5, size_hint_y=None)
        scroll_layout.bind(minimum_height=scroll_layout.setter('height'))
        
        # Create the popup first so we can reference it in the button callbacks
        popup = Popup(title='Select File to Import',
                     size_hint=(0.8, 0.8))
        
        # Add a button for each file
        for filename in files:
            # Create a function that will read this specific file
            def make_reader(fname):
                self.content_layout.clear_widgets()
                global counter
                counter = 0
                def read_this_file(instance):
                    content = self.read_file_content(fname) #returns dict or None
                    if content is not None:
                        for i in content.keys():
                                #print(i, db[i])
                            self.add_message_to_ui(   decrypt_message(aes_key, content[i] )  )
                        toast(f'Restored DB', True, 80, 200, 0)
                    else:
                        toast(f'File is not a readable database, or empty database.', True, 80, 200, 0)
                    popup.dismiss()
                return read_this_file
            
            btn = Button(text=filename, 
                        size_hint_y=None, 
                        height=40)
            btn.bind(on_press=make_reader(filename))
            scroll_layout.add_widget(btn)
        
        # Create ScrollView for buttons
        scroll = ScrollView(size_hint=(1, 1))
        scroll.add_widget(scroll_layout)
        
        # Add close button
        close_button = Button(text='Close', 
                            size_hint_y=None, 
                            height=40)
        close_button.bind(on_press=popup.dismiss)
        
        # Add widgets to content
        content.add_widget(scroll)
        content.add_widget(close_button)
        
        # Set popup content and open
        popup.content = content
        popup.open()


    def show_menu_popup(self, instance):
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)
        
        import_btn = Button(text='Import', size_hint_y=None, height=50)
        export_btn = Button(text='Export', size_hint_y=None, height=50)
        add_new_btn = Button(text='Add New', size_hint_y=None, height=50)
        clear_btn = Button(text='Clear Screen', size_hint_y=None, height=50)
        
        # Bind buttons to their functions
        add_new_btn.bind(on_press=self.show_add_message_popup)
        export_btn.bind(on_press=self.show_export_popup)
        import_btn.bind(on_press=self.show_file_selection_popup)  # Add this line
        clear_btn.bind(on_press= self.clear_screen )

        content.add_widget(import_btn)
        content.add_widget(export_btn)
        content.add_widget(add_new_btn)
        content.add_widget(clear_btn)
        
        popup = Popup(title='Menu',
                     content=content,
                     size_hint=(0.8, 0.4))
        
        # Bind the buttons to close the menu popup
        import_btn.bind(on_press=popup.dismiss)
        export_btn.bind(on_press=popup.dismiss)
        add_new_btn.bind(on_press=popup.dismiss)
        clear_btn.bind(on_press=popup.dismiss)
        
        popup.open()

    def add_message_to_ui(self, message):
        """Add a new message with copy button to the UI"""
        button_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=50, padding=10)
        button_label = Label(text=message, size_hint_x=0.5)
        global counter
        counter = counter + 1
        button_label.id = counter 
        
        copy_button = Button(text="Copy", size_hint_x=0.25,
                            on_press=lambda instance: Clipboard.copy(button_label.text))
        
        # Create remove button that references its parent layout
        rm_button = Button(text="Remove", size_hint_x=0.25,
                          on_press=lambda instance: self.content_layout.remove_widget(button_layout))
        
        button_layout.add_widget(button_label)
        button_layout.add_widget(copy_button)
        button_layout.add_widget(rm_button)
        
        self.content_layout.add_widget(button_layout)
        self.messages.append(message)
        

    def show_add_message_popup(self, *args):
        """Show popup for adding a new message"""
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)
        
        text_input = TextInput(multiline=False, hint_text="Enter your message")
        
        # Create OK button that will add the message
        def add_message(instance):
            message = text_input.text
            if message.strip():  # Only add non-empty messages
                self.add_message_to_ui(message)
            popup.dismiss()
            
        ok_button = Button(text='OK', size_hint_y=None, height=40)
        ok_button.bind(on_press=add_message)
        
        content.add_widget(text_input)
        content.add_widget(ok_button)
        
        popup = Popup(title='Add New Message',
                     content=content,
                     size_hint=(0.8, 0.2))
        popup.open()

    def export_message(self, popup):
        """Export message to a file on the device"""
        try:
            if platform == 'android':
                # Get the external storage directory on Android
                storage_path = os.getenv('EXTERNAL_STORAGE') or '/storage/emulated/0'
                export_dir = os.path.join(storage_path, 'Documents')
            else:
                # Fallback for non-Android platforms
                export_dir = os.path.expanduser('~')

            # Create Documents directory if it doesn't exist
            os.makedirs(export_dir, exist_ok=True)

            # Generate filename with timestamp
            timestamp = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
            filename = f'{timestamp}.db'
            filepath = os.path.join(export_dir, filename)
            data = self.show_widgets()
            if data == '{}' or aes_key == "":
                toast('err: no items to export or no aes-key defined', True, 80, 200, 0)
            else:
                #toast('not empty', True, 80, 200, 0)
                data = json.loads(data)
                for i in data:
                    db = pysos.Dict(filepath)
                    db[i] = encrypt_message(aes_key, data[i])
                toast(f'Exported to {filepath}', True, 80, 200, 0)
            popup.dismiss()

        except Exception as e:
            # Show error message
            toast(f'Export failed: {str(e)}', True, 80, 200, 0)
            popup.dismiss()

    def show_export_popup(self, *args):
        """Show popup for exporting a message"""
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)

        # Create export button
        export_button = Button(text='Confirm Export', size_hint_y=None, height=40)
        
        content.add_widget(export_button)
        
        popup = Popup(title='Export Message',
                     content=content,
                     size_hint=(0.8, 0.2))
        
        # Bind the export button to the export function
        export_button.bind(on_press=lambda x: self.export_message(popup))
        
        popup.open()


    def show_widgets(self):
        """Display all widgets with an ID and their text property as a JSON structure"""
        def get_widget_info(widget):
            """Recursively collect widgets with ID and their text property"""
            widget_data = {}
            
            # Check if the widget has an id
            if hasattr(widget, 'id') and widget.id:
                # Retrieve the widget's text property if applicable
                text = getattr(widget, 'text', None)
                widget_data[widget.id] = text if text else ""

            # If the widget has children, traverse them
            if hasattr(widget, 'children'):
                for child in widget.children:
                    widget_data.update(get_widget_info(child))
            
            return widget_data
            
        def reverse_dict(input_dict):
            """Reverse the order of key-value pairs in a dictionary."""
            return {k: v for k, v in reversed(input_dict.items())}

        # Start with the root widget
        widget_json = get_widget_info(self)
        
        widget_json = reverse_dict(widget_json)
        

        # Convert the collected data to JSON
        json_output = json.dumps(widget_json, indent=4)
        return json_output

    def clear_screen(self, instance):
        global counter
        counter = 0
        self.content_layout.clear_widgets()
        

    def go_back(self, instance):
        self.manager.current = "fetch_aes_key"
        


class PasswordApp(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(PasswordScreen(name="password"))
        sm.add_widget(FetchAESKeyScreen(name="fetch_aes_key"))
        sm.add_widget(ProtectedContentScreen(name="protected"))
        return sm

if __name__ == "__main__":
    PasswordApp().run()
    
    
