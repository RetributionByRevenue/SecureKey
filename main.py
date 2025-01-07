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
from CustomModules import CustomGraphics
import os
from datetime import datetime,timezone
import bcrypt
import pysos
import json
from fernet_utils import encrypt_message, decrypt_message, Fernet, generate_fernet_key_from_password
from androidstorage4kivy import SharedStorage, Chooser
from android.permissions import request_permissions, Permission

# Global variables
aes_key = ""
counter = 0
item = ""

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
            
        request_permissions([
            Permission.READ_EXTERNAL_STORAGE,
            Permission.WRITE_EXTERNAL_STORAGE
        ])
            
            
        # Rest of __init__ remains the same
        self.messages = []
        self.main_layout = BoxLayout(orientation='vertical')
        self.selected_path = None
        
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

############################################################################################################

    def show_file_selection_popup(self, *args):
        # Define the chooser callback function
        def chooser_callback(uri_list):
            try:
                for uri in uri_list:
                    # Copy file from shared storage to private storage
                    selected_path = SharedStorage().copy_from_shared(uri) #can only open .txt files
                    
                    # Read the file contents
                    with open(selected_path, 'r') as file:
                        file_contents = file.read()
                    
                    with open(selected_path, 'w') as file:
                        file.write(file_contents)
                    global item
                    item = selected_path
                    toast('File Selected, press Confirm to continue.', True, 80, 200, 0)
                       
            except Exception as e:
                toast(f'Error in callback: {str(e)}', True, 80, 200, 0)

        # Define the open_and_decrypt function
        def open_and_decrypt(instance):
            try:
                global item
                if 'item' in globals() and item:
                    global counter
                    counter = 0
                    self.content_layout.clear_widgets()
                    
                    db = pysos.Dict(item)
                    Clipboard.copy(item + str(db.keys))
                    for i in db.keys():
                        self.add_message_to_ui(decrypt_message(aes_key, db[i]))
                    
                    # Clean up the temporary file
                    if os.path.exists(item):
                        os.remove(item)
                    # Dismiss the popup after successful operation
                    popup.dismiss()
                else:
                    toast('No file selected. Please load a file first.', True, 80, 200, 0)
            except Exception as e:
                toast(f'Error: {str(e)}', True, 80, 200, 0)

        # Create the main content layout for the popup
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)
        
        # Create a scrollable layout for file buttons
        scroll_layout = BoxLayout(orientation='vertical', spacing=5, size_hint_y=None)
        scroll_layout.bind(minimum_height=scroll_layout.setter('height'))
        
        # Create a ScrollView for the file buttons
        scroll = ScrollView(size_hint=(1, 1))
        scroll.add_widget(scroll_layout)
        
        # Create the popup so it can be referenced in button callbacks
        popup = Popup(
            title="Select File to Import",
            size_hint=(0.8, 0.8),
        )
        
        # Create the "Load" button
        load_button = Button(text="Select", size_hint_y=None, height=40)
        load_button.bind(on_press=lambda instance: Chooser(chooser_callback).choose_content("text/*"))
        
        # Create the "Confirm" button
        confirm_button = Button(text="Confirm", size_hint_y=None, height=40)
        confirm_button.bind(on_press=open_and_decrypt)
        
        # Add widgets to the main content layout
        content.add_widget(scroll)
        content.add_widget(load_button)
        content.add_widget(confirm_button)
        
        # Set the popup's content and open it
        popup.content = content
        popup.open()



############################################################################################################


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
        # Create main layout that will resize based on content
        button_layout = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            padding=10
        )
        
        # Create label with text wrapping enabled
        button_label = Label(
            text=message,
            size_hint_x=0.5,
            text_size=(None, None),  # Will be set in bind
            halign='left',
            valign='middle',
            padding=(10, 10),
            markup=True,
            shorten=False,
        )
        
        # Allow the label to wrap text
        button_label.bind(
            width=lambda *x: setattr(button_label, 'text_size', (button_label.width, None)),
            texture_size=lambda *x: setattr(button_label, 'height', button_label.texture_size[1])
        )
        
        # Bind the layout's height to the label's height
        button_label.bind(
            height=lambda *x: setattr(button_layout, 'height', button_label.height + 20)
        )
        
        global counter
        counter = counter + 1
        button_label.id = counter
        
        copy_button = Button(
            text="Copy",
            size_hint_x=0.25,
            size_hint_y=None,
            height=50,
            on_press=lambda instance: Clipboard.copy(button_label.text)
        )
        
        rm_button = Button(
            text="Remove",
            size_hint_x=0.25,
            size_hint_y=None,
            height=50,
            on_press=lambda instance: self.content_layout.remove_widget(button_layout)
        )
        CustomGraphics.SetBG(button_layout, bg_color=[0, 0, 0.5, 1])
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
            filename = f'{timestamp}_encrypt_db.txt'
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
