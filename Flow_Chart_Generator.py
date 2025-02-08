import pyshark
import sys
import os
import subprocess
from io import StringIO
import ipaddress
import glob
import tkinter as tk
from tkinter import filedialog, messagebox,ttk
import webbrowser
import re
import datetime
import windnd
global folder_path,pcap_file_path,line_dict,chart_editing,ISUP_message_dict,MAP_message_dict,html_entities,html_entities_short,from_argv,ip_hostname_map
chart_editing=False
from_argv=False




def assign_color(input_string, assignments, colors):
    if input_string not in assignments:
        assignments[input_string] = colors[len(assignments) % len(colors)]

    return assignments[input_string]

def remove_duplicates(input_list):
    return list(dict.fromkeys(input_list))

def replace_special_chars(text):
    global html_entities


    for key, value in html_entities.items():
        if key in text:
            text=text.replace(key,value)
    return text

def revert_special_chars(text):
    global html_entities


    for key, value in html_entities.items():
        if value in text:
            text=text.replace(value,key).replace("&quot;",'"')
    return text

def split_into_two(s, separator):
    parts = s.split(separator, 1)
    if len(parts) == 1:  # If the separator was not found
        parts.append('')  # Append an empty string
    return parts

def extract_nodes(text, separator='-->'):
    # Pattern to match words with characters and underscore but must contain at least one letter
    word_pattern = r'\w*[a-zA-Z]+\w*'
    
    # Split text into lines
    lines = text.split('\n')
    # Initialize node lists
    Node_A = []
    Node_B = []
    Message_label =[]
    Protocol=[]
    for line in lines:
        # Split line into nodes based on separator
        nodes = [node.strip() for node in line.split(separator)]
        # Ignore lines with less than 2 nodes
        if len(nodes) < 2: continue
        
        # For each node, check if it contains a valid word
        valid_nodes = [re.search(word_pattern, node) is not None for node in nodes]
        
        # First node is appended to Node_A if it contains a valid word
        if valid_nodes[0]:
            trail=replace_special_chars(nodes[0]).strip()
            A,garbage=split_into_two(trail, ':')
            Node_A.append(A.strip().replace(' ','_'))
        
        # For all middle nodes (if they exist), they are appended as is if they contain a valid word
        for node, is_valid in zip(nodes[1:-1], valid_nodes[1:-1]):
            if is_valid:
                trail=replace_special_chars(node).strip()
                B,label=split_into_two(trail, ':')
                protocol,label=split_into_two(label, ':')
                if not label:
                    label=protocol
                    protocol=''
                if B:
                    Node_B.append(B.strip().replace(' ','_'))
                    Node_A.append(B.strip().replace(' ','_'))
                    Message_label.append(label.strip())
                    Protocol.append(protocol.strip())
        # Last node is appended to Node_B if it contains a valid word
        if valid_nodes[-1]:
            trail=replace_special_chars(nodes[-1]).strip()
            B,label=split_into_two(trail, ':')
            protocol,label=split_into_two(label, ':')
            if not label:
                label=protocol
                protocol=''            
            Node_B.append(B.strip().replace(' ','_'))
            Message_label.append(label.strip())
            Protocol.append(protocol.strip())

    Node_A, Node_B,Message_label,Protocol = zip(*[(item1, item2,item3,item4) for item1, item2,item3,item4 in zip(Node_A, Node_B,Message_label,Protocol) if item1 and item2])
    Node_A=list(Node_A)
    Node_B=list(Node_B)
    Message_label=list(Message_label)
    Protocol=list(Protocol)

            
    return Node_A, Node_B,Message_label,Protocol

def revert_special_chars(text):
    global html_entities_short


    for key, value in html_entities_short.items():
        if value in text:
            text=text.replace(value,key).replace("&quot;",'"')
    return text


def replace_special_chars_short(text):
    global html_entities_short

    result = []

    for key, value in html_entities_short.items():
        if key in text:
            text=text.replace(key,value)
    return text

def summarise(text):
    try:
        output=[]
        lines = text.split('\n')
        for line in lines:
            if 'SIP ' not in line and 'Part:' not in line and 'Not supported' not in line and 'Not set' not in line and 'Vendor-Specific' not in line  and 'Mandatory' not in line  and 'Padding' not in line  and 'AVP Length' not in line and 'AVP Code:' not in line and 'Vendor-Id:' not in line and 'Country Code:' not in line and 'URI parameter:' not in line and 'Host Port:' not in line and 'VendorId:' not in line and ' Userinfo:' not in line and 'E.164 number (MSISDN):' not in line and ' URI:' not in line and 'AVP Vendor Id:' not in line:
                line=replace_special_chars_short(line)
                output.append(line)
        return '\n'.join(output)
    except:
        return ''
    
    

def text_to_html(text):
    lines = text.split('\n')
    html_lines = []

    for line in lines:
        if 'SIP ' not in line and 'Part:' not in line and 'Not supported' not in line and 'Not set' not in line and 'Vendor-Specific' not in line  and 'Mandatory' not in line  and 'Padding' not in line  and 'AVP Length' not in line and 'AVP Code:' not in line and 'Vendor-Id:' not in line and 'Country Code:' not in line and 'URI parameter:' not in line and 'Host Port:' not in line and 'VendorId:' not in line and ' Userinfo:' not in line and 'E.164 number (MSISDN):' not in line and ' URI:' not in line and 'AVP Vendor Id:' not in line:
            line=replace_special_chars_short(line)
            if '==&gt;' in line:
                html_line = f'<p class="separator" style="font-weight:bold;font-family:Courier New;">{line}</p>'
            elif 'Message Body' in line:
                html_line = f'<p style="font-weight:bold;font-family:Courier New;">{line}</p>'                
            elif 'Command Code' in line or '-Line' in line:
                html_line = re.sub(r'(\w+:)(.*)', r'\1<span style="color:blue;font-weight:bold;">\2</span>', line)
                html_line = f'<p style="font-family:Courier New;">{html_line}</p>'            
            elif re.search(r'\w+:', line):
                html_line = re.sub(r'(\w+:)(.*)', r'\1<span style="color:blue;">\2</span>', line)
                html_line = f'<p style="font-family:Courier New;">{html_line}</p>'
            elif '----' in line:
                html_line = f'<p class="separator" style="font-weight:bold;color:green;font-family:Courier New;">{line}</p>'
            else:
                html_line = f'<p style="font-family:Courier New;">{line}</p>'
            
            html_lines.append(html_line)

    html_content = ''.join(html_lines)
    html = f'<html>\n<head>\n<meta charset="utf-8" content="width=device-width, initial-scale=1.0">\n</head>\n<body>\n{html_content}\n</body>\n</html>'
    html=html.replace('</head>','<style>\np{\nline-height:1;\nmargin:0;\npadding:0;\n}\n.separator{\nmargin-top:10px;\nmargin-bottom:10px;\n}\n</style></head>')

    return html

global filter_str

thisdict = {
  "1": "R",
  "0": "A"
}

line_dict={
    "solid-Unidirectionnel":"=>",
    "dotted-Unidirectionnel":">>",
    "solid-bidirectionnel":"<=>",
    "dotted-bidirectionnel":"<<>>",
    "solid-no-arrow":"--",
    "dotted-no-arrow":"..",
    "rounded-box":"rbox"}

diam_code={
"265": "AA",
"268": "DE",
"274": "AS",
"271": "AC",
"272": "CC",
"257": "CE",
"280": "DW",
"282": "DP",
"258": "RA",
"275": "ST",
"283": "UA",
"284": "SA",
"285": "LI",
"286": "MA",
"287": "RT",
"288": "PP",
"300": "UA",
"301": "SA",
"302": "LI",
"303": "MA",
"304": "RT",
"305": "PP",
"306": "UD",
"307": "PU",
"308": "SN",
"309": "PN",
"310": "BI",
"311": "MP",
"316": "UL",
"317": "CL",
"318": "AI",
"319": "ID",
"320": "DS",
"321": "PE",
"8388620": "PL",
"8388622": "RI",
"260": "AM",
"262": "HA",
"8388718": "CI",
"8388719": "RI",
"8388726": "NI"
}

ISUP_message_dict = {
    "1": "IAM",
    "2": "SAM",
    "3": "INR",
    "4": "INF",
    "5": "COT",
    "6": "ACM",
    "7": "CON",
    "8": "FOT",
    "9": "ANM",
    "B": "REL",
    "C": "SUS",
    "D": "RES",
"E":	"RES",
"10":	"RLC",
"11":	"CCR",
"12":	"RSC",
"13":	"BLO",
"14":	"UBL",
"15":	"BLA",
"16":	"UBA",
"1C":	"CMR",
"1D":	"CMC",
"1F":	"FRJ",
"20":	"FAA",
"21":	"FAR",
"2C":	"CPG",
"2D":	"USR"
}

MAP_message_dict = {
    1: "sendAuthenticationInfo",
    2: "updateLocation",
    3: "cancelLocation",
    4: "provideRoamingNumber",
    5:"noteSubscriberDataModified",
    7:"insertSubscriberData",
    8:"deleteSubscriberData",
    9:"sendParameters",
    10:"registerSS",
    12:"activateSS",
    16: "insertSubscriberData",
    17: "deleteSubscriberData",
    18: "getPassword",
    19: "registerSS",
    20: "eraseSS",
    21: "activateSS",
    22: "sendRoutingInfo",
    23: "updateGprsLocation ",
    24: "authenticationFailureReport",
    27: "registerPassword",
    28: "getPassword",
    29: "updateGprsLocation",
    30: "sendRoutingInfoForGprs",
    31: "failureReport",
    32: "noteMsPresentForGprs",
    34: "sendAuthenticationInfo",
    37:"reset",
    38:"forwardCheckSS-Indication",
    43:"checkIMEI",
    44:"mt-ForwardSM",
    45: "restoreData",
    46: "sendEndSignal",
    49: "processUnstructuredSS-Request",
    50: "unstructuredSS-Request",
    51: "unstructuredSS-Notify",
    52: "anyTimeInterrogation",
    53: "ssi-Activate",
    55: "provideSubscriberInfo",
    56: "sendAuthenticationInfo",
    57: "restoreData",
    58: "sendIMSI",
    59: "cancelLocation-Sgsn",
    60: "provideSubscriberLocation",
    61: "sendRoutingInfoForLCS",
    62: "subscriberLocationReport",
    67: "purgeMS",
    68: "mt-ForwardSM",
    70: "provideSubscriberInfo",
    72: "reportSMDeliveryStatus",
    73: "activateTraceMode",
    74: "deactivateTraceMode",
    75: "sendIdentification",
    76: "updateFaLang",
    77: "sendRoutingInfoForGprs-Sgsn",
    78: "failureReport-Sgsn",
    79: "noteMsPresentForGprs-Sgsn",
    80: "provideSubscriberLocation-Sgsn",
    81: "provideSubscriberLocation-Msc",
    82: "subscriberLocationReport-Sgsn",
    83: "subscriberLocationReport-Msc",
    84: "sendIdentification-Sgsn",
    85: "reset",
    86: "forwardCheckSS-Indication",
    87: "prepareHandover",
    88: "prepareSubsequentHandover",
    89: "provideSIWFSNumber",
    90: "sendRoutingInfoForLCS-Msc",
    91: "sendRoutingInfoForLCS-Sgsn",
    92: "subscriberLocationReport-LCS",
    93: "cancelVcsgLocation",
    94: "resetVcsg",
    96: "forwardShortMessage",
    97: "prepareGroupCall",
    98: "sendGroupCallEndSignal",
    99: "processGroupCallSignalling",
    100: "forwardGroupCallSignalling",
        101: "checkIMEI",
    102: "mt-ForwardShortMessage",
    103: "sendRoutingInfoForSM",
    104: "mo-ForwardShortMessage",
    105: "reportSM-DeliveryStatus",
    106: "noteSubscriberPresent",
    107: "alertServiceCentreWithoutResult",
    108: "activateTraceMode",
    109: "deactivateTraceMode",
    110: "sendAuthenticationInfo",
    111: "sendImsi",
    112: "processUnstructuredSS-Data",
    113: "unstructuredSS-Request",
    114: "unstructuredSS-Notify",
    115: "anyTimeInterrogation",
    116: "setReportingState",
    117: "statusReport",
    118: "remoteUserFree",
    119: "registerCC-Entry",
    120: "eraseCC-Entry"
    }


html_entities = {  
        "\"": "&apos;",
        "&quot;": "&apos;",
        "<": "&lt;",
        ">": "&gt;",
        "ä": "ae",
        "Ä": "AE",
        "ü": "ue",
        "Ü": "UE",
        "ö": "oe",
        "Ö": "OE",
        "ß": "ss"
    }

html_entities_short = {

        "\"": "&apos;", 
        "&quot;": "&apos;" ,   
        "<": "&lt;",
        ">": "&gt;"
    }

def generate_chart():
    global folder_path,pcap_file_path,progress_bar,root,remaining_files_label,remaining_files_var,edit_chart_button,add_filter_combo,generate_button,add_filter_label,checkbox,filter_label,filter_entry
    if pcap_file_path:
        filter_str = filter_entry.get("1.0", "end-1c")
        html_file_name=pcap_file_path.replace('.pcapng','.html').replace('.pcap','.html')
        try:
            os.remove(html_file_name)
        except:
            a=0
        main(pcap_file_path, filter_str)
        
        webbrowser.open(html_file_name)
        edit_chart_button.config(state=tk.NORMAL)
        
    elif folder_path:
        filter_str = filter_entry.get("1.0", "end-1c")
        progress_bar.grid()
        remaining_files_label.grid()
        root.update_idletasks()
        total_lines = 0
        total_txt_files = 0
        processed_files = 0
        for root_fold, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.pcap') or file.endswith('.pcapng'):
                    total_txt_files += 1

        if total_txt_files == 0:
            tk.messagebox.showinfo("No file", "No pcap files found in the selected folder and its sub-directories")
            progress_bar.grid_remove()  # Hide the progress bar
            return
    
        progress_bar['maximum'] = total_txt_files
        for root_fold, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.pcap') or file.endswith('.pcapng'):
                    main(os.path.join(root_fold, file).replace('\\','/'), filter_str)
                    processed_files += 1
                    progress_bar['value'] = processed_files
                    remaining_files_var.set(f"Remaining files: {total_txt_files - processed_files}")
                    root.update_idletasks()
        messagebox.showinfo("Information",'Chart generation completed')
        progress_bar['value'] = 0
        progress_bar.grid_remove()
        remaining_files_label.grid_remove()

    else:
        messagebox.showerror("Error", "No PCAP file selected.")






def exit_application():
    global ip_hostname_map
    import os

    root.destroy()

def edit_chart():
    global chart_editing
    chart_editing=True
    create_edit_chart_window()


def load_clipboard():
    global nodes,chart_editing,Node_A_table,Node_B_table, Protocol_table, Message_label_table, Message_content_table, Color_Table, Note_Table,current_message_index,Arrow_table,description,title
    import pyperclip
    from unidecode import unidecode
    text = pyperclip.paste()
    if text and text.strip():
        try:
            try:
                own_chart_window.destroy()
            except:
                a=0     
            text=text.replace('\uf0e0', '->')
            text=text.replace('\uf0e8', '->')
            text=text.replace('\uf0f3', '->')
            text=text.replace('\uf0df', '->')
            text=text.replace('\uf0e7', '->')
            text=unidecode(text)
            text=text.replace('<-->','->').replace('<==>','->').replace('<=>','->').replace('<->','->').replace('-->','->').replace('==>','->').replace('<--','->').replace('<==','->').replace('<-','->').replace('<=','->').replace('=>','->').replace('(','_').replace(')','_').replace(',','_').replace(';',' ').replace('>>','->')
            if '->' in text:
                separator='->'
                       
                Node_A_table, Node_B_table,Message_label_table,Protocol_table = extract_nodes(text, separator)  
                Arrow_table=[] 
                Message_content_table=[]
                Color_Table=[]
                Note_Table=[]
                description=''
                title=''
                for i in range(len(Node_A_table)):
                    Color_Table.append('black')
                    #Protocol_table.append('')
                    Message_content_table.append('')
                    #Message_label_table.append('')
                    Note_Table.append('')
                    if 'diameter' in Protocol_table[i].lower() or 'dns' in Protocol_table[i].lower() or 'camel' in Protocol_table[i].lower() or 'map' in Protocol_table[i].lower():
                        Arrow_table.append('dotted-Unidirectionnel')
                    else:
                        Arrow_table.append('solid-Unidirectionnel')

                current_message_index=0
                edit_chart_button.config(state=tk.NORMAL)
                edit_chart()    
            else:
                tk.messagebox.showinfo("Clipboard content not valid", """
Create a text file describing a chart and copy it to clipboard.

Example 1 :

UE => SBC
SBC => UE
SBC => PCRF
PCRF => SBC

Example 2 :

UE => SBC : SIP:INVITE
SBC=> UE : SIP:100 trying
SBC => PCRF : DIAMETER:AAR
PCRF => SBC : DIAMETER:AAA

Example 3 (same output as example 2 ):

UE => SBC : SIP:INVITE => UE: SIP:100 trying 
SBC => PCRF : DIAMETER:AAR => SBC : DIAMETER:AAA

separators between node names could be  => or  -> or ==> or -->  (same output)""")

        except:
            tk.messagebox.showinfo("Clipboard content not valid", """
Create a text file describing a chart and copy it to clipboard.

Example 1 :

UE => SBC
SBC => UE
SBC => PCRF
PCRF => SBC

Example 2 :

UE => SBC : SIP:INVITE
SBC=> UE : SIP:100 trying
SBC => PCRF : DIAMETER:AAR
PCRF => SBC : DIAMETER:AAA

Example 3 (same output as example 2 ):

UE => SBC : SIP:INVITE => UE: SIP:100 trying 
SBC => PCRF : DIAMETER:AAR => SBC : DIAMETER:AAA

separators between node names could be  => or  -> or ==> or --> (same output)""")
    else:
       tk.messagebox.showinfo("Clipboard empty", """
Create a text file describing a chart and copy it to clipboard.

Example 1 :

UE => SBC
SBC => UE
SBC => PCRF
PCRF => SBC

Example 2 :

UE => SBC : SIP:INVITE
SBC=> UE : SIP:100 trying
SBC => PCRF : DIAMETER:AAR
PCRF => SBC : DIAMETER:AAA

Example 3 (same output as example 2 ):

UE => SBC : SIP:INVITE => UE: SIP:100 trying 
SBC => PCRF : DIAMETER:AAR => SBC : DIAMETER:AAA

separators between node names could be  => or  -> or ==> or --> (same output)""")            
def create_own_chart_window():
    global chart_editing,pcap_file_path,folder_path,flowchart_file_path,generate_button,add_filter_combo,add_filter_label,checkbox,filter_label,filter_entry
    try:
        file_label.config(text='')
        pcap_file_path=None
        folder_path=None
        flowchart_file_path=None
    except:
        a=0    
    chart_editing=False
    edit_chart_button.config(state=tk.DISABLED)
    generate_button.config(state=tk.DISABLED)
    add_filter_combo.config(state=tk.DISABLED)
    add_filter_label.config(state=tk.DISABLED)
    filter_label.config(state=tk.DISABLED)
    filter_entry.config(state=tk.DISABLED)
    
    create_edit_chart_window()


def create_edit_chart_window():
    global Node_A_table, Node_B_table,Protocol_table,Message_label_table,Message_content_table,Color_Table,Note_Table,current_message_index,Arrow_table,chart_editing,own_chart_window,description,title
    try:
        own_chart_window.destroy()
    except:
        a=0
    protocol_var = tk.StringVar()
    own_chart_window = tk.Toplevel()
    #own_chart_window.geometry("800x800")
    frame1 = tk.Frame(own_chart_window, bd=2, relief="groove")
    frame1.grid(row=0, column=0, padx=10, pady=10, sticky="we")
    frame2 = tk.Frame(own_chart_window, bd=2, relief="groove")
    frame2.grid(row=1, column=0, padx=10, pady=10, sticky="we")
    frame3 = tk.Frame(own_chart_window, bd=2, relief="groove")
    frame3.grid(row=2, column=0, padx=10, pady=10, sticky="we")    
    frame3bis = tk.Frame(frame3, bd=2, relief="groove")
    frame3bis.grid(row=0, column=4, padx=10, pady=10)    
    frame4 = tk.Frame(own_chart_window, bd=2, relief="groove")
    frame4.grid(row=1, column=1, padx=10, pady=10)       
    frame5 = tk.Frame(own_chart_window)
    frame5.grid(row=3, column=0, padx=10, pady=10, sticky="we")  # expand frame horizontally
    frame5.columnconfigure(1, weight=1)  # make the middle column expandable
    frame6 = tk.Frame(own_chart_window)
    frame6.grid(row=4, column=0, padx=10, pady=10)    
    if not chart_editing:
        Node_A_table = []
        Node_B_table = []
        Protocol_table = []
        Message_label_table = []
        Message_content_table = []    
        Arrow_table=[]
        Note_Table= []
        Color_Table=[]
        description=''
        title=''
    current_message_index=0


    class ToolTip(object):
        def __init__(self, widget):
            self.widget = widget
            self.tipwindow = None
            self.id = None
            self.x = self.y = 0

        def showtip(self, text):
            "Display text in tooltip window"
            self.text = text
            if self.tipwindow or not self.text:
                return
            x, y, _, _ = self.widget.bbox("insert")
            x = x + self.widget.winfo_rootx() + 57
            y = y + self.widget.winfo_rooty() + 27
            self.tipwindow = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(1)
            tw.wm_geometry("+%d+%d" % (x, y))

            label = tk.Label(tw, text=self.text, background="#ffffe0", relief='solid', borderwidth=1,
                            font=("tahoma", "8", "normal"))
            label.pack(ipadx=1)

        def hidetip(self):
            tw = self.tipwindow
            self.tipwindow = None
            if tw:
                tw.destroy()

    def createToolTip(widget, text):
        toolTip = ToolTip(widget)
        def enter(event):
            toolTip.showtip(text)
        def leave(event):
            toolTip.hidetip()
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)

    def contains_zero_or_one_word(strings):
        for s in strings:
            words = s.split()
            if len(words) > 1:
                return False
        return True

    def load_hosts():
        global nodes,chart_editing,Node_A_table,Node_B_table
        import pyperclip
        if chart_editing:
            try:
                if Node_A_table:
                    return remove_duplicates(Node_A_table+Node_B_table)
            except:
                return []
        hosts = []
        clipboard_content = pyperclip.paste()
        if not clipboard_content:
            # try:
            #     with open('hosts.txt', 'r') as f:
            #         for line in f.readlines():
            #             try:
            #                 hosts.append(line.split()[1].replace('*',''))
            #             except:
            #                 a=0
            # except:
            #     a=0
            # return sorted(list(set(hosts)))
            return hosts
        else:
            lines = clipboard_content.split('\n')
            if contains_zero_or_one_word(lines) :
                hosts = [line.split()[0] for line in lines if line.strip() != '']
                if len(hosts) >1:
                    return remove_duplicates(hosts)
                else:
                    hosts=[]
                    return hosts
            else:
                return hosts


    def update_combobox(event):
        current_text = event.widget.get()
        event.widget['values'] = [item for item in hosts if current_text.lower() in item.lower()]

    def append_combobox_value(event):
        current_text = event.widget.get()
        if current_text not in hosts:
            hosts.append(current_text)
            #hosts.sort()
            node_a_combo['values'] = hosts
            node_b_combo['values'] = hosts
        node_a_combo.set('')
        node_b_combo.set('')


    def disable_widget():
        current= arrow_combo.get()
        if current=='rounded-box':
            protocol_combo.set('')
            #protocol_combo.config(state='disabled')
            note_content_text.delete("1.0", tk.END)
            #note_content_text.config(state='disabled')
            message_content_text.delete("1.0", tk.END)
            #message_content_text.config(state='disabled')        
        else:
            protocol_combo.set('SIP')
            protocol_combo.config(state='normal')
            #note_content_text.delete("1.0", tk.END)
            note_content_text.config(state='normal')
            #message_content_text.delete("1.0", tk.END)
            message_content_text.config(state='normal')                  

    
    

    def update_add_new_message_button():
        if node_a_combo.get() and node_b_combo.get():  # if both are not empty
            add_new_message_button.config(state='normal')  # enable the button
            overwrite_button.config(state='normal')
        else:
            add_new_message_button.config(state='disabled')  # disable the button
            overwrite_button.config(state='disabled')
        if node_a_combo.get():
            filter_nodea_button.config(state='normal')
            filterout_nodea_button.config(state='normal')
        else:
            filter_nodea_button.config(state='disabled')
            filterout_nodea_button.config(state='disabled')
        if node_b_combo.get():
            filter_nodeb_button.config(state='normal')
            filterout_nodeb_button.config(state='normal')
        else:
            filter_nodeb_button.config(state='disabled')
            filterout_nodeb_button.config(state='disabled')
        if message_content_text.get("1.0", tk.END).strip():
            filterout_message_button.config(state='normal')
            filter_message_button.config(state='normal')
        else:
            filterout_message_button.config(state='disabled')
            filter_message_button.config(state='disabled')            

    def append_protocol_value(event):
        current_text = event.widget.get()
        Valeurs=list(protocol_combo['values'])
        if current_text not in Valeurs:
            Valeurs.append(current_text)
            #hosts.sort()
            protocol_combo['values'] = Valeurs
            protocol_combo.set('')




    def add_new_message():
        global current_message_index
        Node_A_table.insert(current_message_index+1,replace_special_chars(node_a_combo.get()).replace(' ','_'))
        Node_B_table.insert(current_message_index+1,replace_special_chars(node_b_combo.get()).replace(' ','_'))
        Color_Table.insert(current_message_index+1,color_combo.get())
        Protocol_table.insert(current_message_index+1,protocol_combo.get())
        Message_label_table.insert(current_message_index+1,replace_special_chars(message_label_entry.get()))
        Message_content_table.insert(current_message_index+1,replace_special_chars(message_content_text.get("1.0", tk.END).strip()))
        Note_Table.insert(current_message_index+1,replace_special_chars(note_content_text.get("1.0", tk.END).strip()).replace('\n','\\n'))
        Arrow_table.insert(current_message_index+1,arrow_combo.get())
        current_message_index+=1
        update_status_bar()
        
        Valeurs=list(protocol_combo['values'])
        
        if node_a_combo.get() not in hosts :
            hosts.append(node_a_combo.get())
            node_a_combo['values']=hosts
            node_b_combo['values']=hosts
        if node_b_combo.get() not in hosts :
            hosts.append(node_b_combo.get())
            node_a_combo['values']=hosts
            node_b_combo['values']=hosts   
        if protocol_combo.get() and protocol_combo.get() not in Valeurs:
            Valeurs.append(protocol_combo.get())
            protocol_combo['values'] = Valeurs
                 

            

    def previous_message():
        global current_message_index
        if current_message_index > 0:
            current_message_index -= 1
            display_message(current_message_index)
            update_status_bar()
        # elif len(Node_A_table)>0:
        #     current_message_index=len(Node_A_table)-1
        #     display_message(current_message_index)
        #     update_status_bar()
        if node_a_combo.get() and node_b_combo.get():
            add_new_message_button.config(state="normal")

    def first_message():
        global current_message_index
        try:
            current_message_index =0
            display_message(current_message_index)
            update_status_bar()
        except:
            a=0
        if node_a_combo.get() and node_b_combo.get():
            add_new_message_button.config(state="normal")

    def last_message():
        global current_message_index
        try:
            current_message_index =len(Node_A_table) - 1
            display_message(current_message_index)
            update_status_bar()
        except:
            a=0
        if node_a_combo.get() and node_b_combo.get():
            add_new_message_button.config(state="normal")

    def next_message():
        global current_message_index
        if current_message_index < len(Node_A_table) - 1:
            current_message_index += 1
            display_message(current_message_index)
            update_status_bar()
        # elif len(Node_A_table)>0:
        #     current_message_index=0
        #     display_message(current_message_index)
        #     update_status_bar()
        if node_a_combo.get() and node_b_combo.get():
            add_new_message_button.config(state="normal")            

    def display_message(index):
        try:
            node_a_combo.set(revert_special_chars(Node_A_table[index]))
            node_b_combo.set(revert_special_chars(Node_B_table[index]))
            color_combo.set(Color_Table[index])
            protocol_combo.set(Protocol_table[index])
            arrow_combo.set(Arrow_table[index])
            message_label_entry.delete(0, tk.END)
            message_label_entry.insert(0, revert_special_chars(Message_label_table[index]))
            message_content_text.delete("1.0", tk.END)
            message_content_text.insert("1.0", revert_special_chars(Message_content_table[index]))
            note_content_text.delete("1.0", tk.END)
            note_content_text.insert("1.0", revert_special_chars(Note_Table[index].replace('\\n','\n')))
            update_status_bar()
            
        except:
            node_a_combo.set('')
            node_b_combo.set('')
            color_combo.set('black')
            arrow_combo.set('solid-Unidirectionnel')
            protocol_combo.set('SIP')
            message_label_entry.delete(0, tk.END)
            message_content_text.delete("1.0", tk.END)
            note_content_text.delete("1.0", tk.END)



    def update_current_message():
        global current_message_index
        if node_a_combo.get() and node_b_combo.get():
            if 0 <= current_message_index < len(Node_A_table):
                Node_A_table[current_message_index] = replace_special_chars(node_a_combo.get())
                Node_B_table[current_message_index] = replace_special_chars(node_b_combo.get())
                Color_Table[current_message_index] = color_combo.get()
                Protocol_table[current_message_index] = protocol_combo.get()
                Message_label_table[current_message_index] = replace_special_chars(message_label_entry.get())
                Message_content_table[current_message_index] = replace_special_chars(message_content_text.get("1.0", tk.END).strip())
                Note_Table[current_message_index] = replace_special_chars(note_content_text.get("1.0", tk.END).strip()).replace('\n','\\n')
                Arrow_table[current_message_index] = arrow_combo.get()
        else:
            if 0 <= current_message_index < len(Node_A_table):
                del Node_A_table[current_message_index]
                del Node_B_table[current_message_index]
                del Color_Table[current_message_index]
                del Protocol_table[current_message_index]
                del Arrow_table[current_message_index]
                del Message_label_table[current_message_index]
                del Message_content_table[current_message_index]
                del Note_Table[current_message_index]
            if 0 <= current_message_index+1 < len(Node_A_table):
                current_message_index+=1
                display_message(current_message_index)
            elif 0 <= current_message_index-1 < len(Node_A_table):
                current_message_index-=1
                display_message(current_message_index)
                
        if node_a_combo.get() and node_a_combo.get() not in hosts :
            hosts.append(node_a_combo.get())
            node_a_combo['values']=hosts
            node_b_combo['values']=hosts
        if node_b_combo.get() and node_b_combo.get() not in hosts :
            hosts.append(node_b_combo.get())
            node_a_combo['values']=hosts
            node_b_combo['values']=hosts   
        update_status_bar()               

    def update_status_bar():
        status_text.set(f"Number of messages in chart: {len(Node_A_table)}")
        if len(Node_A_table) > 0:
            message_number_text.set(f"Message {current_message_index + 1}")
        else:
            message_number_text.set('')

    def overwrite_node():
        global current_message_index,Node_A_table,Node_B_table,ip_hostname_map
        if node_a_combo.get() and node_b_combo.get():
            if len(Node_A_table) > 0:
                new=node_a_combo.get()
                try:
                    old=Node_A_table[current_message_index]
                except:
                    old=Node_A_table[current_message_index-1]
                if new!=old:
                    for i in range(len(Node_A_table)):
                        if Node_A_table[i] == old:
                            Node_A_table[i] = new
                        if Node_B_table[i] == old:
                            Node_B_table[i] = new     
                    node_a_combo.set(new) 
                    liste=  node_a_combo['values']
                    liste =[new if item == old else item for item in liste]
                    liste=remove_duplicates(liste)
                    node_a_combo['values']=liste
                    node_b_combo['values']=liste
                    if is_valid_ip(old.replace('_','.')):
                        ip_hostname_map[old.replace('_','.')] = new
                    if is_valid_ip(old.replace('_',':')):
                        ip_hostname_map[old.replace('_',':')] = new

            if len(Node_B_table) > 0:
                new=node_b_combo.get()
                try:
                    old=Node_B_table[current_message_index]
                except:
                    old=Node_B_table[current_message_index-1]
                if new!=old:
                    for i in range(len(Node_B_table)):
                        if Node_A_table[i] == old:
                            Node_A_table[i] = new
                        if Node_B_table[i] == old:
                            Node_B_table[i] = new     
                    node_b_combo.set(new)     
                    liste=  node_a_combo['values']
                    liste =[new if item == old else item for item in liste]
                    liste=remove_duplicates(liste)
                    node_a_combo['values']=liste
                    node_b_combo['values']=liste                                    
                    if is_valid_ip(old.replace('_','.')):
                        ip_hostname_map[old.replace('_','.')] = new
                    if is_valid_ip(old.replace('_',':')):
                        ip_hostname_map[old.replace('_',':')] = new         

    def clear_chart():
        global Node_A_table, Node_B_table, Protocol_table, Message_label_table, Message_content_table, Color_Table, Note_Table,current_message_index,Arrow_table,description,title
        Node_A_table.clear()
        Node_B_table.clear()
        Protocol_table.clear()
        Arrow_table.clear()
        Message_label_table.clear()
        Message_content_table.clear()
        Color_Table.clear()
        Note_Table.clear()
        description=''
        title=''
        current_message_index=0
        update_status_bar()
        edit_chart_button.config(state=tk.DISABLED)

    def update_arrow_combo(protocol_var):
        protocol = protocol_var.get()
        current= arrow_combo.get()
        if current!='rounded-box':
            if not chart_editing: # If Protocol_table is not empty
                if protocol in Protocol_table:
                    index = Protocol_table.index(protocol)
                    # assuming Arrow_table is a list that corresponds to Protocol_table
                    arrow_combo.set(Arrow_table[index])
                    color_combo.set(Color_Table[index])
     

    def switch_nodes():
        temp = node_a_combo.get()
        node_a_combo.set(node_b_combo.get())
        node_b_combo.set(temp)
        if node_a_combo.get() and node_b_combo.get():
            add_new_message_button.config(state="normal")           

    def filter_node_a():
        global current_message_index,Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table,description,title,Node_A_table_temp, Node_B_table_temp, Color_Table_temp, Protocol_table_temp, Message_label_table_temp, Message_content_table_temp, Note_Table_temp, Arrow_table_temp
        nodea=replace_special_chars(node_a_combo.get()).replace(' ','_')
        try:
            Node_A_table_temp = [item for i, item in enumerate(Node_A_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Node_B_table_temp = [item for i, item in enumerate(Node_B_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Color_Table_temp = [item for i, item in enumerate(Color_Table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Protocol_table_temp = [item for i, item in enumerate(Protocol_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Message_label_table_temp = [item for i, item in enumerate(Message_label_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Message_content_table_temp = [item for i, item in enumerate(Message_content_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Note_Table_temp = [item for i, item in enumerate(Note_Table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Arrow_table_temp = [item for i, item in enumerate(Arrow_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2=Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table
            Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table=Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp
            Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp=Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2
            current_message_index=0
            display_message(0)
            update_status_bar()
        except:
            a=0


    def filterout_node_a():
        global current_message_index,Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table,Node_A_table_temp, Node_B_table_temp, Color_Table_temp, Protocol_table_temp, Message_label_table_temp, Message_content_table_temp, Note_Table_temp, Arrow_table_temp
        nodea=replace_special_chars(node_a_combo.get()).replace(' ','_')
        try:
            Node_A_table_temp = [item for i, item in enumerate(Node_A_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Node_B_table_temp = [item for i, item in enumerate(Node_B_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Color_Table_temp = [item for i, item in enumerate(Color_Table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Protocol_table_temp = [item for i, item in enumerate(Protocol_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Message_label_table_temp = [item for i, item in enumerate(Message_label_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Message_content_table_temp = [item for i, item in enumerate(Message_content_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Note_Table_temp = [item for i, item in enumerate(Note_Table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Arrow_table_temp = [item for i, item in enumerate(Arrow_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2=Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table
            Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table=Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp
            Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp=Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2
            current_message_index=0
            display_message(0)
            update_status_bar()
        except:
            a=0

    def filterout_node_b():
        global current_message_index,Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table,Node_A_table_temp, Node_B_table_temp, Color_Table_temp, Protocol_table_temp, Message_label_table_temp, Message_content_table_temp, Note_Table_temp, Arrow_table_temp
        nodea=replace_special_chars(node_b_combo.get()).replace(' ','_')
        try:
            Node_A_table_temp = [item for i, item in enumerate(Node_A_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Node_B_table_temp = [item for i, item in enumerate(Node_B_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Color_Table_temp = [item for i, item in enumerate(Color_Table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Protocol_table_temp = [item for i, item in enumerate(Protocol_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Message_label_table_temp = [item for i, item in enumerate(Message_label_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Message_content_table_temp = [item for i, item in enumerate(Message_content_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Note_Table_temp = [item for i, item in enumerate(Note_Table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Arrow_table_temp = [item for i, item in enumerate(Arrow_table) if Node_A_table[i] != nodea and Node_B_table[i] != nodea]
            Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2=Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table
            Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table=Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp
            Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp=Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2
            current_message_index=0
            display_message(0)
            update_status_bar()
        except:
            a=0
         
            

    def filter_node_b():
        global current_message_index,Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table,Node_A_table_temp, Node_B_table_temp, Color_Table_temp, Protocol_table_temp, Message_label_table_temp, Message_content_table_temp, Note_Table_temp, Arrow_table_temp
        nodea=replace_special_chars(node_b_combo.get()).replace(' ','_')
        try:
            Node_A_table_temp = [item for i, item in enumerate(Node_A_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Node_B_table_temp = [item for i, item in enumerate(Node_B_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Color_Table_temp = [item for i, item in enumerate(Color_Table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Protocol_table_temp = [item for i, item in enumerate(Protocol_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Message_label_table_temp = [item for i, item in enumerate(Message_label_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Message_content_table_temp = [item for i, item in enumerate(Message_content_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Note_Table_temp = [item for i, item in enumerate(Note_Table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Arrow_table_temp = [item for i, item in enumerate(Arrow_table) if Node_A_table[i] == nodea or Node_B_table[i] == nodea]
            Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2=Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table
            Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table=Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp
            Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp=Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2
            current_message_index=0
            display_message(0)
            update_status_bar()
        except:
            a=0



    def filter_message():
        global current_message_index,Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table,Node_A_table_temp, Node_B_table_temp, Color_Table_temp, Protocol_table_temp, Message_label_table_temp, Message_content_table_temp, Note_Table_temp, Arrow_table_temp
        message=replace_special_chars(message_content_text.get("1.0", tk.END).strip())
        if message:
            try:
                Node_A_table_temp = [item for i, item in enumerate(Node_A_table) if message in Message_content_table[i]]
                Node_B_table_temp = [item for i, item in enumerate(Node_B_table) if message in Message_content_table[i]]
                Color_Table_temp = [item for i, item in enumerate(Color_Table) if message in Message_content_table[i]]
                Protocol_table_temp = [item for i, item in enumerate(Protocol_table) if message in Message_content_table[i]]
                Message_label_table_temp = [item for i, item in enumerate(Message_label_table) if message in Message_content_table[i]]
                Message_content_table_temp = [item for i, item in enumerate(Message_content_table) if message in Message_content_table[i]]
                Note_Table_temp = [item for i, item in enumerate(Note_Table) if message in Message_content_table[i]]
                Arrow_table_temp = [item for i, item in enumerate(Arrow_table) if message in Message_content_table[i]]
                Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2=Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table
                Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table=Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp
                Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp=Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2
                current_message_index=0
                display_message(0)
                update_status_bar()
            except:
                a=0


    def filterout_message():
        global current_message_index,Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table,Node_A_table_temp, Node_B_table_temp, Color_Table_temp, Protocol_table_temp, Message_label_table_temp, Message_content_table_temp, Note_Table_temp, Arrow_table_temp
        message=replace_special_chars(message_content_text.get("1.0", tk.END).strip())
        if message:
            try:
                Node_A_table_temp = [item for i, item in enumerate(Node_A_table) if message not in Message_content_table[i]]
                Node_B_table_temp = [item for i, item in enumerate(Node_B_table) if message not in Message_content_table[i]]
                Color_Table_temp = [item for i, item in enumerate(Color_Table) if message not in Message_content_table[i]]
                Protocol_table_temp = [item for i, item in enumerate(Protocol_table) if message not in Message_content_table[i]]
                Message_label_table_temp = [item for i, item in enumerate(Message_label_table) if message not in Message_content_table[i]]
                Message_content_table_temp = [item for i, item in enumerate(Message_content_table) if message not in Message_content_table[i]]
                Note_Table_temp = [item for i, item in enumerate(Note_Table) if message not in Message_content_table[i]]
                Arrow_table_temp = [item for i, item in enumerate(Arrow_table) if message not in Message_content_table[i]]
                Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2=Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table
                Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table=Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp
                Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp=Node_A_table_temp2,Node_B_table_temp2,Color_Table_temp2,Protocol_table_temp2,Message_label_table_temp2,Message_content_table_temp2,Note_Table_temp2,Arrow_table_temp2
                current_message_index=0
                display_message(0)
                update_status_bar()
            except:
                a=0


    def undo_filter():
        global current_message_index,Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table,Node_A_table_temp, Node_B_table_temp, Color_Table_temp, Protocol_table_temp, Message_label_table_temp, Message_content_table_temp, Note_Table_temp, Arrow_table_temp

        try:
            Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table=Node_A_table_temp,Node_B_table_temp,Color_Table_temp,Protocol_table_temp,Message_label_table_temp,Message_content_table_temp,Note_Table_temp,Arrow_table_temp
            current_message_index=0
            display_message(0)
            update_status_bar()
        except:
            a=0



    def save_flowchart():
        import pickle,os
        from tkinter import filedialog, messagebox,ttk
        try:
            if flowchart_file_path:
                basename = os.path.basename(flowchart_file_path)
                initial, _ = os.path.splitext(basename)
            elif pcap_file_path:
                basename = os.path.basename(pcap_file_path)
                initial, _ = os.path.splitext(basename)
            else:
                initial=''
        except:
            initial=''    
        filename = filedialog.asksaveasfilename(defaultextension=".fcd", filetypes=[("FlowChart Data Files", "*.fcd"),("All Files", "*.*")],initialfile=initial)
        if filename:  # asksaveasfilename will return '' if dialog closed with "cancel".
            # Here is where you can use filename to save the data in your specific format.
            description=description_text.get("1.0", tk.END).strip()
            title=title_entry.get()
            dict_of_lists = {
    'Node_A_table': Node_A_table,
    'Node_B_table': Node_B_table,
    'Color_Table': Color_Table,
    'Protocol_table': Protocol_table,
    'Message_label_table': Message_label_table,
    'Message_content_table': Message_content_table,
    'Note_Table': Note_Table,
    'Arrow_table': Arrow_table,  
    'description': description,
    'title':title
}
            # a=remove_duplicates(nodes)
            # b=remove_duplicates(Node_A_table+Node_B_table)
            # print(str(a))
            # print(str(b))
            try:
                with open(filename, 'wb') as f:
                    pickle.dump(dict_of_lists, f)
                tk.messagebox.showinfo("Success", "Flowchart file saved successfully")
            except:
                tk.messagebox.showerror("Error", "Error in saving Flowchart file. Try to choose another location")

    def empty_message():
        for i in range(len(Message_content_table)):
            Message_content_table[i] = ""
        message_content_text.delete("1.0", tk.END)

    def update_note():
        global current_message_index,Node_A_table,Node_B_table,ip_hostname_map,Protocol_table
        prot=protocol_combo.get()
        for i in range(len(Note_Table)):
            if Protocol_table[i]==prot:
                Note_Table[i] = replace_special_chars(note_content_text.get("1.0", tk.END)).replace('\n','\\n')
        #note_content_text.delete("1.0", tk.END)

    def get_parameter_value(parameter_name, string):
        import re
        pattern = f"\n\t{re.escape(parameter_name)}: (.*?)(?=\n\t|\Z)"
        results = re.findall(pattern, string, re.DOTALL)
        return '\\n'.join(results)

    def remove_lines_ending_with_colon(input_string):
        def truncate_string(s, sub):
            idx = s.find(sub)

            if idx == -1:    # substring not found
                return s
            else:            # substring found
                return s[:idx]
        #temp=input_string.replace('\\\\n','\n')
        lines = input_string.split('\\n')
        new_lines = [truncate_string(truncate_string(line, ';tag'),';yop') for line in lines if not line.rstrip().endswith(':')]
        return '\\n'.join(new_lines)

    def close_chart():
        global flowchart_file_path, pcap_file_path,own_chart_window
        try:
            #save_flowchart_button.config(state=tk.DISABLED)
            own_chart_window.destroy()
            if flowchart_file_path:
                flowchart_file_path=None
                file_label.config(text='')
                edit_chart_button.config(state=tk.DISABLED)
        except:
            a=0

    def sanitize_filename(filename):
        import re
        return re.sub(r'[<>:"/\\|?*]', '', filename).strip()

    def is_valid_path(path):
        import os
        if path and os.path.split(path)[1]:
            return True
        return False    

    def Create_own_chart_html():
        global nodes, flowchart_file_path,pcap_file_path

        mscgen_output = "xu {\n hscale=\"1.4\", wordwraparcs=on, width=\"auto\";\n\n"
        nodes = []
        output=''
        description=description_text.get("1.0", tk.END).strip()
        title_fname=sanitize_filename(title_entry.get()).strip()
        mytitle=title_entry.get().strip()
        header_title=''
        body_title=''
        if mytitle:
            header_title='<title>'+mytitle+'</title>'
            body_title='<h1 style="color:blue;text-align:center;">'+mytitle+'</h1>'

        if pcap_file_path:
            try:
                if title_fname:  
                    html_file_name=pcap_file_path.replace(os.path.basename(pcap_file_path),title_fname+'.html')
                    if not is_valid_path(html_file_name):
                        html_file_name=script_location+'\\'+title_fname+'.html'
                        if not is_valid_path(html_file_name):
                            html_file_name=pcap_file_path.replace('.pcapng','.html').replace('.pcap','.html')
                            if not is_valid_path(html_file_name):
                                h = str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
                                html_file_name=script_location+'\\myChart'+h+'.html'
                    output_html=html_file_name.replace('.html','_text.html').replace('\\','/')
                else:
                    html_file_name=pcap_file_path.replace('.pcapng','.html').replace('.pcap','.html')
                    if not is_valid_path(html_file_name):
                        h = str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
                        html_file_name=script_location+'\\myChart'+h+'.html'
                    output_html=html_file_name.replace('.html','_text.html').replace('\\','/')
            except:
                h = str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
                html_file_name=script_location+'\\myChart'+h+'.html'
                output_html=html_file_name.replace('.html','_text.html').replace('\\','/')
        elif flowchart_file_path:
            try:
                if title_fname:  
                    html_file_name=flowchart_file_path.replace(os.path.basename(flowchart_file_path),title_fname+'.html')
                    if not is_valid_path(html_file_name):
                        html_file_name=script_location+'\\'+title_fname+'.html'
                        if not is_valid_path(html_file_name):
                            html_file_name=flowchart_file_path.replace('.fcd','.html')
                            if not is_valid_path(html_file_name):
                                h = str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
                                html_file_name=script_location+'\\myChart'+h+'.html'
                    output_html=html_file_name.replace('.html','_text.html').replace('\\','/')
                else:
                    html_file_name=flowchart_file_path.replace('.fcd','.html')
                    if not is_valid_path(html_file_name):
                        h = str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
                        html_file_name=script_location+'\\myChart'+h+'.html'
                    output_html=html_file_name.replace('.html','_text.html').replace('\\','/')
            except:
                h = str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
                html_file_name=script_location+'\\myChart'+h+'.html'
                output_html=html_file_name.replace('.html','_text.html').replace('\\','/')
        else:
            h = str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
            html_file_name=script_location+'\\myChart'+h+'.html'
            output_html=html_file_name.replace(h,h+'_text').replace('\\','/') 
                

        for i in range(len(Node_A_table)):
            if Node_A_table[i] and Node_B_table[i]:
                if Node_A_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'):
                    nodes.append(Node_A_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'))
                if Node_B_table[i].replace('.', '_').replace('-', '_').replace(':', '_'):
                    nodes.append(Node_B_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'))            
                # if Protocol_table[i]=='SIP':
                #             #print(packet.number)
                #     try:
                #         mscgen_output += generate_mscgen_message(Node_A_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), Node_B_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), f"{Protocol_table[i]}: {Message_label_table[i]}",replace_special_chars(Message_content_table[i]),Color_Table[i]) + "\n"
                #     except:
                #         a=0
                # else:
                #     try:
                #         mscgen_output += generate_mscgen_dotted(Node_A_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), Node_B_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), f"{Protocol_table[i]}: {Message_label_table[i]}",replace_special_chars(Message_content_table[i]),Color_Table[i]) + "\n"
                #     except:
                #         try:
                #             mscgen_output += generate_mscgen_dotted(Node_A_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), Node_B_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), f"{Protocol_table[i]}: {Message_label_table[i]}",replace_special_chars(Message_content_table[i]),'') + "\n"
                #         except:
                #             a=0
                if Protocol_table[i]:
                    protocol=Protocol_table[i]+': '
                else:
                    protocol=''
                mscgen_output += generate_mscgen_custom(Node_A_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), Node_B_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), f"{protocol}{Message_label_table[i]}",replace_special_chars(Message_content_table[i]),Color_Table[i],line_dict[Arrow_table[i]]) + "\n"
                try:
                    output+=f"{Node_A_table[i]} ==> {Node_B_table[i]},    {protocol}{Message_label_table[i]} \n"
                    try:
                        output+=Message_content_table[i].replace('"',"'")
                    except:
                        a=0
                    output+='\n'+'-' * 124 + '\n'
                except:
                    a=0
                if Note_Table[i]:
                    try:
                        temp=re.sub(r'\$(.*?)\\n',lambda m: get_parameter_value(m.group(1),Message_content_table[i])+'\\n',Note_Table[i])
                        try:
                            temp=remove_lines_ending_with_colon(temp)
                        except:
                            a=0
                        if temp.replace('\\n',''):
                            mscgen_output += generate_mscgen_note(Node_A_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), Node_B_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), f"{temp}") + "\n"
                    except:
                        mscgen_output += generate_mscgen_note(Node_A_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), Node_B_table[i].replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'), f"{Note_Table[i]}") + "\n"
        if nodes:    
            mscgen_output = mscgen_output.replace("width=\"auto\";\n\n", f"width=\"auto\";\n\n{','.join(remove_duplicates(nodes))};\n\n")
        mscgen_output += "}\n"
        js_file=script_location+'\\resource.js'
        mscgen_output = '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta content='text/html;charset=utf-8' http-equiv='Content-Type'>
        hohoho
        <script>
        var mscgen_js_config = {{
            clickable: false
        }}
        </script>
<script>
  var sources = [
    "https://sverweij.github.io/mscgen_js/mscgen-inpage.js",
    "hahaha",
  ];

  function loadScript(sourceIndex) {
    if (sourceIndex >= sources.length) {
      console.error('All script sources failed to load.');
      return;
    }

    var script = document.createElement('script');
    script.src = sources[sourceIndex];
    script.onerror = function() {
      console.error('Failed to load script from: ' + sources[sourceIndex]);
      loadScript(sourceIndex + 1);
    };
    document.head.appendChild(script);
  }

  loadScript(0);
</script>
        <style>
            #openFileButton {
                position: fixed;
                bottom: 20px;
                right: 20px;
                padding: 10px 20px;
                font-size: 16px;
                cursor: pointer;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <pre class='code mscgen mscgen_js' data-named-style='lazy' data-mirror-entities='true'>
        '''+mscgen_output+'''

        </pre>
        <button id="openFileButton" onclick="openTextFile()">Open Text File</button>
        <script>
            function openTextFile() {{
                var textFileUrl = "{}";  // Placeholder for output_file_name variable
                window.open(textFileUrl, "_blank");
            }}
        </script>
        hawhawhaw
    </body>
    </html>
    '''.format(output_html)
        mscgen_output=mscgen_output.replace('hahaha',js_file).replace('hohoho',header_title).replace('hawhawhaw',body_title)


        with open(html_file_name, "w") as f:
            f.write(mscgen_output)
        html=text_to_html(output)
        with open(output_html, "w") as output_file:
            output_file.write(html)        
        webbrowser.open(html_file_name)
        #save_flowchart_button.config(state='normal')


    hosts = load_hosts()

    title_label = tk.Label(frame1, text="Title:")
    title_label.grid(row=0, column=0, padx=10, pady=10, sticky='w')
    createToolTip(title_label, 'You can give your chart a title, which will be used as a name for your generated diagram, and will be added at the bottom of the web page\nIf this field is empty, a default name will be then used to generate the diagram')
    title_entry = tk.Entry(frame1, width=50)
    title_entry.grid(row=0, column=1, padx=10, pady=10, sticky='w')
    try:
        title_entry.insert(0, title)
    except:
        a=0
    description_label = tk.Label(frame1, text="Chart description:")
    
    description_label.grid(row=1, column=0, padx=10, pady=10, sticky='w')
    createToolTip(description_label, 'A text which describes the scenario of the chart.\nThis will not be displayed in the flow chart, but it will be saved in the flowchart data.')

    description_text = tk.Text(frame1, width=120, height=5)
    description_text.grid(row=1, column=1, padx=10, pady=10, sticky='w')
    try:
        description_text.insert("1.0", description)
    except:
        a=0

    node_a_label = tk.Label(frame2, text="Node A:")
    node_a_label.grid(row=0, column=0, padx=10, pady=10, sticky='w')
    node_b_label = tk.Label(frame2, text="Node B:")
    node_b_label.grid(row=2, column=0, padx=10, pady=10, sticky='w')

    node_a_combo = ttk.Combobox(frame2, values=hosts)
    node_a_combo.grid(row=0, column=1, padx=10, pady=10, sticky='w')
    node_a_combo.bind("<KeyRelease>", lambda e: update_add_new_message_button())
    node_a_combo.bind("<Return>", append_combobox_value)
    node_a_combo.bind("<<ComboboxSelected>>", lambda e:  update_add_new_message_button())


    filter_nodea_button = tk.Button(frame2, text="filter", command=filter_node_a, state='disabled')
    filter_nodea_button.grid(row=0, column=2, padx=10, pady=10, sticky='w')
    

    filterout_nodea_button = tk.Button(frame2, text="filter out", command=filterout_node_a, state='disabled')
    filterout_nodea_button.grid(row=0, column=3, padx=10, pady=10, sticky='w')
    


    createToolTip(filter_nodea_button, 'Keep only the messages involving current Node A')
    createToolTip(filterout_nodea_button, 'remove all messages involving current Node A')

    switch_button = tk.Button(frame2, text="⇕", command=switch_nodes)
    switch_button.grid(row=1, column=1, padx=10, pady=10)
    createToolTip(switch_button, 'switch Node A and Node B content')

    overwrite_button = tk.Button(frame2, text="update node names", command=overwrite_node, state='disabled')
    overwrite_button.grid(row=1, column=2, padx=10, pady=10, sticky='w')
    createToolTip(overwrite_button, 'Overwrite all old node names in the whole chart with the new ones, when relevant')

    filter_nodeb_button = tk.Button(frame2, text="filter", command=filter_node_b, state='disabled')
    filter_nodeb_button.grid(row=2, column=2, padx=10, pady=10, sticky='w')
    
    filterout_nodeb_button = tk.Button(frame2, text="filter out", command=filterout_node_b, state='disabled')
    filterout_nodeb_button.grid(row=2, column=3, padx=10, pady=10, sticky='w')
    


    createToolTip(filter_nodeb_button, 'Keep only the messages involving current Node B')
    createToolTip(filterout_nodeb_button, 'remove all messages involving current Node B')

    node_b_combo = ttk.Combobox(frame2, values=hosts)
    node_b_combo.grid(row=2, column=1, padx=10, pady=10, sticky='w')
    node_b_combo.bind("<KeyRelease>", lambda e: update_add_new_message_button())
    node_b_combo.bind("<Return>", append_combobox_value)
    node_b_combo.bind("<<ComboboxSelected>>", lambda e:  update_add_new_message_button())

    protocol_label = tk.Label(frame2, text="Protocol:")
    protocol_label.grid(row=3, column=0, padx=10, pady=10, sticky='w')
    createToolTip(protocol_label, 'Select protocol, or write your own name')






    protocol_combo = ttk.Combobox(frame2, values=['SIP', 'Diameter', 'DNS', 'HTTP', 'ISUP','MEGACO','ISUP','MAP',''], textvariable=protocol_var)
    protocol_combo.grid(row=3, column=1, padx=10, pady=10, sticky='w')
    protocol_combo.set('SIP')
    #protocol_var.trace('w', lambda *args: update_arrow_combo(protocol_var))
    protocol_combo.bind("<Return>", append_protocol_value)

    arrow_label = tk.Label(frame2, text="Line type:")
    arrow_label.grid(row=4, column=0, padx=10, pady=10, sticky='w')

    arrow_combo = ttk.Combobox(frame2, values=['solid-Unidirectionnel', 'solid-bidirectionnel','solid-no-arrow','dotted-Unidirectionnel' ,'dotted-bidirectionnel', 'dotted-no-arrow','rounded-box'], state='readonly')
    arrow_combo.grid(row=4, column=1, padx=10, pady=10, sticky='w')
    arrow_combo.set('solid-Unidirectionnel')
    arrow_combo.bind("<KeyRelease>", lambda e: disable_widget())
    arrow_combo.bind("<<ComboboxSelected>>", lambda e:  disable_widget())
    message_label_label = tk.Label(frame2, text="Message Label:")
    message_label_label.grid(row=5, column=0, padx=10, pady=10, sticky='w')

    message_label_entry = tk.Entry(frame2, width=25)
    message_label_entry.grid(row=5, column=1, padx=10, pady=10, sticky='w')
    createToolTip(message_label_label, 'Text to be shown after the protocol name above the line, example:\nINVITE')
    colors = ['black', 'blue', 'green', 'orange', 'pink', 'red', 'violet', 'lime', 'cyan']

    color_label = tk.Label(frame2, text="Color:")
    color_label.grid(row=6, column=0, padx=10, pady=10, sticky='w')

    color_combo = ttk.Combobox(frame2, values=colors, state='readonly')
    color_combo.grid(row=6, column=1, padx=10, pady=10, sticky='w')
    if not chart_editing:
        color_combo.set('black')  # Set the default value to 'black'
    note_content_label = tk.Label(frame3, text="Note Content:")
    
    note_content_label.grid(row=0, column=0, padx=10, pady=10, sticky='w')
    createToolTip(note_content_label, '''yellow box displayed under the message
                  
                  If you have generated the chart from a pcap, you can use relative values token from the Message Content lines below

                  Example :

                  RURI: $Request-Line
                  $CSeq
                  Session ID: $Session ID''')

    note_content_text = tk.Text(frame3, width=120, height=5)
    note_content_text.grid(row=0, column=1, padx=10, pady=10, sticky='w')
    note_button = tk.Button(frame3bis, text="update all note contents", command=update_note)
    note_button.grid(row=0, column=0, padx=10, pady=10, sticky='w')
    createToolTip( note_button, 'All notes  of the same protocol will be updated with the currently displayed note')    
    message_content_label = tk.Label(frame3, text="Message Content:")
    message_content_label.grid(row=1, column=0, padx=10, pady=10, sticky='w')
    createToolTip( message_content_label, 'Content will be displayed when the user hovers over the line text')
    message_button = tk.Button(frame3bis, text="Clear all message contents", command=empty_message)
    message_button.grid(row=1, column=0, padx=10, pady=10, sticky='w')    
    
    filter_message_button = tk.Button(frame3, text="filter", command=filter_message, state='disabled')
    filter_message_button.grid(row=1, column=2, padx=10, pady=10, sticky='w') 

    filterout_message_button = tk.Button(frame3, text="filter out", command=filterout_message, state='disabled')
    filterout_message_button.grid(row=1, column=3, padx=10, pady=10, sticky='w') 

    createToolTip(filter_message_button, 'Keep only the messages containing input string. \nOverwrite the Message content box by the input string to be used as filter, then press this button')
    createToolTip(filterout_message_button, 'remove all messages containing input string. \nOverwrite the Message content box by the input string to be used as filter, then press this button')
    #frame = tk.Frame(own_chart_window)
    #frame.grid(row=10, column=1, padx=10, pady=10, sticky='w')

    # Create a vertical scrollbar in the Frame
    # v_scrollbar = tk.Scrollbar(frame3)
    # v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # # Create a horizontal scrollbar in the Frame
    # h_scrollbar = tk.Scrollbar(frame3, orient='horizontal')
    # h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

    # Create the Text widget in the Frame and associate the scrollbars with it
    message_content_text = tk.Text(frame3, width=120, height=10)
    message_content_text.grid(row=1, column=1, padx=10, pady=10, sticky='w')

    # Configure the scrollbars to move with the text widget
    # v_scrollbar.config(command=message_content_text.yview)
    # h_scrollbar.config(command=message_content_text.xview)

    add_new_message_button = tk.Button(frame4, text="Insert message", command=add_new_message, state='disabled')
    add_new_message_button.grid(row=0, column=0, pady=10, sticky='w')
    createToolTip(add_new_message_button, 'insert the message just after the current displayed one')


    update_current_message_button = tk.Button(frame4, text="Update/delete message", command=update_current_message)
    update_current_message_button.grid(row=1, column=0, pady=10, sticky='w')
    createToolTip(update_current_message_button, 'Change the current message contents. If you want to delete the message, make Node A or Node B empty')

    revert_button = tk.Button(frame4, text="Undo filter", command=undo_filter)
    revert_button.grid(row=2, column=0, pady=10, sticky='w')
    createToolTip(revert_button, 'Revert the last filter applied on the chart')

    clear_chart_button = tk.Button(frame4, text="Clear the chart", command=clear_chart)
    clear_chart_button.grid(row=3, column=0, pady=10, sticky='w')  

    save_flowchart_button = tk.Button(frame4, text="Save chart...", command=save_flowchart)
    save_flowchart_button.grid(row=4, column=0, pady=10, sticky='w')  # You can adjust the position as per your need  

    first_message_button = tk.Button(frame5, text="First message", command=first_message)
    first_message_button.grid(row=0, column=0, padx=(0, 10), sticky="w")  # stick to the left (west)

    prev_message_button = tk.Button(frame5, text="Previous message", command=previous_message)
    prev_message_button.grid(row=0, column=1, padx=10)

    next_message_button = tk.Button(frame5, text="Next message", command=next_message)
    next_message_button.grid(row=0, column=2, padx=10)

    last_message_button = tk.Button(own_chart_window, text="Last message", command=last_message)
    last_message_button.grid(row=3, column=1, pady=10)  # stick to the right (east)


    generate_chart_button = tk.Button(own_chart_window, text="Generate diagram", command=Create_own_chart_html, bg='green',height=3)
    generate_chart_button.grid(row=2, column=1,pady=10)



    close_window_button = tk.Button(own_chart_window, text="Close", command=close_chart)
    close_window_button.grid(row=4, column=0, pady=10)  # Adjust the row and column values as needed to place the button at the center bottom    




    status_text = tk.StringVar()
    status_bar = tk.Label(own_chart_window, textvariable=status_text, bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_bar.grid(row=5, column=0, columnspan=4, sticky="we")

    message_number_text = tk.StringVar()
    message_number_label = tk.Label(own_chart_window, textvariable=message_number_text, bd=1, relief=tk.SUNKEN, anchor=tk.E)
    message_number_label.grid(row=5, column=4, sticky="we") 

    if chart_editing:
        own_chart_window.title("Edit chart")        
        filter_nodea_button.grid()
        filterout_nodea_button.grid()
        filter_nodeb_button.grid()
        filterout_nodeb_button.grid()
        filterout_message_button.grid()
        filter_message_button.grid()
        note_button.grid()
        message_button.grid()        
        filter_nodea_button.config(state='normal')
        filterout_nodea_button.config(state='normal')
        filter_nodeb_button.config(state='normal')    
        filterout_nodeb_button.config(state='normal')
        filterout_message_button.config(state='normal')
        filter_message_button.config(state='normal')
        add_new_message_button.config(state='normal')          
    else:
        own_chart_window.title("Create Own Chart")
        filter_nodea_button.grid_remove()
        filterout_nodea_button.grid_remove()
        filter_nodeb_button.grid_remove()
        filterout_nodeb_button.grid_remove()
        filter_message_button.grid_remove()
        filterout_message_button.grid_remove()
        note_button.grid_remove()
        message_button.grid_remove() 



    # frame2 = tk.Frame(own_chart_window, bd=2, relief="groove")
    # frame3 = tk.Frame(own_chart_window, bd=2, relief="groove")
    # frame4 = tk.Frame(own_chart_window, bd=2, relief="groove")
    # frame5 = tk.Frame(own_chart_window, bd=2, relief="groove")


    # frame2.grid(row=1, column=0, padx=10, pady=10, sticky="we")
    # frame3.grid(row=2, column=0, padx=10, pady=10, sticky="we")
    # frame4.grid(row=3, column=0, padx=10, pady=10, sticky="we")
    # frame5.grid(row=4, column=0, padx=10, pady=10, sticky="we")

    update_status_bar()  # Update the status bar initially
    current_message_index = 0


    #save_flowchart_button.config(state=tk.DISABLED)
    # if pcap_file_path:
    #     save_flowchart_button.config(state='normal')
    if len(Node_A_table) > 0:
        display_message(current_message_index)    
    own_chart_window.mainloop()




def create_gui():
    global root, file_label, filter_entry, pcap_file_path,progress_bar,remaining_files_label,remaining_files_var,folder_path,edit_chart_button,add_filter_combo,checkbox_var,flowchart_file_path,generate_button,add_filter_label,checkbox,filter_label,filter_entry,from_argv,predefined_filter_combo
    pcap_file_path = None
    folder_path= None
    flowchart_file_path=None
    from_argv=False
    
    
    
    def load_predefined_filters():
        """Load predefined filters from wireshark_filter.ini and return a dictionary of filter categories and their corresponding filter strings."""
        filter_dict = {}
        try:
            with open(script_location + '\\wireshark_filter.ini', "r") as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            category, filter_str = line.split(':', 1)
                            filter_dict[category.strip()] = filter_str.strip()
        except Exception as e:
            print(f"Error loading predefined filters: {e}")
        return filter_dict
    
    def update_filter_entry(event):
        """Update the filter_entry with the selected filter string."""
        selected_category = predefined_filter_combo.get()
        if selected_category in predefined_filters:
            filter_entry.delete("1.0", tk.END)
            filter_entry.insert("1.0", predefined_filters[selected_category])

    def drop(files):
        global pcap_file_path,folder_path,add_filter_combo,flowchart_file_path,add_filter_label,checkbox,filter_label,filter_entry
        f=files[0]
        file_path = f.decode('utf-8')
        if os.path.isfile(file_path) and '.pcap' in file_path:
            pcap_file_path=file_path.replace('\\','/')
            try:
                own_chart_window.destroy()
            except:
                a=0            
            try:
                file_label.config(text=pcap_file_path)
                folder_path=''
                flowchart_file_path=None
                update_button_state()
                add_filter_combo['values']=[]
                add_filter_combo.set('')
                generate_chart()           

            except:
                a=0
        elif os.path.isdir(file_path):
            folder_path=file_path.replace('\\','/')
            file_label.config(text=f"Selected folder: {folder_path}")
            pcap_file_path=''
            flowchart_file_path=None
            try:
                own_chart_window.destroy()
            except:
                a=0                
            try:
                flowchart_file_path=None
            except:
                a=0              
            update_button_state()




    def update_button_state():
        if pcap_file_path or folder_path:
            generate_button.config(state=tk.NORMAL)
            add_filter_combo.config(state=tk.NORMAL)
            add_filter_label.config(state=tk.NORMAL)
            filter_label.config(state=tk.NORMAL)
            filter_entry.config(state=tk.NORMAL)
            predefined_filter_combo.config(state=tk.NORMAL)
            predefined_filter_label.config(state=tk.NORMAL)         
            checkbox.config(state=tk.NORMAL)
            if pcap_file_path:
                edit_chart_button.config(state=tk.DISABLED)
        else:
            generate_button.config(state=tk.DISABLED)
            add_filter_combo.config(state=tk.DISABLED)
            add_filter_label.config(state=tk.DISABLED)
            filter_label.config(state=tk.DISABLED)
            filter_entry.config(state=tk.DISABLED)
            checkbox.config(state=tk.DISABLED)   
            predefined_filter_combo.config(state=tk.DISABLED)
            predefined_filter_label.config(state=tk.DISABLED)            
        if flowchart_file_path:
            edit_chart_button.config(state=tk.NORMAL)
            filter_entry.config(state=tk.NORMAL)
            filter_entry.delete("1.0", tk.END)
            filter_entry.config(state=tk.DISABLED)
        else:
            edit_chart_button.config(state=tk.DISABLED)

    def browse_pcap_file():
        global pcap_file_path,folder_path,add_filter_combo,flowchart_file_path,add_filter_label,checkbox,filter_label,filter_entry
        pcap_file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap;*.pcapng")])
        if pcap_file_path:
            try:
                own_chart_window.destroy()
            except:
                a=0            
            try:
                file_label.config(text=pcap_file_path)
                folder_path=''
                flowchart_file_path=None
                update_button_state()
                add_filter_combo['values']=[]
                add_filter_combo.set('')
         

            except:
                a=0

    class ToolTip(object):
        def __init__(self, widget):
            self.widget = widget
            self.tipwindow = None
            self.id = None
            self.x = self.y = 0

        def showtip(self, text):
            "Display text in tooltip window"
            self.text = text
            if self.tipwindow or not self.text:
                return
            x, y, _, _ = self.widget.bbox("insert")
            x = x + self.widget.winfo_rootx() + 57
            y = y + self.widget.winfo_rooty() + 27
            self.tipwindow = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(1)
            tw.wm_geometry("+%d+%d" % (x, y))

            label = tk.Label(tw, text=self.text, background="#ffffe0", relief='solid', borderwidth=1,
                            font=("tahoma", "8", "normal"))
            label.pack(ipadx=1)

        def hidetip(self):
            tw = self.tipwindow
            self.tipwindow = None
            if tw:
                tw.destroy()

    def createToolTip(widget, text):
        toolTip = ToolTip(widget)
        def enter(event):
            toolTip.showtip(text)
        def leave(event):
            toolTip.hidetip()
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)

    def open_saved_flowchart():
        import pickle
        global pcap_file_path,folder_path,add_filter_combo,flowchart_file_path,add_filter_label,checkbox,filter_label,filter_entry
        global current_message_index,Node_A_table,Node_B_table,Color_Table,Protocol_table,Message_label_table,Message_content_table,Note_Table,Arrow_table,description,title,from_argv
        try:
            own_chart_window.destroy()
        except:
            a=0
        if not from_argv:
            flowchart_file_path = filedialog.askopenfilename(filetypes=[("FlowChart Data Files", "*.fcd")])
        if flowchart_file_path:
            from_argv=False
            file_label.config(text=flowchart_file_path)
            folder_path=''
            pcap_file_path=''
            update_button_state()
            add_filter_combo['values']=[]
            add_filter_combo.set('')
            with open(flowchart_file_path, 'rb') as f:
                loaded_lists = pickle.load(f)    
            Node_A_table= loaded_lists['Node_A_table'] 
            Node_B_table= loaded_lists['Node_B_table']
            Color_Table= loaded_lists['Color_Table']
            Protocol_table= loaded_lists['Protocol_table']
            Message_content_table=loaded_lists['Message_content_table']
            Message_label_table= loaded_lists['Message_label_table']
            Note_Table= loaded_lists['Note_Table']
            Arrow_table= loaded_lists['Arrow_table']   
            try:
                description= loaded_lists['description']
            except:
                description=''
            try:
                title= loaded_lists['title']
            except:
                base_name = os.path.basename(flowchart_file_path)

                # Split the base name into name and extension and take the name part
                title = os.path.splitext(base_name)[0]
            current_message_index=0
            edit_chart_button.config(state=tk.NORMAL)
            edit_chart()


    def choose_folder():
        global pcap_file_path,folder_path,add_filter_combo,flowchart_file_path,add_filter_label,checkbox,filter_label,filter_entry,from_argv
        folder_path = filedialog.askdirectory()
        if folder_path:
            file_label.config(text=f"Selected folder: {folder_path}")
            pcap_file_path=''
            flowchart_file_path=None
            try:
                own_chart_window.destroy()
            except:
                a=0                
            try:
                flowchart_file_path=None
            except:
                a=0
            if not filter_entry.get("1.0", tk.END).strip():
                filter_text=''
                with open(script_location+'\\wireshark_filter.ini', "r") as output_file:
                    for line in output_file:
                        if line.strip() and not line.startswith('#'):
                            filter_text=line
                            break
                filter_entry.insert("1.0", filter_text)                   
            update_button_state()
        else:
            file_label.config(text="No folder selected")

    root = tk.Tk()
    root.title("Flow Chart Generator")
    predefined_filters = load_predefined_filters()
    windnd.hook_dropfiles(root, func=drop)
    menu = tk.Menu(root)
    root.config(menu=menu)

    file_menu = tk.Menu(menu)
    #folder_menu = tk.Menu(menu)
    #menu.add_cascade(label="Folder", menu=folder_menu)
    #folder_menu.add_command(label="Choose Folder", command=choose_folder)

    menu.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Open/Edit saved flowchart..", command=open_saved_flowchart)
    file_menu.add_separator()
    file_menu.add_command(label="Choose pcap file..", command=browse_pcap_file)
    file_menu.add_command(label="Choose pcap folder..", command=choose_folder)  # Add this line
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=exit_application)

    frame = tk.Frame(root, padx=20, pady=20)
    frame.pack()

    file_label = tk.Label(frame, text="", font=("Arial", 12), wraplength=500)
    file_label.grid(row=0, column=0, pady=10, sticky='w')
    
    predefined_filter_label = tk.Label(frame, text="Predefined Filters:", font=("Arial", 12))
    predefined_filter_label.grid(row=1, column=0, pady=10, sticky='w')
    #predefined_filter_label.config(state=tk.DISABLED)

    predefined_filter_combo = ttk.Combobox(frame, values=list(predefined_filters.keys()), state="readonly")
    predefined_filter_combo.grid(row=1, column=1, pady=10, sticky='w')
    createToolTip(predefined_filter_label, 'Predefined filters imported from wireshark_filter.ini')
   

    predefined_filter_combo.bind("<<ComboboxSelected>>", update_filter_entry)

    filter_label = tk.Label(frame, text="Filter String:", font=("Arial", 12))
    filter_label.grid(row=2, column=0, pady=10, sticky='w')
    createToolTip(filter_label, 'Wireshark filter to be applied when importing a pcap file(s)')

    filter_entry = tk.Text(frame, width=60, height=5, font=("Courier New", 12), wrap="word")
 
    filter_entry.grid(row=3, column=0, pady=10, sticky='w')
    if predefined_filters:
        # Get the first key from the dictionary
        first_key = list(predefined_filters.keys())[0]
        
        # Set the first key as the selected value in the combobox
        predefined_filter_combo.set(first_key)
        
        # Set the corresponding dictionary value to the filter_entry content
        filter_entry.delete("1.0", tk.END)  # Clear any existing content in the filter_entry
        filter_entry.insert("1.0", predefined_filters[first_key])     
    #filter_entry.config(state=tk.DISABLED)
    #predefined_filter_combo.config(state=tk.DISABLED)
    add_filter_frame = tk.Frame(frame)
    add_filter_frame.grid(row=4, column=0, pady=10, sticky='w')

    add_filter_label = tk.Label(add_filter_frame, text="Additional text filter:", font=("Arial", 12), state=tk.DISABLED)
    add_filter_label.grid(row=0, column=0, pady=10, sticky='w')
    createToolTip(add_filter_label, 'In addition to the wireshark filter string above, you can add here an additional text filter. \nAll mesages which does not include this text will be discarded. \nIf you have already generated the chart from the loaded pcap, the box will be filled with a list of suggested strings which you can use, if you want.')

    add_filter_combo = ttk.Combobox(add_filter_frame,width=50, state=tk.DISABLED)
    add_filter_combo.grid(row=0, column=1,pady=10, sticky='w')
    checkbox_var = tk.IntVar()
    checkbox_var.set(1)
    checkbox = tk.Checkbutton(frame, text="Generate notes", variable=checkbox_var, font=("Arial", 12), state=tk.DISABLED)
    createToolTip(checkbox, 'Include the most relevant headers in a yellow note box under the lines')
    checkbox.grid(row=5, column=0, sticky='w')

    generate_button = tk.Button(frame, text="Generate diagram from pcap(s)", font=("Arial", 12), command=generate_chart, state=tk.DISABLED)
    generate_button.grid(row=6, column=0, pady=10, sticky='w')
    createToolTip(generate_button, 'You need to select pcap file or directory in order to generate corresponding diagram')
    edit_chart_button = tk.Button(frame, text="Edit generated chart..", font=("Arial", 12), command=edit_chart, state=tk.DISABLED)
    edit_chart_button.grid(row=6, column=1, pady=10, sticky='w')    
    create_own_chart_button = tk.Button(frame, text="Create Own Chart...", font=("Arial", 12), command=create_own_chart_window)
    create_own_chart_button.grid(row=7, column=0, pady=10, sticky='w')    
    from_clipboard_button = tk.Button(frame, text="Generate diagram from clipboard...", font=("Arial", 12), command=load_clipboard)
    from_clipboard_button.grid(row=8, column=0, pady=10, sticky='w')      
    createToolTip(from_clipboard_button, """
Create a text file describing a chart and copy it to clipboard.

Example 1 :

UE => SBC
SBC => UE
SBC => PCRF
PCRF => SBC

Example 2 :

UE => SBC : SIP:INVITE
SBC=> UE : SIP:100 trying
SBC => PCRF : DIAMETER:AAR
PCRF => SBC : DIAMETER:AAA

Example 3 (same output as example 2 ):

UE => SBC : SIP:INVITE => UE: SIP:100 trying 
SBC => PCRF : DIAMETER:AAR => SBC : DIAMETER:AAA

separators between node names could be  => or  -> or ==> or --> or > (same output)""")
    progress_bar = ttk.Progressbar(frame, length=500, mode='determinate', maximum=100, value=0)
    progress_bar.grid(row=9, column=0, padx=20, pady=(0, 20), sticky='w')  # Change the row value here
    progress_bar.grid_remove()  # Hide the progress bar initially
    exit_button = tk.Button(root, text="Exit", font=("Arial", 12), command=exit_application)
    exit_button.pack(side=tk.BOTTOM, anchor=tk.SE, padx=20, pady=20)
    remaining_files_var = tk.StringVar()
    remaining_files_var.set("Remaining files: 0")
    remaining_files_label = tk.Label(frame, textvariable=remaining_files_var, font=("Arial", 12))  # Place the label inside the 'frame' widget
    remaining_files_label.grid(row=10, column=0, padx=20, pady=20, sticky='w')  # Change the row value here
    remaining_files_label.grid_remove()  # Hide the label initially
    from_argv=False
    if len(sys.argv) > 1:
        try:
            if '.pcap' not in sys.argv[1]:
                from_argv=True
                flowchart_file_path = sys.argv[1]
                
                open_saved_flowchart()
                from_argv=False
            else:
                pcap_file_path=sys.argv[1].replace('\\','/')
                try:
                    own_chart_window.destroy()
                except:
                    a=0     
                try:
                    file_label.config(text=pcap_file_path)
                    folder_path=''
                    flowchart_file_path=None
                    update_button_state()
                    add_filter_combo['values']=[]
                    add_filter_combo.set('')

                    generate_chart()           

                except:
                    a=0                  
        except:
            a=0
    root.mainloop()

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def capture_pretty_print(layer):
    original_stdout = sys.stdout
    sys.stdout = StringIO()
    layer.pretty_print()
    captured_output = sys.stdout.getvalue()
    sys.stdout = original_stdout
    captured_output = '\n'.join([line.rstrip() for line in captured_output.split('\n')])
    return captured_output

def read_host_file(host_file_path):
    ip_hostname_map = {}
    with open(host_file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line and line.strip() and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2:
                    ip_hostname_map[parts[0]] = parts[1]
    return ip_hostname_map

def read_reverse_host_file(host_file_path):
    ip_hostname_map = {}
    
    with open(host_file_path, 'r') as file:
        # Read all lines into a list
        lines = file.readlines()
    
    # Iterate through the lines in reverse order
    for line in reversed(lines):
        line = line.strip()
        if line and line.strip() and not line.startswith('#'):
            parts = line.split()
            if len(parts) >= 2:
                ip_hostname_map[parts[0]] = parts[1]
    
    return ip_hostname_map


def packet_summary(pkt,src_name,dst_name):
    global add_filter_values,checkbox_var
    note=''
    if 'ip' not in pkt and 'ipv6' not in pkt:
        return None

    #src = pkt.ip.src
    #dst = pkt.ip.dst

    #src_name = ip_hostname_map.get(src, None)
    if src_name is None:
        src_name = src_name.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_')

    #dst_name = ip_hostname_map.get(dst, None)
    if dst_name is None:
        dst_name = dst_name.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_')

    if 'sip' in pkt:
        if hasattr(pkt.sip, 'Request_Line') and pkt.sip.Request_Line:
            method = pkt.sip.Request_Line.split()[0]+' , packet '+pkt.number
            if checkbox_var.get()==1:
                try:
                    note+='\\n'+'RURI: '+pkt.sip.r_uri+'\\n'
                except:
                    a=0
                try:
                    note+='From: '+pkt.sip.from_addr+'\\n'
                except:
                    a=0            
                try:
                    note+='To: '+pkt.sip.to_addr+'\\n'
                except:
                    a=0 
                try:
                    if pkt.sip.pai_addr:
                        note+='PAI: '+pkt.sip.pai_addr +'\\n' 
                except:
                    a=0        
                try:
                    if pkt.sip.ppi_addr:
                        note+='PPI: '+pkt.sip.ppi_addr+'\\n'  
                except:
                    a=0                
                try:
                    if pkt.sip.p_served_user:
                        note+='P-Served-User: '+replace_special_chars_short(pkt.sip.p_served_user)+'\\n'  
                except:
                    a=0      
                try:
                    if pkt.sip.p_profile_key:
                        note+='PPK: '+replace_special_chars_short(pkt.sip.p_profile_key)+'\\n'  
                except:
                    a=0     
                try:
                    if pkt.sip.route and ('mode' in pkt.sip.route or ';pbx' in pkt.sip.route):
                        note+='Route: '+replace_special_chars_short(pkt.sip.route)+'\\n'  
                except:
                    a=0                                      
            try:
                if pkt.sip.call_id not in add_filter_values:
                    add_filter_values.append(pkt.sip.call_id)
            except:
                a=0    
            try:
                cleaned=pkt.sip.from_user
                cleaned=cleaned.replace('+49','').replace('+','')
                if cleaned not in add_filter_values:
                    add_filter_values.append(cleaned)
            except:
                a=0  
            try:
                cleaned=pkt.sip.to_user
                cleaned=cleaned.replace('+49','').replace('+','')                
                if cleaned not in add_filter_values:
                    add_filter_values.append(cleaned)
            except:
                a=0                                   
                                
        elif hasattr(pkt.sip, 'Status_Line') and pkt.sip.Status_Line:
            method = pkt.sip.Status_Line.split()[1]
            try:
                method+=' '+ pkt.sip.Status_Line.split()[2]+' , packet '+pkt.number
            except:
                a=0
            if checkbox_var.get()==1:
                try:
                    if pkt.sip.p_associated_uri:
                        note+='PAU: '+replace_special_chars_short(pkt.sip.p_associated_uri)+'\\n'  
                except:
                    a=0
        else:
            method = 'Unknown'
        add_filter_combo['values']=add_filter_values
        return ('SIP', src_name, dst_name, method,note)
    elif 'diameter' in pkt:
        if hasattr(pkt.diameter, 'cmd_code'):
            try:
                cmd=diam_code[pkt.diameter.cmd_code]+thisdict[pkt.diameter.flags_request]+' , packet '+pkt.number
            except:
                cmd = pkt.diameter.cmd_code+' , packet '+pkt.number
                  
        else:
            cmd = 'Unknown'
        try:
            if pkt.diameter.session_id not in add_filter_values:
                add_filter_values.append(pkt.diameter.session_id)
        except:
            a=0   
        add_filter_combo['values']=add_filter_values    
        return ('Diameter', src_name, dst_name, cmd,note)
    elif 'dns' in pkt:
        if hasattr(pkt.dns, 'flags'):
            dns_qr = 'Query'+' , packet '+pkt.number if int(pkt.dns.flags, base=16) & 0x8000 == 0 else 'Response'+' , packet '+pkt.number
            if checkbox_var.get()==1:
                try:
                    note+='\\n'+pkt.dns.qry_name+'\\n'
                except:
                    a=0      
                try:
                    note+=pkt.dns.a+'\\n'
                except:
                    a=0                                      
        else:
            dns_qr = 'Unknown'+' , packet '+pkt.number
        return ('DNS', src_name, dst_name, dns_qr,note)
    else:
        if pkt.layers[-1].layer_name !='sctp' and pkt.layers[-1].layer_name !='tcp' and pkt.layers[-1].layer_name !='arp' and pkt.layers[-1].layer_name !='udp':
            if checkbox_var.get()==1:
                try:
                    output_lines = []
                    for key, value in pkt.layers[-1]._all_fields.items():
                        if value and value !='0':
                            output_lines.append(f"{key}: {value}")

                    note = '\\n'+'\\n'.join(output_lines)+'\\n'
                except:
                    note=''
            try:
                method=ISUP_message_dict[pkt.isup.message_type]+' , packet '+pkt.number
            except:
                try:
                    method=MAP_message_dict[int(pkt.layers[-1].gsm_old_localvalue)]+' , packet '+pkt.number
                except:
                    try:
                        method=pkt.megaco.transaction+' '+pkt.megaco.command+' , packet '+pkt.number
                    except:                    
                        method=' packet '+pkt.number


            try:
                return (pkt.layers[-1].layer_name,src_name, dst_name,method,note)
            except:
                return None
        else:
            return None


def generate_mscgen_message(src, dst, message,title,couleur):
    src = src.replace('.', '_')
    dst = dst.replace('.', '_')
    return f"{src} => {dst} [label=\"{message}\",linecolor=\"{couleur}\",textcolor=\"{couleur}\",title=\"{title}\"];"

def generate_mscgen_custom(src, dst, message,title,couleur,line):
    src = src.replace('.', '_')
    dst = dst.replace('.', '_')
    return f"{src} {line} {dst} [label=\"{message}\",linecolor=\"{couleur}\",textcolor=\"{couleur}\",title=\"{title}\"];"

def generate_mscgen_dotted(src, dst, message,title,couleur):
    src = src.replace('.', '_')
    dst = dst.replace('.', '_')
    if couleur:
        return f"{src} >> {dst} [label=\"{message}\",linecolor=\"{couleur}\",textcolor=\"{couleur}\",title=\"{title}\"];"
    else:
        return f"{src} >> {dst} [label=\"{message}\",title=\"{title}\"];"

def generate_mscgen_note(src, dst, message):
    src = src.replace('.', '_')
    dst = dst.replace('.', '_')
    return f"{src} note {dst} [label=\"{message}\"];"

# Read pcap file
#cap = pyshark.FileCapture('c:/test2.pcapng')

# Prepare mscgen header
mscgen_output = "xu {\n hscale=\"1.4\", wordwraparcs=on, width=\"auto\";\n\n"

# Collect unique node names (IP addresses)
nodes = set()


script_location=os.path.dirname(os.path.abspath(__file__))
try:
    host_file_path = script_location+'\\hosts.txt'
    ip_hostname_map = read_reverse_host_file(host_file_path)
except:
    ip_hostname_map ={} 




def main(pcap_file, filter_str):
    global Node_A_table, Node_B_table,Protocol_table,Message_label_table,Message_content_table,Color_Table,Note_Table,current_message_index,Arrow_table,add_filter_combo,add_filter_values,nodes,add_filter_label,checkbox,filter_label,filter_entry,description,title
    #global filter_str
    colors = ['black','blue',  'green', 'orange', 'pink','red','violet','lime','cyan']
    assignments = {}
    assignments2 = {}
    assignments3 = {}
    output_file_name = pcap_file.replace('.pcapng', '.txt').replace('.pcap', '.txt')
    output_html=output_file_name.replace('.txt', '').replace('#', '_')+'_text.html'
    try:
        os.remove(output_file_name)
    except:
        a=0
    try:
        os.remove(output_html)
    except:
        a=0        
    mscgen_output = "xu {\n hscale=\"1.4\", wordwraparcs=on, width=\"auto\";\n\n"
    Node_A_table = []
    Node_B_table = []
    Protocol_table = []
    Message_label_table = []
    Message_content_table = []    
    Arrow_table=[]
    Note_Table= []
    Color_Table=[]   
    description=''
    title=''
    add_filter_values=list(add_filter_combo['values']) 

# Collect unique node names (IP addresses)
    nodes = []
    try:
        output=''
        cap = pyshark.FileCapture(pcap_file, display_filter=filter_str,keep_packets=False)
        #dns_info = get_tshark_resolved_names(pcap_file)
        #updated_hostname=append_non_existing_keys(ip_hostname_map, dns_info)
        #write_to_hosts_file(updated_hostname, host_file_path)
        for packet in cap:
            try:
                additional_filter=add_filter_combo.get()
                if additional_filter:
                    if additional_filter not in str(packet):
                        continue
        
                if 'Malformed' in str(packet):
                    continue
                try:
                    if packet.layers[-1].layer_name =='sctp' or packet.layers[-1].layer_name =='tcp' or packet.layers[-1].layer_name =='arp':
                        continue
                except:
                    a=0
            
                if 'ipv6' in packet:
                    try:
                        src_ip = packet.ipv6.src
                    except:
                        src_ip='N/A'
                    try:
                        dst_ip = packet.ipv6.dst
                    except:
                        dst_ip='N/A'
                elif 'ip' in packet:
                    try:
                        src_ip = packet.ip.src
                    except:
                        src_ip='N/A'
                    try:
                        dst_ip = packet.ip.dst
                    except:
                        dst_ip='N/A'
                
                #src_ip = packet.ip.src if 'ip' in packet else 'N/A'
                #dst_ip = packet.ip.dst if 'ip' in packet else 'N/A'
                #src_ip = packet.ipv6.src if 'ipv6' in packet
                #src_ip = packet.ipv6.src if 'ipv6' in packet
                #src_ip = dns_info.get(src_ip, src_ip)
                #dst_ip = dns_info.get(dst_ip, dst_ip)
                orig_src_ip=src_ip
                orig_dst_ip=dst_ip
                if is_valid_ip(src_ip):
                    try:
                        src_ip=ip_hostname_map[src_ip]
                        orig_src_ip=src_ip + ' ('+orig_src_ip+')'
                    except:
                        a=0
                if is_valid_ip(dst_ip):
                    try:
                        dst_ip=ip_hostname_map[dst_ip]
                        orig_dst_ip=dst_ip + ' ('+orig_dst_ip+')'
                    except:
                        a=0            
                src_port = packet[packet.transport_layer].srcport if packet.transport_layer and packet.transport_layer in packet else 'N/A'
                dst_port = packet[packet.transport_layer].dstport if packet.transport_layer and packet.transport_layer in packet else 'N/A'
                packet_time=str(packet.sniff_time)
                packet_number=packet.number
                try:
                    if src_port=='N/A':
                        src_port = packet.sctp.srcport 
                    if dst_port=='N/A':
                        dst_port = packet.sctp.dstport
                except:
                    a=0
                #########################################################################################
                #mscgen_output = "xu {\n hscale=\"1.4\", wordwraparcs=on, width=\"auto\";\n\n"
        # Cllect unique node names (IP addresses)
                #nodes = set()
                summary = packet_summary(packet, src_ip,dst_ip)
                if summary:
                    protocol, src, dst, message, note = summary
                    message=message.replace('"',"'")
                    note=note.replace('"',"'")
                    if src.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'):
                        nodes.append(src.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'))
                    if dst.replace('.', '_').replace('-', '_').replace(':', '_'):
                        nodes.append(dst.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_'))
                    if protocol=='SIP':
                        #print(packet.number)
                        try:
                            my_color=assign_color(packet.sip.call_id,assignments,colors)
                            source=src.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_')
                            destination=dst.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_')
                            my_summary=summarise(capture_pretty_print(packet.sip))
                            
                            mscgen_output += generate_mscgen_message(source, destination, f"{protocol}: {message}",my_summary,my_color) + "\n"
                            Node_A_table.append(source)
                            Node_B_table.append(destination)
                            Protocol_table.append('SIP')
                            Message_label_table.append(message)
                            Message_content_table.append(my_summary)
                            Arrow_table.append('solid-Unidirectionnel')
                            Color_Table.append(my_color)
                            good=True
                        except:
                            a=0
                            good=False
                    else:
                        try:
                            try:
                                my_color=assign_color(packet.layers[-1].transid,assignments3,colors)
                            except:
                                try:
                                    my_color=assign_color(packet.layers[-1].session_id,assignments2,colors)
                                except:
                                    my_color='black'
                            source=src.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_')
                            destination=dst.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_')
                            my_summary=summarise(capture_pretty_print(packet.layers[-1]))
                                                        
                            mscgen_output += generate_mscgen_dotted(source, destination, f"{protocol}: {message}",my_summary,my_color) + "\n"
                            Node_A_table.append(source)
                            Node_B_table.append(destination)
                            Protocol_table.append(protocol)
                            Message_label_table.append(message)
                            Message_content_table.append(my_summary)
                            Arrow_table.append('dotted-Unidirectionnel')
                            Color_Table.append(my_color)    
                            good=True                        

                        except:
                            a=0
                            good=False
                    if note and good:
                        source=src.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_')
                        destination=dst.replace('.', '_').replace('-', '_').replace(':', '_').replace('/', '_')                        
                        mscgen_output += generate_mscgen_note(source, destination, f"{note}") + "\n"  
                        Note_Table.append(note)
                    elif good:
                        Note_Table.append('')
                #############################################################################################    
                output+=f"{orig_src_ip}:{src_port} ==> {orig_dst_ip}:{dst_port},    Packet: {packet_number},    Time: {packet_time} \n"
                if packet.layers[-1].layer_name == 'DATA':
                    try:
                        output+=capture_pretty_print(packet.layers[-2]).replace('"',"'")
                    except:
                        output+=capture_pretty_print(packet.layers[-1]).replace('"',"'")
                else:
                    output+=capture_pretty_print(packet.layers[-1]).replace('"',"'")

                output+='\n'+'-' * 124 + '\n'
                

            except:
                continue
        with open(output_file_name, "w") as output_file:
            output_file.write(output)
        if nodes:    
            mscgen_output = mscgen_output.replace("width=\"auto\";\n\n", f"width=\"auto\";\n\n{','.join(remove_duplicates(nodes))};\n\n")
        # Complete mscgen output
        mscgen_output += "}\n"
        js_file=script_location+'\\resource.js'
        js_file_aternate=os.path.dirname(pcap_file)+'\\resource.js'
        mscgen_output = '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta content='text/html;charset=utf-8' http-equiv='Content-Type'>
        <script>
        var mscgen_js_config = {{
            clickable: false
        }}
        </script>
<script>
  var sources = [
    "https://sverweij.github.io/mscgen_js/mscgen-inpage.js",
    "hahaha",
    "hihihi",
  ];

  function loadScript(sourceIndex) {
    if (sourceIndex >= sources.length) {
      console.error('All script sources failed to load.');
      return;
    }

    var script = document.createElement('script');
    script.src = sources[sourceIndex];
    script.onerror = function() {
      console.error('Failed to load script from: ' + sources[sourceIndex]);
      loadScript(sourceIndex + 1);
    };
    document.head.appendChild(script);
  }

  loadScript(0);
</script>
        <style>
            #openFileButton {
                position: fixed;
                bottom: 20px;
                right: 20px;
                padding: 10px 20px;
                font-size: 16px;
                cursor: pointer;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <pre class='code mscgen mscgen_js' data-named-style='lazy' data-mirror-entities='true'>
        '''+mscgen_output+'''

        </pre>
        <button id="openFileButton" onclick="openTextFile()">Open Text File</button>
        <script>
            function openTextFile() {{
                var textFileUrl = "{}";  // Placeholder for output_file_name variable
                window.open(textFileUrl, "_blank");
            }}
        </script>
    </body>
    </html>
    '''.format(output_html)
        mscgen_output=mscgen_output.replace('hahaha',js_file).replace('hihihi',js_file_aternate)  # Use str.format() to replace the placeholder with the variable value




            # Save the output to a file
        html_file_name = pcap_file.replace('.pcapng', '.html').replace('.pcap', '.html')
        with open(html_file_name, "w") as f:
            f.write(mscgen_output)
        try:
            cap.close()
        except:
            a=0
        with open(output_file_name, "r") as output_file:
            texte=output_file.read()
        html=text_to_html(texte)
        try:
            os.remove(output_file_name)
        except:
            a=0    
        with open(output_html, "w") as output_file:
            output_file.write(html)
    except:
        try:
            cap.close()
            return
        except:
            return

if __name__ == "__main__":
    create_gui()
