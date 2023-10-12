"""Copyright (c) 2021 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""
import tkinter as tk
import time
import re

digger_gui = None


class DiggerGui:
    gui = False
    window = None
    greeting = None
    textwindow = None
    e_text = ""
    readinp = False

    def __init__(self):
        pass

    def enable_gui(self):
        self.gui = True
        self.window = tk.Tk()
        self.window.title("SDA Digger")
        self.scroll = tk.Scrollbar(self.window, orient='vertical')
        self.scroll.pack(side=tk.RIGHT, fill="y")
        self.textwindow = tk.Text(self.window, height=24, width=80, yscrollcommand=self.scroll.set)
        self.scroll.config(command=self.textwindow.yview)
        self.textwindow.pack()
        self.entry1 = tk.Entry(self.window, width=30)
        self.entry1.pack()
        # self.button = tk.Button(self.window, text="Enter", command=self.get_value)
        # self.button.pack()
        self.window.bind('<Return>', self.get_value)

    def out(self, text, *args, **kwargs):
        # print(kwargs)
        if self.gui is False:
            if len(text) == 1:
                print(text, end='')
            else:
                print(text)
        else:
            self.textwindow.insert(tk.END, text + "\n")
            self.textwindow.see(tk.END)
            self.window.update_idletasks()
            self.window.update()

    def get_value(self, *args):
        self.e_text = self.entry1.get()
        self.entry1.delete(0, tk.END)
        self.readinp = True

    def inp(self, text):
        self.e_text = ""
        if self.gui is False:
            return (input(text))
        else:
            self.out(text)
            while True:
                self.window.update_idletasks()
                self.window.update()
                time.sleep(0.1)
                if self.readinp is True:
                    self.readinp = False
                    return (self.e_text)


# Helper funtion for output to send outputs through GUI.

def dig_out_function(text, *args, **kwargs):
    global digger_gui
    # print(args,kwargs)
    if digger_gui is None:
        digger_gui = DiggerGui()
    digger_gui.out(text, args, kwargs)


# Helper funtion for Input gathering to send it through GUI or CLI

def dig_in_function(text, *args, **kwargs):
    global digger_gui
    return (digger_gui.inp(text))


def dig_gui_enable():
    global digger_gui
    if digger_gui is None:
        digger_gui = DiggerGui()
    digger_gui.enable_gui()
    return
