#
# Risk Bias Detector
# Copyright (C) 2025 Damian Strojek, Hubert Piotroski, Marcin Szachowski 
#

# Imports
import os
import openai
import subprocess
import datetime
import textwrap
from openai import OpenAI
from fpdf import FPDF

# Constants
DEBUG = True
TEMPERATURE = 0
MODEL = "gpt-4o"
IMAGE_MODEL = "dall-e-3"

# Color constants
RED='\033[1;31m'
GRN='\033[1;32m'
YEL='\033[1;33m\n'
BLU='\033[1;34m'
MAG='\033[1;35m'
ORN='\033[38;5;208m'
CYN='\033[1;36m'
ITA='\033[3m'
NC='\033[0m'

# Create a class inheriting from FPDF for custom functions
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Vulnerability Scan Report', ln=True, align='C')

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def add_report_title(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, f'Report generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True)
        self.ln(10)  # Line break

    def add_host_report(self, hostData):
        # Host details
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, f'Host: {hostData["host"]} ({hostData["status"]})', ln=True)

        # Open ports
        self.set_font('Arial', 'B', 10)
        self.cell(0, 10, 'Open Ports:', ln=True)
        self.set_font('Arial', '', 10)
        self.cell(0, 10, ', '.join(map(str, hostData['openPorts'])), ln=True)

        # Recommendations
        if hostData['recommendations']:
            self.set_font('Arial', 'B', 10)
            self.cell(0, 10, 'Recommendations:', ln=True)
            self.set_font('Arial', '', 10)
            
            # Split recommendations string by line breaks
            recommendations = hostData['recommendations'].split('\n\n')
            
            for rec in recommendations:
                # Wrap the recommendation text to fit into the PDF page
                wrappedRecommendation = wrap_text(rec)
                self.multi_cell(0, 10, wrappedRecommendation)
        else:
            self.cell(0, 10, 'No recommendations available.', ln=True)

        self.ln(10)  # Add space before next host

# Prompt the user for their OpenAI API key (security measures)
# or Read it from file that is excluded from the repo
def set_openai_api_key():

    filePath = './files/.key'
    if os.path.exists(filePath):
        with open(filePath, 'r') as file:
            apiFileKey = file.readline().strip()
            if apiFileKey.startswith("sk-proj"):
                apiKey = apiFileKey
            else:
                apiKey = input(YEL + "[?] " + BLU + "Please enter your OpenAI API key: " + NC)
    else:
        apiKey = input(YEL + "[?] " + BLU + "Please enter your OpenAI API key: " + NC)
    
    openai.api_key = apiKey
    client = OpenAI(api_key=apiKey)
    return client

# Send request to OpenAI API and return response
# Use pre-defined systemPrompt and context
def send_openai_request(client, userQuery, debug):
    systemPrompt = """
        You are an AI ethics analyst focused on bias and fairness in cybersecurity.
        Your job is to evaluate events and decisions made by security systems (such as logins, access attempts, alerts) 
        and determine whether they contain any form of unfair bias (e.g. based on location, age, gender, user role, time, etc). 
        You should clearly explain if bias is detected, what kind it is (systemic, statistical, human-induced), 
        and whether the event or decision seems fair or not. If there are suggestions to improve fairness, include them."""
    context = """
        You are assisting with the Risk-Bias-Detector project. The tool is designed to evaluate cybersecurity event data and 
        detect possible bias or ethical concerns in AI-based decision making. It should help assess whether users or groups 
        are being unfairly treated based on AI rules. The types of bias to look for include: implicit bias, historical bias, 
        sampling bias, algorithmic bias, and automation bias. 
        Provide clear and structured analysis with explanations in bullet points if needed. 
        Your output may be used in compliance or audit reports."""
    
    messages = [{"role": "system", "content": systemPrompt},
                {"role": "user", "content": userQuery},
                {"role": "assistant", "content": context}]

    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()
    debug.write(chatCompletion + "\n")
    
    if(DEBUG): print(YEL + "[DEBUG] " + RED + chatCompletion + NC)
    
    return chatCompletion

# Send custom request to OpeniAI API and retun response
def send_custom_openai_request(client, systemPrompt, context, userQuery, debug):
    messages = [{"role": "system", "content": systemPrompt},
                {"role": "user", "content": userQuery},
                {"role": "assistant", "content": context}]

    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()
    debug.write(chatCompletion + "\n")
    
    return chatCompletion

# Send request to image generation model
def send_dalle_request(client, userQuery, debug):
    response = client.images.generate(model=IMAGE_MODEL, prompt=userQuery, 
        size="1024x1024", quality="standard", n=1)
    imageUrl = response.data[0].url
    
    print(YEL + "[*] " + MAG + "Your image is located at: " + imageUrl + NC)
    debug.write("Image URL: " + imageUrl + "\n")
    
    return

# Print out welcoming banner
def create_banner(client, debug):
    systemPrompt = """
        You are a creative assistant. Your task is to return a banner that will be shown as the 
        first thing after running the application."""
    context = """
        Return only plain text that can be printed immediately to the console. 
        Do not include any functions, code, or markdown formatting. Avoid backticks and quotation marks. 
        Do not include comments or explanations. Start the output with an ASCII art logo or visual related 
        to the application's name or theme. Then include the application name: Risk Bias Detector. 
        Add the current date, time, and approximate geolocation in a readable format (e.g., City, Country). 
        Keep it stylish but minimal. The goal is to impress and inform the user at launch."""
    userQuery = """
        Generate a startup banner for a Python application named 'Risk Bias Detector'. 
        This tool is used to identify and eliminate bias in AI-based decision-making. 
        Make the design professional, with ASCII art at the top. 
        Include the current date, time, and approximate geolocation."""
    
    debug.write("\n" + "#" * 50 + "\n")
    response = send_custom_openai_request(client, systemPrompt, context, userQuery, debug)
    
    print("\n" + CYN + response + NC + "\n")
    return

def handle_demoqueries(client, debug):
    demoqueries = [
        # Bias detected: Geographic bias / Implicit bias
        # Explanation: The system may be unfairly penalizing users from certain regions regardless of behavior patterns.
        # Since the credentials matched, denying access may be discriminatory based solely on location.
        """A user from Nigeria was flagged and denied access due to unusual login activity, 
        although the login credentials and behavior matched the user profile. 
        The AI system marked it as 'high-risk'. Please analyze for bias.""",
        # Bias detected: Temporal / automation bias
        # Explanation: The system seems to apply blanket rules based on typical working hours without considering individual work schedules.
        # This results in false positives for night shift workers.
        """An employee working night shifts regularly gets flagged for login attempts outside business hours.
        The AI model treats these as high risk. Is there any bias?""",
        # Bias detected: None
        # Explanation: The decision seems justified and based on objective rules about permissions.
        # No evidence of discriminatory behavior or unfair treatment.
        """A user tried to access confidential files multiple times without sufficient permissions.
        The AI blocked the access and generated a warning."""
    ]

    print(YEL + "[*] " + MAG + "Available demo queries:" + NC)
    for idx, query in enumerate(demoqueries, start=1):
        print(YEL + f"[{idx}] " + ORN + f" {query}" + NC)

    try:
        choice = int(input(YEL + "[?] " + BLU + "Choose option: " + NC))
        if 1 <= choice <= len(demoqueries):
            selectedQuery = demoqueries[choice - 1]
            response = send_openai_request(client, selectedQuery, debug)
            print(ITA + "\n" + response + NC)
        else:
            print(YEL + "[!]" + RED + "Invalid selection." + NC) 
    except ValueError:
        print(YEL + "[!]" + RED + "Please enter a valid number." + NC)
    return

# Provide a recursive menu for the user
def menu(client, debug):
    print(YEL + "[*] " + MAG + "MENU" + NC)
    print(YEL + "[1] " + MAG + "Enter a new 'security event'" + NC)
    print(YEL + "[2] " + MAG + "Use a demo query from the built-in list" + NC)
    print(YEL + "[3] " + MAG + "Exit the program" + NC)
    choice = input(YEL + "[?] " + BLU + "Choose option: " + NC)

    if choice == '1':
        userQuery = input(YEL + "[?] " + BLU + "Enter a new 'security event': " + NC)
        response = send_openai_request(client, userQuery, debug)
        print(ITA + response + NC)
        menu(client, debug)
    elif choice == '2':
        handle_demoqueries(client, debug)
        menu(client, debug)
    elif choice == '3':
        print("\n[+] Goodbye!")
        return
    else:
        print(YEL + "[!] " + RED + "Invalid option, please try again." + NC)
        menu(client, debug)
    return

# Create the PDF report
def generate_pdf_report(scanResults, outputFilename='./files/Report.pdf'):
    pdf = PDFReport()
    pdf.add_page()
    pdf.add_report_title()

    for host in scanResults:
        if host != scanResults[0]:
            pdf.add_page()
        pdf.add_host_report(host)
    
    pdf.output(outputFilename)
    print(YEL + "[*] " + MAG + "Report saved as " + outputFilename + "." + NC)
    return

# Helper function to wrap long recommendation text
def wrap_text(text, width=100):
    return '\n'.join(textwrap.wrap(text, width))

# Main function
def main():
    debug = open('./files/openai-log.txt', 'a')

    # Set the OpenAI API key, hosts, and print welcoming banner
    client = set_openai_api_key()
    create_banner(client, debug)

    menu(client, debug)
        
    # --------------------------
    # PDF Report
    # --------------------------
    
    #scanData = []

    #for currentHost in activeHosts:
        
    #    hostReport = {
    #        "host": currentHost.ipAddress,
    #        "status": "online",
    #        "openPorts": currentHost.openPorts,
    #        "recommendations": currentHost.recommendations
    #    }
        
    #    scanData.append(hostReport)

    #generate_pdf_report(scanData)
        
    print(YEL + "[*] " + MAG + "The application is terminating." + NC)
    debug.close()
    exit()

if __name__ == "__main__":
    main()
