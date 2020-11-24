#! /usr/bin/env python3

import email
import smtplib
from itertools import islice
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

""" It creates a dictionary with all the values of the config file"""
def getValuesConfig():
    configFile_value = dict()
    filename = 'config.txt'
    with open(filename) as f_obj:
        lines = f_obj.readlines()
    for line in lines:
        if not line.startswith( '#' ) and not line.startswith( '\n' ):
            text = line.rstrip().split("=")[0]
            configFile_value[text]=line.rstrip().split("=")[1]
    return configFile_value


"""Function in order to send emails"""
def send_email():
    # We fill up all the values in order to send an email
    subject = "Email from BCAST_IDS sended correctly!"
    body = "Congrats! This email means that you have configured sending emails successfully. BCAST_IDS will be able to let you know when a network anomaly is detected."
    sender_email = configFile_value.get('SENDER_EMAIL')
    sender_password = configFile_value.get('SENDER_PASSWORD')
    receivers_email = configFile_value.get('RECEIVERS_EMAIL').split(",")
    mail_server = configFile_value.get('MAIL_SERVER')
    port_mail_server = int(configFile_value.get('PORT_MAIL_SERVER'))

    ## Log in to server using secure context and send email
    try:
        for receiver_email in receivers_email:
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = receiver_email
            message["Subject"] = subject

            # Add body to email
            message.attach(MIMEText(body, "plain"))

            text = message.as_string()
            with smtplib.SMTP(mail_server, port_mail_server) as server:
                if sender_password:
                    server.starttls() #enable security
                    server.login(sender_email, sender_password) #login with mail_id and password
                server.sendmail(sender_email, receiver_email, text)
                server.quit()

        # Email sended successfully
        print(f"Email sended successfully from {sender_email} to {', '.join(map(str,receivers_email))}")

    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == '__main__':

    # Dictionary with all the values of the config file
    configFile_value = getValuesConfig()

    if configFile_value.get('SEND_EMAIL')=='yes':
        send_email()
    else:
        print("Change the variable 'SEND_EMAIL' to 'yes' and make sure you have fill up the rest of the variables of the config.txt: SENDER_EMAIL, SENDER_PASSWORD (if necessary), RECEIVERS_EMAIL, MAIL_SERVER and PORT_MAIL_SERVER")
