#! /usr/bin/env python3

"""
*********************************************************
*           INTEGRATION WITH TELEGRAM                   *
* https://api.telegram.org/bot<API-TOKEN>/getUpdates    *
*                                                       *
*********************************************************
"""
import sys
import json
import requests
import argparse
import urllib

""" Dictionary with all the values of the config FILE"""
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

# Diccionary which saves the data of the config file
configFile_value = getValuesConfig()

# CONSTANTS
TOKEN = configFile_value.get('BOT_TELEGRAM_TOKEN')
URL = "https://api.telegram.org/bot{}/".format(TOKEN)

#.............................................................................

"""
It obtains the given results if the bot URL
"""
def get_url(url):
    response = requests.get(url)
    content = response.content.decode("utf8")
    updates = json.loads(content)
    return updates

"""
 CHAT_ID otained successfully: (num_chat_id, None)
 CHAT_ID not obtained successfullt: (None, error message)
"""
def get_chatID(offset=None):
    chat_id = None
    cad_error = None
    url = URL + "getUpdates?timeout=100"
    if offset:
        url += "&offset={}".format(offset)
    try:
       updates = get_url(url)
       if updates['ok'] == True:
           result = True
           num_updates = len(updates["result"])
           last_update = num_updates - 1
           # We check that the chat_id is not a BOT
           if updates["result"][last_update]["message"]["from"]["is_bot"] == False:
               chat_id = updates["result"][last_update]["message"]["chat"]["id"]
       else:
           cad_error = f"{updates['error_code']}: {updates['description']}"
    except Exception as e:
        cad_error = e
    finally:
        return (chat_id,cad_error)

"""
 EMAIL sended successfully: (True, None)
 EMAIL NOT sended successfully: (False, error message)
"""
def send_message_telegram(text, chat_id):
    sended = False
    cad_error = None
    try:
        text = urllib.parse.quote_plus(text)
        url = URL + "sendMessage?text={}&chat_id={}".format(text, chat_id)
        updates = get_url(url)
        if updates['ok'] == True:
            sended = True
        else:
           cad_error = f"{updates['error_code']}: {updates['description']}"
    except Exception as e:
        cad_error = e
    finally:
        return (sended,cad_error)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''Script to test the integration with Telegram''')
    parser.add_argument('-i', '--chat_id', action='store_true', help=f"Obtain the last chat_id of the URL: {URL}getUpdates in order to send emails to your channel")
    parser.add_argument("-t", "--send_message", nargs=1, help="Send a message to your chat_id")
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.chat_id:
        result = get_chatID()
        # Print chat_id
        if result[0] != None:
            print(f"Chat_ID: {result[0]}")
        # Print the errors if there were any
        else:
            print(f"ERROR - {result[1]}. The chat_id was not obtained successfully. Check if you typed properly the TELEGRAM_TOKEN property in the config.txt file or you have initialized the bot in Telegram correctly.")

    # Send a message to try the configuration of Telegram
    if args.send_message:
        result_message = send_message_telegram("Congrats! You have configured successfully the integration with Telegram!",args.send_message[0])
        if result_message[0]:
            print(f"Congrats! A test message was sent to {args.send_message[0]}. Check your Telegram bot")
        else:
            print(f"Error! A test message was not sent to {args.send_message[0]} - {result_message[1]}")
