from typing import Final #Allows gradual (static & dynamic) typing
import os
from responses import get_response
from dotenv import load_dotenv
from discord import Intents, Client, Message

#Load token
load_dotenv()
TOKEN: Final[str] = os.getenv('DISCORD_TOKEN')
print(TOKEN)

#Bot Setup
#"Intents" specify the events/data the bot can access.
#"Client" represents a connection to the Discord API, responsible for handling events/tracking states
intents: Intents = Intents.default()
intents.message_content = True 
client: Client = Client(intents=intents)

#Message Functionality:
async def send_message(message: Message, user_message: str) -> None:
    if not user_message:
        print('Message was empty likely because intents were not enabled')
        return
    
    if is_private := user_message[0] == "?":
        user_message = user_message[1:]

    try:
        response: str = get_response(user_message)
        await message.author.send(response) if is_private else await message.channel.send(response)
    except Exception as e:
        print(e)

#Handle Bot Startup
@client.event
async def on_ready() -> None:
    print(f'{client.user} is now running')

@client.event
async def on_message(message: Message) -> None:
    if message.author == client.user: #If bot is the one who wrote the message
        return
    username: str = str(message.author)
    user_message: str = message.content
    channel: str = str(message.channel)

    print(f'[{channel}] {username}: "{user_message}"')

    await send_message(message, user_message)

#Main Entry Point
def main() -> None:
    client.run(token=TOKEN)

if __name__ == '__main__':
    main()