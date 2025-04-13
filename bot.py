import os
import sys
import traceback
import json
import random
import string
import logging
import time
import signal
from flask import Flask, request, jsonify
from discord.ext import commands
from dotenv import load_dotenv
import discord
import requests
from threading import Thread

# Load environment variables
load_dotenv("secret.env")
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))

if not DISCORD_TOKEN:
    raise ValueError("❌ DISCORD_TOKEN is not set in the environment variables.")
if not WEBHOOK_URL:
    logging.warning("⚠️ WEBHOOK_URL is not set. Admin notifications will not work.")

# Setup logging
logging.basicConfig(level=logging.INFO)

# Flask setup
app = Flask(__name__)
LICENSE_FILE = "credentials.json"
ADMIN_FILE = "admins.json"
MACHINE_BINDINGS_FILE = "machine_bindings.json"

def handle_global_exception(exc_type, exc_value, exc_traceback):
    """Handle global exceptions and send error to Discord if necessary."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    error_message = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    logging.error(f"Unhandled exception: {error_message}")
    send_error_to_discord(error_message)

sys.excepthook = handle_global_exception

# License utilities
def generate_license_key():
    """Generate a random license key."""
    return '-'.join(''.join(random.choices(string.ascii_uppercase + string.digits, k=6)) for _ in range(6))

def send_error_to_discord(error_message):
    """Send error notifications to Discord."""
    webhook_url = os.getenv("ERROR_WEBHOOK_URL")
    if not webhook_url:
        print("⚠️ ERROR_WEBHOOK_URL is not set. Cannot send error notifications.")
        return

    payload = {
        "content": f"🚨 **Bot Error:**\n```\n{error_message}\n```"
    }

    try:
        requests.post(webhook_url, json=payload)
    except Exception as e:
        print(f"Failed to send error to Discord: {e}")

def load_licenses():
    """Load licenses from file."""
    if not os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, "w") as f:
            json.dump({}, f)
    with open(LICENSE_FILE, "r") as f:
        return json.load(f)

def save_licenses(data):
    """Save licenses to file."""
    with open(LICENSE_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_admins():
    """Load admin users from file."""
    if os.path.exists(ADMIN_FILE):
        with open(ADMIN_FILE, "r") as f:
            return json.load(f)
    return [ADMIN_ID]

def save_admins():
    """Save admin users to file."""
    with open(ADMIN_FILE, "w") as f:
        json.dump(admins, f, indent=4)

def load_machine_bindings():
    """Load machine bindings from file."""
    if not os.path.exists(MACHINE_BINDINGS_FILE):
        with open(MACHINE_BINDINGS_FILE, "w") as f:
            json.dump({}, f)
    with open(MACHINE_BINDINGS_FILE, "r") as f:
        return json.load(f)

def save_machine_bindings(data):
    """Save machine bindings to file."""
    with open(MACHINE_BINDINGS_FILE, "w") as f:
        json.dump(data, f, indent=4)

admins = load_admins()
machine_bindings = load_machine_bindings()

# Track failed attempts and penalties
failed_attempts = {}
penalty_thresholds = [2, 3, 5, 10, 12]  # Penalty durations in seconds
max_penalty = penalty_thresholds[-1]  # Maximum penalty duration (40 minutes)

banned_users = set()

# Flask routes

@app.route('/verify', methods=['POST'])
def verify():
    """Handle user verification with machine binding."""
    data = request.json
    user_name = data.get("username")
    key = data.get("key")
    machine_id = data.get("machine_id")

    if not user_name or not key or not machine_id:
        return jsonify({"status": "error", "message": "Missing username, key, or machine_id"}), 400

    # Check if the user is banned
    if user_name in banned_users:
        return jsonify({"status": "banned", "penalty": max_penalty, "message": "User is banned."}), 403

    # Check if the user is under penalty
    if user_name in failed_attempts:
        penalty_info = failed_attempts[user_name]
        if penalty_info["penalty_end"] > time.time():
            remaining_time = int(penalty_info["penalty_end"] - time.time())
            return jsonify({"status": "error", "penalty": remaining_time, "message": f"Blocked. Try again in {remaining_time} seconds."}), 429

    # Verify the license key
    licenses = load_licenses()
    if user_name in licenses and licenses[user_name]["key"] == key:
        # Check machine binding
        if user_name not in machine_bindings:
            # First-time binding
            machine_bindings[user_name] = machine_id
            save_machine_bindings(machine_bindings)
        elif machine_bindings[user_name] != machine_id:
            # Machine mismatch
            return jsonify({"status": "denied", "reason": "machine mismatch"}), 403

        # Reset failed attempts on success
        failed_attempts.pop(user_name, None)
        return jsonify({"status": "success"}), 200

    # Increment failed attempts
    failed_attempts.setdefault(user_name, {"count": 0, "penalty_end": 0})
    failed_attempts[user_name]["count"] += 1

    attempt_count = failed_attempts[user_name]["count"]

    # Handle penalties and banning
    if attempt_count > len(penalty_thresholds):  # Sixth failed attempt
        banned_users.add(user_name)  # Ban the user
        if WEBHOOK_URL:
            requests.post(WEBHOOK_URL, json={
                "content": f"🚨 User `{user_name}` has been banned after exceeding maximum failed attempts."
            })
        return jsonify({"status": "banned", "penalty": max_penalty, "message": "User is banned."}), 403

    # Apply penalty for failed attempts
    if attempt_count > 1:
        penalty_index = attempt_count - 2
        penalty_duration = penalty_thresholds[penalty_index]
        failed_attempts[user_name]["penalty_end"] = time.time() + penalty_duration

        # Notify admin of failed attempt
        if WEBHOOK_URL:
            requests.post(WEBHOOK_URL, json={
                "content": f"❌ Failed login attempt for `{user_name}` with key `{key}`"
            })

        return jsonify({"status": "error", "penalty": penalty_duration, "message": f"Blocked. Try again in {penalty_duration} seconds."}), 429

    # Notify admin of first failed attempt
    if WEBHOOK_URL:
        requests.post(WEBHOOK_URL, json={
            "content": f"❌ First failed login attempt for `{user_name}` with key `{key}`"
        })

    return jsonify({"status": "failure", "message": "Invalid license key."}), 401

@app.route('/check_status', methods=['POST'])
def check_status():
    """Check if the machine is still allowed."""
    data = request.json
    user_name = data.get("username")
    machine_id = data.get("machine_id")

    if not user_name or not machine_id:
        return jsonify({"status": "error", "message": "Missing username or machine_id"}), 400

    # Check if the user is banned
    if user_name in banned_users:
        return jsonify({"status": "banned", "message": "User is banned."}), 403

    # Check machine binding
    if user_name in machine_bindings and machine_bindings[user_name] == machine_id:
        return jsonify({"status": "allowed"}), 200

    return jsonify({"status": "denied", "reason": "machine mismatch or not bound"}), 403

@app.route('/all', methods=['GET'])
def show_all():
    """Show all licenses."""
    return jsonify(load_licenses())

# Discord bot setup
intents = discord.Intents.default()
intents.message_content = True  # Required to read messages

bot = commands.Bot(command_prefix='!', intents=intents)

# Check for admin
def is_admin(ctx):
    return ctx.author.id in admins

# Bot events
@bot.event
async def on_ready():
    print(f"✅ Bot is online as {bot.user}")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("❌ Missing required argument. Use `!help` for usage details.")
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"⏳ Command is on cooldown. Try again in {round(error.retry_after, 2)} seconds.")
    elif isinstance(error, commands.CommandNotFound):
        await ctx.send("❌ Invalid command.")
    else:
        logging.error(f"An error occurred: {error}")
        await ctx.send("❌ An unexpected error occurred.")

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    return jsonify({"status": "error", "message": "Internal server error"}), 500        


# Commands

# Remove the default help command
bot.remove_command("help")

@bot.command(name='help')
async def custom_help(ctx):
    """
    Custom help command that lists all available bot commands.
    """
    help_text = """
    ℹ️ **Bot Commands**:
    - `!generate <username>`: Generate a license for a user.
    - `!delete_license <username>`: Delete a user's license.
    - `!list_licenses [page]`: List all licenses (paginated).
    - `!reset_penalty <username>`: Reset a user's penalty.
    - `!update_license <username> <new_key>`: Update a user's license key.
    - `!check_license <username>`: Check a user's license.
    - `!clear_licenses`: Clear all licenses.
    - `!export_licenses`: Export licenses to a backup file.
    - `!import_licenses`: Import licenses from a backup file.
    - `!failed_attempts <username>`: View failed attempts for a user.
    - `!stats`: View system statistics.
    - `!list_admins`: List all admins.
    - `!add_admin <new_admin_id>`: Add a new admin.
    - `!remove_admin <admin_id>`: Remove an admin.
    - `!clear_chat [limit]`: Clear messages in the current channel.
    - `!help_admin`: List all admin-specific commands.
    - `!view_banned_users`: View banned users.
    - `!unban_user <username>`: Unban a user.
    - `!ban_user <username>`: Ban a user.
    """
    await ctx.send(help_text)

@bot.command(name='generate')
async def generate_license(ctx, username: str):
    """Generate a license for a user."""     
    licenses = load_licenses()
    if username in licenses:
        await ctx.send(f"❌ User `{username}` already has a license.")
        return

    license_key = generate_license_key()
    licenses[username] = {"key": license_key}
    save_licenses(licenses)
    await ctx.send(f"✅ License generated for `{username}`: `{license_key}`")    


@bot.command(name='delete_license')
async def delete_license(ctx, username: str):
    """Delete a user's license."""
    licenses = load_licenses()
    if username not in licenses:
        await ctx.send(f"❌ No license found for `{username}`.")
        return

    del licenses[username]
    save_licenses(licenses)
    await ctx.send(f"✅ License for `{username}` has been deleted.")

@bot.command(name='list_licenses')
async def list_licenses(ctx, page: int = 1):
    """List all licenses (paginated)."""
    licenses = load_licenses()
    items_per_page = 10
    total_pages = (len(licenses) + items_per_page - 1) // items_per_page
    if page < 1 or page > total_pages:
        await ctx.send(f"❌ Invalid page number. There are {total_pages} pages.")
        return

    start = (page - 1) * items_per_page
    end = start + items_per_page
    licenses_list = list(licenses.items())[start:end]
    message = "\n".join([f"`{user}`: `{data['key']}`" for user, data in licenses_list])
    await ctx.send(f"📄 **Licenses (Page {page}/{total_pages}):**\n{message}")

@bot.command(name='reset_penalty')
async def reset_penalty(ctx, username: str):
    """Reset a user's penalty."""
    if username in failed_attempts:
        del failed_attempts[username]
        await ctx.send(f"✅ Penalty for `{username}` has been reset.")
    else:
        await ctx.send(f"❌ No penalty found for `{username}`.")

@bot.command(name='update_license')
async def update_license(ctx, username: str, new_key: str):
    """Update a user's license key."""
    licenses = load_licenses()
    if username not in licenses:
        await ctx.send(f"❌ No license found for `{username}`.")
        return

    licenses[username]["key"] = new_key
    save_licenses(licenses)
    await ctx.send(f"✅ License for `{username}` has been updated to `{new_key}`.")


@bot.command(name='unban_app')
async def diffie_hellman(ctx, p: int, g: int, A: int):
    """
    Perform Diffie-Hellman key exchange.
    Parameters:
    - p: Prime number
    - g: Base
    - A: Client's public key
    """
    try:
        # Server's private key
        b = random.randint(1, p - 1)

        # Compute server's public key
        B = pow(g, b, p)  # B = g^b mod p

        # Compute shared secret
        K = pow(A, b, p)  # K = A^b mod p

        # Send results to the user
        await ctx.send(f"🔑 **Diffie-Hellman Key Exchange Results:**\n"
                       f"- Server's Public Key (B): `{B}`\n"
                       f"- Shared Secret (K): `{K}`")
    except Exception as e:
        await ctx.send(f"❌ An error occurred: {e}")    

@bot.command(name='check_license')
async def check_license(ctx, username: str):
    """Check a user's license."""
    licenses = load_licenses()
    if username in licenses:
        await ctx.send(f"✅ `{username}` has a valid license: `{licenses[username]['key']}`")
    else:
        await ctx.send(f"❌ No license found for `{username}`.")

@bot.command(name='clear_licenses')
async def clear_licenses(ctx):
    """Clear all licenses."""
    save_licenses({})
    await ctx.send("✅ All licenses have been cleared.")

@bot.command(name='export_licenses')
async def export_licenses(ctx):
    """Export licenses to a backup file."""
    licenses = load_licenses()
    backup_file = "licenses_backup.json"
    with open(backup_file, "w") as f:
        json.dump(licenses, f, indent=4)
    await ctx.send(f"✅ Licenses have been exported to `{backup_file}`.")

@bot.command(name='import_licenses')
async def import_licenses(ctx):
    """Import licenses from a backup file."""
    backup_file = "licenses_backup.json"
    if not os.path.exists(backup_file):
        await ctx.send(f"❌ Backup file `{backup_file}` not found.")
        return

    with open(backup_file, "r") as f:
        licenses = json.load(f)
    save_licenses(licenses)
    await ctx.send("✅ Licenses have been imported from the backup file.")

@bot.command(name='failed_attempts')
async def view_failed_attempts(ctx, username: str):
    """View failed attempts for a user."""
    if username in failed_attempts:
        attempts = failed_attempts[username]["count"]
        await ctx.send(f"❌ `{username}` has {attempts} failed attempts.")
    else:
        await ctx.send(f"✅ `{username}` has no failed attempts.")

@bot.command(name='stats')
async def view_stats(ctx):
    """View system statistics."""
    licenses = load_licenses()
    total_licenses = len(licenses)
    total_banned_users = len(banned_users)
    await ctx.send(f"📊 **System Statistics:**\n- Total Licenses: {total_licenses}\n- Banned Users: {total_banned_users}")

@bot.command(name='list_admins')
async def list_admins(ctx):
    """List all admins."""
    await ctx.send(f"👮 **Admins:**\n" + "\n".join([f"- <@{admin}>" for admin in admins]))

@bot.command(name='add_admin')
async def add_admin(ctx, new_admin_id: int):
    """Add a new admin."""
    if new_admin_id in admins:
        await ctx.send(f"❌ User `<@{new_admin_id}>` is already an admin.")
        return

    admins.append(new_admin_id)
    save_admins()
    await ctx.send(f"✅ User `<@{new_admin_id}>` has been added as an admin.")

@bot.command(name='remove_admin')
async def remove_admin(ctx, admin_id: int):
    """Remove an admin."""
    if admin_id not in admins:
        await ctx.send(f"❌ User `<@{admin_id}>` is not an admin.")
        return

    admins.remove(admin_id)
    save_admins()
    await ctx.send(f"✅ User `<@{admin_id}>` has been removed as an admin.")

@bot.command(name='clear_chat')
@commands.has_permissions(manage_messages=True)
async def clear_chat(ctx, limit: int = 100):
    """Clear messages in the current channel."""
    await ctx.channel.purge(limit=limit)
    await ctx.send(f"✅ Cleared {limit} messages.", delete_after=5)

@bot.command(name='help_admin')
async def help_admin(ctx):
    """List all admin-specific commands."""
    admin_help_text = """
    ℹ️ **Admin Commands**:
    - `!list_admins`: List all admins.
    - `!add_admin <new_admin_id>`: Add a new admin.
    - `!remove_admin <admin_id>`: Remove an admin.
    - `!clear_chat [limit]`: Clear messages in the current channel.
    """
    await ctx.send(admin_help_text)

@bot.command(name='view_banned_users')
async def view_banned_users(ctx):
    """View banned users."""
    if banned_users:
        await ctx.send(f"🚫 **Banned Users:**\n" + "\n".join(banned_users))
    else:
        await ctx.send("✅ No users are currently banned.")

@bot.command(name='unban_user')
async def unban_user(ctx, username: str):
    """Unban a user."""
    if username in banned_users:
        banned_users.remove(username)
        await ctx.send(f"✅ `{username}` has been unbanned.")
    else:
        await ctx.send(f"❌ `{username}` is not banned.")

@bot.command(name='ban_user')
async def ban_user(ctx, username: str):
    """Ban a user."""
    banned_users.add(username)
    await ctx.send(f"🚫 `{username}` has been banned.")

# Start both Flask and Discord bot
def run_flask():
    """Run Flask server."""
    app.run(host="0.0.0.0", port=5000)

def run_discord():
    """Run Discord bot."""
    bot.run(DISCORD_TOKEN)

def shutdown(signal, frame):
    """Shutdown server gracefully."""
    print("Shutting down...")
    os._exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

if __name__ == "__main__":
    Thread(target=run_flask).start()
    run_discord()
