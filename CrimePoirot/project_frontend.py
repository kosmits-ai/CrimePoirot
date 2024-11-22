import tkinter as tk
import subprocess
import webbrowser
from tkinter import ttk

def open_link(url):
    """
    Open the specified URL in the default web browser.
    """
    webbrowser.open_new(url)

def custom_message_with_link(title, message, link_text, link_url):
    """
    Create a custom message window with a hyperlink.
    """
    message_window = tk.Toplevel()
    message_window.title(title)
    message_window.geometry("500x300")
    message_window.config(bg="#003300")

    frame = tk.Frame(message_window, bg="#f0f0f0", padx=20, pady=20, relief="solid", borderwidth=2)
    frame.pack(expand=True, fill="both", padx=10, pady=10)

    message_label = tk.Label(
        frame,
        text=message,
        font=("Helvetica", 14),
        bg="#f0f0f0",
        fg="#003300",
        justify="center",
        wraplength=450
    )
    message_label.pack(pady=(10, 5))

    link_label = tk.Label(
        frame,
        text=link_text,
        font=("Helvetica", 14, "underline"),
        fg="blue",
        bg="#f0f0f0",
        cursor="hand2"
    )
    link_label.pack(pady=(5, 10))
    link_label.bind("<Button-1>", lambda e: open_link(link_url))

    close_button = tk.Button(
        message_window,
        text="Close",
        font=("Helvetica", 12),
        bg="#818580",
        fg="white",
        command=message_window.destroy
    )
    close_button.pack(pady=10)

from threading import Thread
import subprocess
import tkinter as tk

def run_scripts_in_window(repo_url, output_text):
    """
    Runs scripts and displays the output in the Text widget in real-time.
    """
    try:
        scripts = ["main.py", "mongo_handler.py", "csv_handler.py"]

        for script in scripts:
            output_text.insert(tk.END, f"Running {script}...\n")
            output_text.see(tk.END)  # Scroll to the end

            if script == "main.py":
                # Pass repo URL as input for interactive behavior
                process = subprocess.Popen(
                    ["python3", script],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(input=repo_url)
            else:
                # Non-interactive scripts
                process = subprocess.Popen(
                    ["python3", script],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate()

            # Display script status
            if process.returncode == 0:
                output_text.insert(tk.END, f"{script} successfully run.\n")
            else:
                output_text.insert(tk.END, f"{script} failed.\n", "error")
                output_text.insert(tk.END, f"Error in {script}:\n{stderr}\n", "error")
                break

            # Print result of csv_handler.py only
            if script == "csv_handler.py" and stdout:
                output_text.insert(tk.END, "\n--- Result of csv_handler.py ---\n")
                output_text.insert(tk.END, stdout + "\n")
                output_text.insert(tk.END, "--------------------------------\n")
                output_text.see(tk.END)  # Scroll to the end

    except Exception as e:
        output_text.insert(tk.END, f"Error running scripts: {e}\n", "error")



def open_output_window(repo_url):
    """
    Opens a new window to display the terminal output of the scripts.
    """
    output_window = tk.Toplevel()
    output_window.title("Script Output")
    output_window.geometry("700x500")
    output_window.config(bg="#003300")

    # Add a text widget to display output
    output_text = tk.Text(
        output_window,
        wrap="word",
        font=("Courier", 12),
        bg="black",
        fg="white"
    )
    output_text.pack(padx=10, pady=10, fill="both", expand=True)

    # Add tags for styling error and success messages
    output_text.tag_config("error", foreground="red")
    output_text.tag_config("success", foreground="green")

    # Run the scripts in a separate thread to keep the UI responsive
    thread = Thread(target=run_scripts_in_window, args=(repo_url, output_text), daemon=True)
    thread.start()

    # Add a button to terminate the GUI
    terminate_button = tk.Button(
        output_window,
        text="Terminate GUI",
        font=("Helvetica", 12),
        bg="#818580",
        fg="white",
        command=output_window.destroy  # Close the output window
    )
    terminate_button.pack(pady=10)


def open_url_window():
    """
    Opens the URL input window.
    """
    welcome_window.withdraw()

    url_window = tk.Toplevel()
    url_window.title("Enter GitHub Repository URL")
    url_window.geometry("600x400")
    url_window.config(bg="#003300")

    instructions_label = tk.Label(
        url_window,
        text="Enter GitHub Repository URL:",
        font=("Helvetica", 14, "bold"),
        fg="white",
        bg="#003300"
    )
    instructions_label.pack(pady=20)

    url_entry = tk.Text(url_window, height=2, width=50, font=("Helvetica", 12))
    url_entry.pack(pady=10)

    def handle_submit():
        repo_url = url_entry.get("1.0", tk.END).strip()
        if repo_url:
            url_window.destroy()
            open_output_window(repo_url)
        else:
            tk.messagebox.showwarning("Input Error", "Please enter a valid URL.")

    submit_button = tk.Button(
        url_window,
        text="Run Scripts",
        font=("Helvetica", 12),
        bg="#006400",
        fg="white",
        command=handle_submit
    )
    submit_button.pack(pady=20)

    def go_back():
        url_window.destroy()
        welcome_window.deiconify()

    back_button = tk.Button(
        url_window,
        text="Back",
        font=("Helvetica", 12),
        bg="#818580",
        fg="white",
        command=go_back
    )
    back_button.pack(pady=10)

def open_info_window():
    """
    Open the info window with project details and a hyperlink.
    """
    custom_message_with_link(
        title="About This Tool",
        message="This tool was developed as part of a diploma thesis to analyze GitHub repositories for vulnerabilities and malware.\n\n"
                "For more information, visit the project page:",
        link_text="GitHub Project",
        link_url="https://github.com/kosmits-ai/CrimePoirot/blob/main/README.md"
    )

# Main welcome window
welcome_window = tk.Tk()
welcome_window.title("CrimePoirot - Welcome")
welcome_window.geometry("600x400")
welcome_window.config(bg="#006400")

welcome_label = tk.Label(
    welcome_window,
    text="Hello! Welcome to CrimePoirot",
    font=("Helvetica", 16, "bold"),
    fg="black",
    bg="white"
)
welcome_label.pack(pady=20)

start_button = tk.Button(
    welcome_window,
    text="Start Scanning",
    font=("Helvetica", 14),
    bg="#818580",
    fg="white",
    command=open_url_window
)
start_button.pack(pady=10)

info_button = tk.Button(
    welcome_window,
    text="Info",
    font=("Helvetica", 14),
    bg="#818580",
    fg="white",
    command=open_info_window
)
info_button.pack(pady=10)

welcome_window.mainloop()

