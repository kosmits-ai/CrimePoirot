import tkinter as tk
from tkinter import ttk


def run_scripts(repo_url):
    """
    Function to run the scripts when the user clicks the button.
    """
    try:
        scripts = ["main.py", "mongo_handler.py", "csv_handler.py"]

        for script in scripts:
            print(f"Running {script}...")
            if script == "main.py":
                # Pass repo URL as input for interactive behavior
                result = subprocess.run(["python3", script], input=repo_url, text=True)
            else:
                # Standard behavior for non-interactive scripts
                result = subprocess.run(["python3", script], capture_output=True, text=True)

            if result.returncode != 0:
                print(f"{script} failed! Error:\n{result.stderr}")
                return False

        print("All scripts executed successfully.")
        return True
    except Exception as e:
        print(f"Error running scripts: {e}")
        return False


def open_url_window():
    """
    Opens the second window to enter the GitHub repo URL.
    """
    welcome_window.withdraw()  # Close the welcome window

    # Create the URL input window
    url_window = tk.Toplevel()
    url_window.title("Enter GitHub Repository URL")
    url_window.geometry("600x400")
    url_window.config(bg="#003300")  # Darker green background

    # Add instructions label
    instructions_label = tk.Label(
        url_window,
        text="Enter GitHub Repository URL:",
        font=("Helvetica", 14, "bold"),
        fg="white",
        bg="#003300"
    )
    instructions_label.pack(pady=20)

    # Add a text area for URL input
    url_entry = tk.Text(url_window, height=2, width=50, font=("Helvetica", 12))
    url_entry.pack(pady=10)

    # Function to handle the submission
    def handle_submit():
        repo_url = url_entry.get("1.0", tk.END).strip()
        if repo_url:
            print(f"Processing URL: {repo_url}")  # Replace with actual script execution
            tk.messagebox.showinfo("Success", "Scripts executed successfully!")
        else:
            tk.messagebox.showwarning("Input Error", "Please enter a valid URL.")

    # Add a submit button
    submit_button = tk.Button(
        url_window,
        text="Run Scripts",
        font=("Helvetica", 12),
        bg="#006400",
        fg="white",
        command=handle_submit
    )
    submit_button.pack(pady=20)

    # Function to handle going back to the welcome window
    def go_back(url_window):
        url_window.destroy()  # Close the URL window
        welcome_window.deiconify()  # Show the welcome window again

    # Add a "Back" button to return to the welcome window
    back_button = tk.Button(
        url_window,
        text="Back",
        font=("Helvetica", 12),
        bg="#818580",
        fg="white",
        command=lambda: go_back(url_window)  # Pass url_window to go_back function
    )
    back_button.pack(pady=10)


def open_info_window():
    welcome_window.withdraw()  # Hide welcome window
    info_window = tk.Toplevel()  # Create new info window
    info_window.title("Information about the project")
    info_window.geometry("600x400")  # Set window size
    info_window.config(bg="#000000")  # Green background

    # Info text for the project
    # Bold Label
    title_label = tk.Label(
        info_window,
        text="Detecting Vulnerabilities/Malware with Python",
        font=("Helvetica", 14, "bold"),  # Bold font
        bg="#003300",
        fg="white"
    )
    title_label.pack(pady=(20, 10))  # Add some space below

# Regular Label
    info_label = tk.Label(
        info_window,
        text=(
        "I used four open source projects from GitHub:\n"
        "1. GitLeaks: Secret Detection (e.g., passwords, API keys, tokens).\n"
        "2. Guarddog: Identifies supply chain risks in Python dependencies.\n"
        "3. Safety: Checks dependencies for known vulnerabilities.\n"
        "4. Bearer: Scans codebases for sensitive data exposure.\n\n"
        "This tool combines the findings of these tools to calculate a\n"
        "repository trust score based on vulnerability metrics."
    ),
        font=("Helvetica", 14),  # Regular font
        bg="#003300",
        fg="white",
        justify="left"
)
    info_label.pack(pady=(0, 20))


    # Function to go back to the welcome window
    def go_back(info_window):
        info_window.destroy()  # Close the info window
        welcome_window.deiconify()  # Show the welcome window again

    # Add "Back" button
    back_button = tk.Button(
        info_window,
        text="Back",
        font=("Helvetica", 14),
        bg="#818580",
        fg="white",
        command=lambda: go_back(info_window)
    )
    back_button.pack(pady=20)


# Main welcome window
welcome_window = tk.Tk()
welcome_window.title("CrimePoirot - Welcome")
welcome_window.geometry("600x400")  # Set window size
welcome_window.config(bg="#006400")  # Dark green background

# Define shorter width for the outlines
outline_width = 378  # Shorter than the label's width

# Create a top outline above the label
top_outline = tk.Frame(welcome_window, bg="#818580", height=5, width=outline_width)
top_outline.pack(pady=(30, 0))  # Add space above

# Add the welcome label
welcome_label = tk.Label(
    welcome_window,
    text="Hello! Welcome to CrimePoirot",
    font=("Helvetica", 16, "bold"),
    fg="black",  # Text color
    bg="white"  # Background inside the label
)
welcome_label.pack()

# Create a bottom outline below the label
bottom_outline = tk.Frame(welcome_window, bg="#818580", height=5, width=outline_width)
bottom_outline.pack(pady=(0, 30))  # Add space below

# Add a button below the label to proceed
click_button = tk.Button(
    welcome_window,
    text="Start scanning",
    font=("Helvetica", 14),
    bg="#818580",
    fg="white",
    command=open_url_window
)
click_button.pack()

# Create "Info" button
info_button = tk.Button(
    welcome_window,
    text="Info",
    font=("Helvetica", 14),
    bg="#818580",
    fg="white",
    command=open_info_window
)
info_button.pack(pady=20)

# Run the Tkinter event loop
welcome_window.mainloop()
