the backend app.py must be running to use those features in the code
Open your terminal and cd into that folder.

Create a Virtual Environment (Recommended):
# On Windows
python -m venv venv
.\venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
4.  **Install dependencies:** You'll need `Flask` and the other libraries.
```bash
pip install Flask flask-cors pyjwt bcrypt
5.  **Run the server:**
```bash
python app.py
