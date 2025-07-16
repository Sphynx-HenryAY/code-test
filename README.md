# intructions
- install required modules listed in file `requirements` by `pip install -r requirements`, make sure you choose the pip matches to the python executable you use in later steps. or a better way is creating a virtual environment beforehand.
- copy file `env.example` and rename it as `.env`
- add your abuse ip db API key to `.env` file
- navigate to the folder and then call the script through `python ip_rep_filtering.py`


# requirements
## python version
- 3.6+ for f-string support

## modules
- requests
- dotenv
