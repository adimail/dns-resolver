from flask import Flask

app = Flask(__name__)

# Set the SERVER_NAME to include the subdomain and port
app.config['SERVER_NAME'] = 'socks.localhost:3000'

@app.route('/')
def home():
    return 'You can add subdomains on localhost!'

if __name__ == '__main__':
    app.run(host='socks.localhost', port=3000)

