from LifeLineServer import app, socket

# Runserver
if __name__ == "__main__":
    socket.run(app, debug=True)
    # app.run(debug=True)
