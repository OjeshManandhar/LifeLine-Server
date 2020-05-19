from flask_socketio import emit, send

socket_distribution_object = {"obstructions":[], "driver_path":{}, "driver_gps":{}}

@socket.on('obstruction')
def handle_obstruction(obstruction):
    print('Obstruvtion: ' + str(obstruction))
    socket_distribution_object["obstructions"].append(obstruction)
    send(socket_distribution_object, json=True, broadcast=True)

@socket.on('driver_route')
def handle_route(driver_route):
    print('driver_route: ' + str(driver_route))
    socket_distribution_object["driver_path"]= driver_route
    send(socket_distribution_object, json=True, broadcast=True)
    

@socket.on('driver_gps')
def handle_gps(driver_gps):
    print('driver_gps: ' + str(driver_gps))
    socket_distribution_object["driver_gps"] = driver_gps
    send(socket_distribution_object, json=True, broadcast=True)