from flask_socketio import emit, send, disconnect
from flask import request
from LifeLineServer import *

socket_distribution_object = {"obstructions":[], "driver_routes":[], "driver_gps":[], "traffic_gps":[]}
#ignore last ma garne 

@socket.on('connect')
def handle_connect():
    send(socket_distribution_object)

@socket.on('obstruction')
def handle_obstruction(data):
    operation = data['operation']
    obstruction = data['obstruction']
    if operation == 'create':
        # print('Obstruvtion: ' + str(data['obstruction']))
        socket_distribution_object["obstructions"].append(data['obstruction'])
    elif operation == 'delete':
        # print('Obstruvtion: ' + str(data['obstruction']))
        for i in range(len(socket_distribution_object["obstructions"])):
            if socket_distribution_object["obstructions"][i]['properties']['id'] == obstruction['properties']['id'] and socket_distribution_object["obstructions"][i]['properties']['contact'] == obstruction['properties']['contact']:
                del socket_distribution_object["obstructions"][i] 
                break
    elif operation == 'update':
        # print('Obstruvtion: ' + str(data['obstruction']))
        for i in range(len(socket_distribution_object["obstructions"])):
            if socket_distribution_object["obstructions"][i]['properties']['id'] == obstruction['properties']['id'] and socket_distribution_object["obstructions"][i]['properties']['contact'] == obstruction['properties']['contact']:
                del socket_distribution_object["obstructions"][i] 
                break
            socket_distribution_object["obstructions"].append(data['obstruction'])
    print()
    print(socket_distribution_object['obstructions'])
    emit('obstruction', socket_distribution_object['obstructions'], broadcast=True)


@socket.on('driver_route')
def handle_route(data):
    operation = data['operation']
    driver_route = data['driver_route']
    if operation == 'create':
        print('Add Driver route: ' + str(data['driver_route']))
        socket_distribution_object["driver_routes"].append(driver_route)
    elif operation == 'delete':
        print('Delete Driver route: ' + str(data['driver_route']))
        socket_distribution_object["driver_routes"].remove(driver_route)
    elif operation == 'update':
        print('Update Driver route: ' + str(data['driver_route']))
        for i in range(len(socket_distribution_object["driver_routes"])): 
            if socket_distribution_object["driver_routes"][i]['properties']['contact'] == driver_route['properties']['contact']: 
                del socket_distribution_object["driver_routes"][i] 
                break
        socket_distribution_object["driver_routes"].append(driver_route)
    print()
    print('driver_route',socket_distribution_object['driver_routes'])
    emit('driver_route',socket_distribution_object["driver_routes"], json=True, broadcast=True, include_self=False)
    
@socket.on('driver_gps')
def handle_driver_gps(data):
    print()
    operation = data['operation']
    driver_gps = data['driver_gps']
    if operation == 'create':
        print('Add Driver gps: ' + str(data['driver_gps']))
        socket_distribution_object["driver_gps"].append(driver_gps)
    elif operation == 'delete':
        print('Delete Driver gps: ' + str(data['driver_gps']))
        socket_distribution_object["driver_gps"].remove(driver_gps)
    elif operation == 'update':
        # print('Update Driver gps: ' + str(data['driver_gps']))
        for i in range(len(socket_distribution_object["driver_gps"])): 
            if socket_distribution_object["driver_gps"][i]['properties']['contact'] == driver_gps['properties']['contact']: 
                del socket_distribution_object["driver_gps"][i] 
                break
        socket_distribution_object["driver_gps"].append(driver_gps)
    print()
    print('driver_gps',socket_distribution_object['driver_gps'])
    emit('driver_gps', socket_distribution_object["driver_gps"], json=True, broadcast=True, include_self=False)


@socket.on('traffic_gps')
def handle_traffic_gps(data):

    print()
    operation = data['operation']
    traffic_gps = data['traffic_gps']
    if operation == 'create':
        # print('Add Traffic gps: ' + str(data['traffic_gps']))
        socket_distribution_object["traffic_gps"].append(traffic_gps)
    elif operation == 'delete':
        # print('Delete Traffic gps: ' + str(data['traffic_gps']))
        socket_distribution_object["traffic_gps"].remove(traffic_gps)
    elif operation == 'update':
        # print('Update Traffic gps: ' + str(data['traffic_gps']))
        for i in range(len(socket_distribution_object["traffic_gps"])): 
            if socket_distribution_object["traffic_gps"][i]['properties']['contact'] == traffic_gps['properties']['contact']: 
                del socket_distribution_object["traffic_gps"][i] 
                break
        socket_distribution_object["traffic_gps"].append(traffic_gps)
    print()
    print('traffic_gps',socket_distribution_object['traffic_gps'])
    emit('traffic_gps', socket_distribution_object["traffic_gps"], json=True, broadcast=True, include_self=False)

    
@socket.on('disconnect')
def test_disconnect():
    print(request.remote_addr)