from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

from algosdk.v2client import indexer
from algosdk import mnemonic
from web3 import Web3

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    g.session.add(Log(message = msg))
    g.session.commit()

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    mnemonic_secret = "dose palace garage night heavy battle position civil summer asset fat copper erode honey extend pizza sleep robot trim scare blouse flock double abandon tortoise"
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    
    return algo_sk, algo_pk

def get_eth_keys(filename = "eth_mnemonic.txt"):

    IP_ADDR='18.188.235.196'
    PORT='8545'

    w3 = Web3(Web3.HTTPProvider('http://' + IP_ADDR + ':' + PORT))
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys

    mnemonic_secret = "clutch oval meadow vast slush burger swallow air garden urban zebra about"
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key

    return eth_sk, eth_pk
  
def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

	# If your fill_order function is recursive, and you want to have fill_order return a list of transactions to be filled, 
	# Then you can use the "txes" argument to pass the current list of txes down the recursion
	# Note: your fill_order function is *not* required to be recursive, and it is *not* required that it return a list of transactions, 
	# but executing a group of transactions can be more efficient, and gets around the Ethereum nonce issue described in the instructions
    
    dt = datetime.now()
    order.timestamp = dt
    order.filled = datetime(2222, 2, 2)
    g.session.add(order)
    g.session.commit()
    
    tx = {'amount': order.sell_amount, 'platform': order.sell_currency, 'receiver_pk': order.receiver_pk, 'order_id': order.id, 'tx_id': None} # tx_id to be assigned later when the transaction is executed
    txes.append(tx)
        
    #2.    Check if there are any existing orders that match. 
    orders = g.session.query(Order).filter(Order.filled == datetime(2222, 2, 2)).all() #Get all unfilled orders
    for existing_order in orders:
      if (existing_order.buy_currency == order.sell_currency and 
        existing_order.sell_currency == order.buy_currency and 
        float(existing_order.sell_amount)/float(existing_order.buy_amount) > float(order.buy_amount)/float(order.sell_amount)): #match
        #print("matched")
    
        #3.    If a match is found between order and existing_order:
        #– Set the filled field to be the current timestamp on both orders
        dt = datetime.now()
        existing_order.filled = dt
        order.filled = dt
        
        #– Set counterparty_id to be the id of the other order
        existing_order.counterparty_id = order.id
        order.counterparty_id = existing_order.id
        existing_order.counterparty = [order]
        order.counterparty = [existing_order]
        g.session.commit()
        #print("order.id:", order.id)
        #print("existing_order.id:", existing_order.id)        

        #– If one of the orders is not completely filled (i.e. the counterparty’s sell_amount is less than buy_amount):
        if existing_order.buy_amount < order.sell_amount: #this order is not completely filled
          parent_order = order
          buy_amount = order.buy_amount - existing_order.sell_amount
          sell_amount = order.sell_amount - existing_order.buy_amount
        elif order.buy_amount < existing_order.sell_amount: #existing_order is not completely filled
          parent_order = existing_order
          buy_amount = existing_order.buy_amount - order.sell_amount
          sell_amount = existing_order.sell_amount - order.buy_amount
        else:
          return

        if buy_amount==0 or sell_amount==0:
          return
        
        #o    Create a new order for remaining balance
        child_order = {} #new dict
        child_order['buy_amount'] = buy_amount
        child_order['sell_amount'] = sell_amount
        child_order['buy_currency'] = parent_order.buy_currency
        child_order['sell_currency'] = parent_order.sell_currency
        
        #o    The new order should have the created_by field set to the id of its parent order
        child_order['creator_id'] = parent_order.id
        print("parent_order.id:", parent_order.id)
        
        #o    The new order should have the same pk and platform as its parent order
        child_order['sender_pk'] = parent_order.sender_pk
        child_order['receiver_pk'] = parent_order.receiver_pk
        
        #o    The sell_amount of the new order can be any value such that the implied exchange rate of the new order is at least that of the old order
        #o    You can then try to fill the new order
        corder = Order(**{f:child_order[f] for f in child_order})
        fill_order(corder, txes)
        
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    tx_ids = send_tokens_algo(g.acl, algo_sk, algo_txes)
    for tx in algo_txes:
        t = {'platform': 'Algorand', 'receiver_pk': tx['receiver_pk'], 'order_id': tx['order_id'], 'tx_id': tx['tx_id']}
        tx = TX(**{f:t[f] for f in t})
        g.session.add(tx)
        g.session.commit()

    tx_ids = send_tokens_eth(g.w3, eth_sk, eth_txes)
    for tx in eth_txes:
        t = {'platform': 'Ethereum', 'receiver_pk': tx['receiver_pk'], 'order_id': tx['order_id'], 'tx_id': tx['tx_id']}
        tx = TX(**{f:t[f] for f in t})
        g.session.add(tx)
        g.session.commit()
 
""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            return jsonify( "0xB7F6617dc26C3C609c8837E45eE9D061Eb7a9D9b" )
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk, algo_pk = get_algo_keys()
            #Public Algorand Address: 63G6Z6H5OD24CV5XKKECHPPW6TYFITKLNWHIOFMURKP6Q5DMK3N5BYLXHM
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        sig = content['sig']
        payload = content['payload']
        payload_pk = payload['sender_pk']
        
        if payload['platform'] == 'Algorand':
            sig_valid = algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), sig, payload_pk)
        else:
            eth_encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
            sig_valid = eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == payload_pk
        
        # 1. Check the signature
        if sig_valid:
            del payload['platform']
            payload['signature'] = sig
            order = Order(**{f:payload[f] for f in payload})
            
            # 2. Add the order to the table
            
            # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            if order.sell_currency == "Ethereum":
                tx = w3.eth.get_transaction(payload['tx_id'])
                if tx is None or tx["value"] != order.sell_amount:
                    return jsonify(False)
            elif order.sell_currency == "Algorand":
                tx = indexer.search_transaction(txid=payload['tx_id'])
                if tx is None or tx.amt != order.sell_amount:
                    return jsonify(False)

            # 3b. Fill the order (as in Exchange Server II) if the order is valid
            txes = []
            fill_order(order, txes)
            
            # 4. Execute the transactions
            execute_txes(txes)
            
            return jsonify(True) # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful

        else:  #If the signature does not verify, do not insert the order into the “Order” table. Instead, insert a record into the “Log” table, with the message field set to be json.dumps(payload).
            print('signature does not verify')
            log_message(payload)
            return jsonify(False) # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful

    return jsonify(True)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk" ]
    
    # Same as before
    l = []
    orders = g.session.query(Order).all()
    for order in orders:
        d = {"buy_currency": order.buy_currency, "sell_currency": order.sell_currency, "buy_amount": order.buy_amount, "sell_amount": order.sell_amount, "signature": order.signature, "tx_id": order.tx_id, "receiver_pk": order.receiver_pk, "sender_pk": order.sender_pk}
        l.append(d)
    result = {'data': l}
    return jsonify(data=result)

if __name__ == '__main__':
    app.run(port='5002')
