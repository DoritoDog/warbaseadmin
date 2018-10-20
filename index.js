var http = require('http');
var Web3 = require('web3');
var tx = require('ethereumjs-tx');
var util = require('ethereumjs-util');
var lightwallet = require('eth-lightwallet');
var txutils = lightwallet.txutils;
const abiDecoder = require('abi-decoder');
var BigNumber = require('bignumber.js');
var PlayFab = require("playfab-sdk/Scripts/PlayFab/PlayFab");
var PlayFabServer = require("playfab-sdk/Scripts/PlayFab/PlayFabServer");
var PlayFabClient = require("playfab-sdk/Scripts/PlayFab/PlayFabClient");
var express = require('express');
var app = express();
var mySQL = require("mysql");
var bodyParser = require('body-parser');
var fs = require('fs');
const LINQ = require('node-linq').LINQ;
require('dotenv').load();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.set('port', (process.env.PORT));
app.use(express.static(__dirname + '/public'));

app.post('/', function(req, res) {
	if (typeof req.body.trade !== 'undefined' && req.body.trade) {
		var trade = JSON.parse(req.body.trade);
		openTrade(trade, res);
	} else if (typeof req.body.acceptTrade !== 'undefined' && req.body.acceptTrade) {
		acceptTrade(JSON.parse(req.body.acceptTrade));
	} else if (typeof req.body.tokenReciept !== 'undefined' && req.body.tokenReciept) {
		validateReciept(req.body.tokenReciept, true);
	} else if (typeof req.body.ethReciept !== 'undefined' && req.body.ethReciept) {
		validateReciept(req.body.ethReciept, false);
	} else if (typeof req.body.deleteTrade !== 'undefinded' && req.body.deleteTrade) {
		deleteTrade(req.body.deleteTrade, req.body.ticket);
	}

	if (typeof(req.body.listRequest !== 'undefined' && req.body.listRequest)) {
		createListing(JSON.parse(req.body.listRequest));
	}
	else if (typeof(req.body.marketBuyRequest) !== 'undefined' && req.body.marketBuyRequest) {
		const request = JSON.parse(req.body.marketBuyRequest);
		purchaseMarketItem(request.Id, request.Address, request.PlayFabId);
	}

	res.send('');
});

app.get('/getLastPrices', function(req, res) {
	// For each listing this selects an ItemId and the last price it was sold for.
	var selectSql = 'SELECT market_sales.item_id, (SELECT amount FROM market_sales ORDER BY completed DESC LIMIT 1) AS last_price FROM market_sales GROUP BY market_sales.item_id';

	queryDB(selectSql, [], sales => {
		res.send(sales);
	});
});

app.get('/getListings', function(req, res) {
	queryDB("SELECT * FROM listings", [], dbListings => {

		// Format the listings into the C# class format.
		var listings = [];
		dbListings.forEach(listing => {
			listings.push({
				'Id': listing.id,
				'InstanceId': listing.instance_id,
				'ItemId': listing.item_id,
				'Price': listing.price,
				'PlayFabId': listing.playfab_id,
				'Address': listing.address,
			});
		});

		res.send(listings);
	});
});

app.post('/giveDefault', function(req, res) {
	giveDefaultItemsTo(req.body.playerId);
});

app.listen(app.get('port'), function() {
  console.log("Node app is running at localhost:" + app.get('port'))
});

login();

var web3 = new Web3(new Web3.providers.HttpProvider("https://mainnet.infura.io/MalstqsO7EYyOSLpTUdi"));

var altAccAddress = "0xe11d0DA3835B97Cba7f10970207E1Ebe6d37e355";
var accountAddress = "0x47028de64620FC7A6e70D54574a46F31F3b42eAD";
var contractAddress = '0x62Efbef0B9A22234F65566341eE42791b329A3ed';
var key = process.env.PRIVATE_KEY;

//#region Contract data
var bytecode = "60806040527f6e426173652043727970746f476f6c64000000000000000000000000000000006000557f4e434700000000000000000000000000000000000000000000000000000000006001556002805460ff1916601217905534801561006557600080fd5b50600254606460ff909116600a0a02600381905560048054600160a060020a03338116600160a060020a0319909216919091179182905516600090815260056020526040902055610647806100bb6000396000f3006080604052600436106100ae5763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166306fdde0381146100b3578063095ea7b3146100da57806318160ddd1461011257806323b872dd14610127578063313ce5671461015157806370a082311461017c57806379c650681461019d5780638da5cb5b146101c357806395d89b41146101f4578063a9059cbb14610209578063dd62ed3e1461022d575b600080fd5b3480156100bf57600080fd5b506100c8610254565b60408051918252519081900360200190f35b3480156100e657600080fd5b506100fe600160a060020a036004351660243561025a565b604080519115158252519081900360200190f35b34801561011e57600080fd5b506100c86102c5565b34801561013357600080fd5b506100fe600160a060020a03600435811690602435166044356102cb565b34801561015d57600080fd5b50610166610373565b6040805160ff9092168252519081900360200190f35b34801561018857600080fd5b506100c8600160a060020a036004351661037c565b3480156101a957600080fd5b506101c1600160a060020a0360043516602435610397565b005b3480156101cf57600080fd5b506101d8610499565b60408051600160a060020a039092168252519081900360200190f35b34801561020057600080fd5b506100c86104a8565b34801561021557600080fd5b506100fe600160a060020a03600435166024356104ae565b34801561023957600080fd5b506100c8600160a060020a03600435811690602435166104c4565b60005481565b600160a060020a03338116600081815260066020908152604080832094871680845294825280832086905580518681529051929493927f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925929181900390910190a35060015b92915050565b60035490565b600160a060020a0380841660009081526006602090815260408083203390941683529290529081205482111561030057600080fd5b600160a060020a0380851660009081526006602090815260408083203390941683529290522054610337908363ffffffff6104ef16565b600160a060020a0380861660009081526006602090815260408083203390941683529290522055610369848484610504565b5060019392505050565b60025460ff1681565b600160a060020a031660009081526005602052604090205490565b60045433600160a060020a039081169116146103b257600080fd5b600160a060020a0382166000908152600560205260409020546103db908263ffffffff61060b16565b600160a060020a038316600090815260056020526040902055600354610407908263ffffffff61060b16565b600355600454604080518381529051600160a060020a03909216916000917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef919081900360200190a3600454604080518381529051600160a060020a038086169316917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef919081900360200190a35050565b600454600160a060020a031681565b60015481565b60006104bb338484610504565b50600192915050565b600160a060020a03918216600090815260066020908152604080832093909416825291909152205490565b6000828211156104fe57600080fd5b50900390565b6000600160a060020a038316151561051b57600080fd5b600160a060020a03841660009081526005602052604090205482111561054057600080fd5b600160a060020a0383166000908152600560205260409020548281011161056657600080fd5b50600160a060020a038083166000818152600560209081526040808320805495891680855282852080548981039091559486905281548801909155815187815291519390950194927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef929181900390910190a3600160a060020a0380841660009081526005602052604080822054928716825290205401811461060557fe5b50505050565b818101828110156102bf57600080fd00a165627a7a7230582004de4838c6754bd97154cd0af78485d50db815b65bba632c39011b004b9c03f50029";
var interface = [{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"spender","type":"address"},{"name":"tokens","type":"uint256"}],"name":"approve","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"tokens","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"accountAddress","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"target","type":"address"},{"name":"amount","type":"uint256"}],"name":"mintToken","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"tokens","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"account","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"name":"remaining","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"tokens","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"tokenOwner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"tokens","type":"uint256"}],"name":"Approval","type":"event"}];
//#endregion

var contractDefinition = web3.eth.contract(interface);
var contract = contractDefinition.at(contractAddress);

abiDecoder.addABI(interface);

function sendRaw(rawTx) {
    var privateKey = new Buffer(key, 'hex');
    var transaction = new tx(rawTx);
    transaction.sign(privateKey);
    var serializedTx = transaction.serialize().toString('hex');
    web3.eth.sendRawTransaction(
    '0x' + serializedTx, function(err, result) {
        if(err) {
            console.log(err);
        } else {
            console.log(result);
        }
    });
}

function sendTokens(address, amount) {
	var txOptions = {
		nonce: web3.toHex(web3.eth.getTransactionCount(accountAddress)),
		gasLimit: web3.toHex(800000),
		gasPrice: web3.toHex(20000000000),
		to: contractAddress
	};

	var rawTx = txutils.functionTx(interface, "transfer", [address, amount], txOptions);
	sendRaw(rawTx);
}

function sendTx(functionName, args) {
	var txOptions = {
		nonce: web3.toHex(web3.eth.getTransactionCount(accountAddress)),
		gasLimit: web3.toHex(800000),
		gasPrice: web3.toHex(20000000000),
		to: contractAddress
	};

	var rawTx = txutils.functionTx(interface, functionName, args, txOptions);
	sendRaw(rawTx);
}

function getBalance(address) {
	var storedData = contract.balanceOf(address);
	console.log(storedData.toString());
}

function mintTokens(target, amountInput) {
	var amount = new BigNumber(amountInput);
	var txOptions = {
		nonce: web3.toHex(web3.eth.getTransactionCount(accountAddress)),
		gasLimit: web3.toHex(800000),
		gasPrice: web3.toHex(20000000000),
		to: contractAddress
	};

	var rawTx = txutils.functionTx(interface, "mintToken", [target, amount], txOptions);
	sendRaw(rawTx);
}

function login() {
	PlayFab.settings.titleId = '194';
    var loginRequest = {
        CustomId: process.env.PF_CUSTOM_ID,
        CreateAccount: true
    };

    PlayFabClient.LoginWithCustomID(loginRequest, function(error, result) {
		if (result !== null) {
			console.log("Logged in.");
		} else if (error !== null) {
			onPlayFabError(error);
		}
	});
}

function openTrade(trade, res) {
	console.log(JSON.stringify(trade));
	var authRequest = { SessionTicket: trade.sessionTicket };
	PlayFabServer.AuthenticateSessionTicket(authRequest, function(error, result) {
		if (error) {
			console.log(trade.sessionTicket);
			onPlayFabError(error);
			return;
		} else {
			// Don't let players open trades that offer more cryptocurrency than they have approved.
			var address = getAddress(trade.playerKey);
			var allowance = contract.allowance(address, accountAddress);
			var offeredTokens = web3.toWei(trade.offeredCryptocurrency);
			if (allowance.lt(offeredTokens))
			{
				console.log("Allowance: " + allowance.toString());
				console.log("Offered: " + offeredTokens);
				return;
			}

			// Check if the player has all the items they are offering
			PlayFabServer.GetUserInventory({PlayFabId: trade.playerID}, function(error, result) {
				var inventory = result.data.Inventory;
				for (var i = 0; i < trade.offeredItems.length; i++) {
					if (!inventoryContainsInstanceId(trade.offeredItems[i].instanceID, inventory))
					{
						console.log("The inventory doesn't contain an InstanceId " +
						trade.offeredItems[i].instanceID);
						return;
					}
			}
				
			// Store the items in the DB
			var sql = "INSERT INTO trades (offered_CryptoGold, requested_CryptoGold, address, player_id)" +
			"VALUES ?";
			var values = [[
				trade.offeredCryptocurrency,
				trade.requestedCryptocurrency,
				address,
				trade.playerID
			]];
			queryDB(sql, [values], function (queryResult) {
				tradeID = queryResult.insertId;
				console.log(tradeID);

				for (var i = 0; i < trade.offeredItems.length; i++) {
					var item = trade.offeredItems[i];
					
					var sql = "INSERT INTO offered_items" +
					"(item_instance_ID, item_ID, level, level_value, property, trade_ID) VALUES ?";
					var values = [[item.instanceID, item.itemID, item.level,
								item.levelValue, item.property, tradeID]];
					queryDB(sql, [values], function (queryResult) { });
				}

				for (var i = 0; i < trade.requestedItems.length; i++) {
					var item = trade.requestedItems[i];
					
					var sql = "INSERT INTO requested_items (item_ID, allowed_levels, trade_ID) VALUES ?";
					var values = [[item.catalogID, item.allowedLevels.join(','), tradeID]];
					queryDB(sql, [values], function (queryResult) { });
				}

				res.send(tradeID.toString());
			});

			// Revoke the items
			for (var i = 0; i < trade.offeredItems.length; i++) {
				var item = trade.offeredItems[i];
				var request = {
					ItemInstanceId: item.instanceID,
					PlayFabId: trade.playerID
				};
				
				PlayFabServer.RevokeInventoryItem(request, function(error, result) {
					if (error)
						onPlayFabError(error);
				});
			}
			});
		}
	});
}

function inventoryContainsInstanceId(ID, inventory) {
    for (var i = 0; i < inventory.length; i++) {
		if (inventory[i].ItemInstanceId == ID)
			return true;
	}

	return false;
}

function inventoryContainsItemId(ID, inventory) {
    for (var i = 0; i < inventory.length; i++) {
		if (isContained = inventory[i].ItemId == ID)
			return true;
	}

	return false;
}

function tradeRequests(itemId, requestedItems) {
    for (var i = 0; i < requestedItems.length; i++) {
        console.log(requestedItems[i].item_ID);
        if (requestedItems[i].item_ID == itemId)
            return true;
    }

    return false;
}

function acceptedIDsContainIdAndLevel(item, acceptedItems) {
    for (var i = 0; i < acceptedItems.length; i++) {
        if (acceptedItems[i].itemID == item.item_ID) {
            var allowedLevels = item.allowed_levels.split(',');
            var level = parseInt(acceptedItems[i].level);
            for (var c = 0; c < allowedLevels.length; c++) {
                if (level == allowedLevels[c])
                    return true;
            }
        }
    }

    return false;
}

function acceptTrade(request) {
	var authRequest = { SessionTicket: request.sessionTicket };
    PlayFabServer.AuthenticateSessionTicket(authRequest, function(error, result) {
	if (error) {
		onPlayFabError(error);
		return;
	} else {
		var tradeID = mySQL.escape(request.ID);
		var sql = 'SELECT * FROM requested_items WHERE trade_ID = ' + tradeID;
		queryDB(sql, [], function (result) {
			var requestedItems = result;
	
			var invRequest = {PlayFabId: request.acceptorID};
			PlayFabServer.GetUserInventory(invRequest, function(error, result) {
				// Check if the acceptor has the ItemInstanceIds in his inv.
				for (var i = 0; i < request.acceptedItems.length; i++) {
					var ID = request.acceptedItems[i].instanceID;
					if (!inventoryContainsInstanceId(ID, result.data.Inventory))
						throw "Inventory doesn't contain an InstanceId";
				}
	
				// Check if the accepted items have the correct levels and are requested.
				/*for (var i = 0; i < requestedItems.length; i++) {
					if (!acceptedIDsContainIdAndLevel(requestedItems[i], request.acceptedItems))
						throw "Not all the items have correct levels";
				}*/
	
				// Get the trade from the DB
				var selectSQL = "SELECT * FROM trades WHERE id=" + tradeID;
				var itemsSQL = "SELECT * FROM offered_items WHERE trade_ID=" + tradeID;
				queryDB(selectSQL, [], function(tradeResult) {
					queryDB(itemsSQL, [], function(itemsResult) {
						// completeTrade() is called after this function
						transferTokens(request, tradeResult[0], tradeID);
					});
				});
			});
		});
	}
	});
}

function transferTokens(request, trade, tradeID) {
	// Get the addresses from the private keys.
	var posterAddress = altAccAddress; //trade.address;
	var acceptorAddress = accountAddress; //getAddress(request.acceptorKey);

	// Get their allowances.
	var posterAllowance = contract.allowance(posterAddress, accountAddress);
	var acceptorAllowance = contract.allowance(acceptorAddress, accountAddress);

	// Convert the allowances to wei.
	var offeredCrypto = web3.toWei(trade.offered_CryptoGold, 'ether');
	var requestedCrypto = web3.toWei(trade.requested_CryptoGold, 'ether');

	// Transfer, gte is "greater than or equal to".
	if (posterAllowance.gte(offeredCrypto) && acceptorAllowance.gte(requestedCrypto)) {
		if (trade.offered_CryptoGold > 0) {
			sendTx("transferFrom", [posterAddress, acceptorAddress, offeredCrypto]);
		}
		if (trade.requested_CryptoGold > 0) {
			sendTx("transferFrom", [acceptorAddress, posterAddress, requestedCrypto]);
		}

		var SQL = "SELECT * FROM offered_items WHERE trade_ID=" + tradeID;
		queryDB(SQL, [], function(result) {
			// completeTrade() is called after this function
			completeTrade(request, trade, result, tradeID);
		});
	}
	else {
		console.log("Not enough allowance.");
	}
}

function completeTrade(request, trade, offeredItems, tradeID) {
	// Grant the offered items to the acceptor
	for (var i = 0; i < offeredItems.length; i++) {
		var item = offeredItems[i];
		var grantRequest = {
			ItemIds: [offeredItems[i].item_ID],
			PlayFabId: request.acceptorID
		};
		PlayFabServer.GrantItemsToUser(grantRequest, function(error, result){
			if (error) onPlayFabError(error);
			//#region Old
			/*var dataRequest = {
				ItemInstanceId: result.data.ItemGrantResults[0].ItemInstanceId,
				PlayFabId: request.acceptorID,
				Data: {
					"Value": item.levelValue,
					"Level": item.level,
					"Property": item.property
				  }
			  };
			PlayFabServer.UpdateUserInventoryItemCustomData(dataRequest, function(error, result) {
				if (error) onPlayFabError(error);
			});*/
			//#endregion
		});
	}
	
	// Revoke the acceptor's items and grant them to the poster.
    for	(var i = 0; i < request.acceptedItems.length; i++) {
		var item = request.acceptedItems[i];
		var revokeRequest = {
			ItemInstanceId: request.acceptedItems[i].instanceID,
			PlayFabId: request.acceptorID
		};
		PlayFabServer.RevokeInventoryItem(revokeRequest, function(error, result) {
			if (error) onPlayFabError(error);

			var grantRequest = {
				ItemIds: [item.itemID],
				PlayFabId: trade.player_id
			};
			PlayFabServer.GrantItemsToUser(grantRequest, function(error, result){
				if (error) onPlayFabError(error);

				//#region UpdateCustomData(deletion happened inside)
				/*var dataRequest = {
					ItemInstanceId: result.data.ItemGrantResults[0].ItemInstanceId,
					PlayFabId: trade.player_id,
					Data: {
						"Value": item.levelValue,
						"Level": item.level,
						"Property": item.property
				  	}
				};
				PlayFabServer.UpdateUserInventoryItemCustomData(dataRequest, function(error, result) {
					if (error) onPlayFabError(error);*/

					// Delete the trade from the database.
					
				//});
				//#endregion

				var id = tradeID;
				var SQL = "DELETE FROM offered_items WHERE trade_ID=" + id;
				queryDB(SQL, [], function(result) {
					var SQL = "DELETE FROM requested_items WHERE trade_ID=" + id;
					queryDB(SQL, [], function(result) {
						var SQL = "DELETE FROM trades WHERE id=" + id;
						queryDB(SQL, [], function(result) {
							console.log("Successful trade.");
						});
					});
				});
			});
		});
	}
}

function deleteTrade(ID, ticket) {
	var authRequest = { SessionTicket: ticket };
	PlayFabServer.AuthenticateSessionTicket(authRequest, function(error, result) {
		if (error) {
			onPlayFabError(error);
		} else {
			var id = mySQL.escape(ID);
			
			var SQL = "SELECT * FROM offered_items WHERE trade_ID=" + id;
			queryDB(SQL, [], function(itemsResult) {
				queryDB("SELECT * FROM trades WHERE id="+id, [], function(result) {
					var playerId = result[0].player_id;
		
					var SQL = "DELETE FROM offered_items WHERE trade_ID=" + id;
					queryDB(SQL, [], function(result) {
						var SQL = "DELETE FROM requested_items WHERE trade_ID=" + id;
						queryDB(SQL, [], function(result) {
							var SQL = "DELETE FROM trades WHERE id=" + id;
							queryDB(SQL, [], function(result) {
								completeDelete(playerId, itemsResult);
							});
						});
					});
				});
			});
		}
	});
}

function completeDelete(playerId, offeredItems) {
	for (var i = 0; i < offeredItems.length; i++) {
		var item = offeredItems[i];
		var grantRequest = {
			ItemIds: [offeredItems[i].item_ID],
			PlayFabId: playerId
		};
		PlayFabServer.GrantItemsToUser(grantRequest, function(error, result) {
			var dataRequest = {
				ItemInstanceId: result.data.ItemGrantResults[0].ItemInstanceId,
				PlayFabId: playerId,
				Data: {
					"Value": item.level_value,
					"Level": item.level,
					"Property": item.property
					}
				};
			PlayFabServer.UpdateUserInventoryItemCustomData(dataRequest, function(error, result) {
				if (error) onPlayFabError(error);
			});
		});
	}
}

function getAllowance(account, spender) {
    var amount = contract.allowance(account, spender);
    return amount.c[0];
}

function getAddress(privateKey) {
	privateKey = privateKey.startsWith('0x') ? privateKey : '0x' + privateKey;
	var buffer = util.privateToAddress(privateKey);
	return '0x' + buffer.toString('hex');
}

function onPlayFabError(error) {
    if (error == null)
        return "";
    var fullErrors = error.errorMessage;
    for (var paramName in error.errorDetails)
        for (var msgIdx in error.errorDetails[paramName])
			fullErrors += "\n" + paramName + ": " + error.errorDetails[paramName][msgIdx];
			
    console.log(fullErrors);
}

function queryDB(SQL, args, callback) {
	var connection_config = {
		host: process.env.DB_HOST,
		user: "root",
		password: process.env.DB_PASSWORD,
		database: "game"
	};
	
	var connection = mySQL.createConnection(connection_config);
	connection.connect(function(err) {
		if (err) throw err;

		if (args.length > 0) {
			connection.query(SQL, args, function(err, result) {
				if (err) throw err;
				connection.end();
				callback(result);
			});
		} else {
			connection.query(SQL, function(err, result) {
				if (err) throw err;
				connection.end();
				callback(result);
			});
		}
	});
}

function buyEther(reciever, amount) {
	var txValues = {
		from: accountAddress,
		to: reciever,
		gasLimit: web3.toHex(800000),
		gasPrice: web3.toHex(20000000000),
		value: web3.toHex(web3.toWei(amount, 'ether')),
		nonce: web3.toHex(web3.eth.getTransactionCount(accountAddress))
	};
	var tx = txutils.valueTx(txValues);
	sendRaw(tx);
}

function validateReciept(req, warbasecoins) {
	
	var request = JSON.parse(req);
	var productIdValues = {
		"10_warbasecoins": 10,
		"50_warbasecoins": 50,
		"100_warbasecoins": 100,
		"500_warbasecoins": 500,
		"1k_warbasecoins": 1000,
		"0.005_eth": 0.005,
		"0.002_eth": 0.002,
		"0.001_eth": 0.001
	};

	var receipt = JSON.parse(request.validateRequest.ReceiptJson);

	PlayFabClient.ValidateGooglePlayPurchase(request.validateRequest, function(error, result) {
		if (error) onPlayFabError(error);
		else {
			var productId = receipt.productId;
			var amount = web3.toWei(productIdValues[productId]);
			// Do not convert to wei when buying ether, only when buying Warbasecoins.
			if (warbasecoins)
				mintTokens(request.address, amount);
			else
				buyEther(request.address, productIdValues[productId]);
		}
	});
}

function giveDefaultItemsTo(playerId) {
	var grantRequest = {
		ItemIds: ['builder', 'unit', 'jet', 'light_tank', 'passenger_ship'],
		PlayFabId: playerId
	};

	PlayFabServer.GrantItemsToUser(grantRequest, function(error, result) {
		if (error) onPlayFabError(error);
	});
}

function giveAllItemsTo(player) {
	PlayFabServer.GetUserInventory({PlayFabId: player}, function(error, result) {
		var inv = result.data.Inventory;
		for (var i = 0; i < inv.length; i++) {
			var revokeRequest = {
				ItemInstanceId: inv[i].ItemInstanceId,
				PlayFabId: player
			};
			PlayFabServer.RevokeInventoryItem(revokeRequest, function(error, result) {
				if (error) onPlayFabError(error);
			});
		}

		console.log("h");
	});

	PlayFabServer.GetCatalogItems({}, function(error, result) {
		if (error) onPlayFabError(error);
	
		var catalog = result.data.Catalog;
		for (var i = 0; i < catalog.length; i++) {
			if (catalog[i].Bundle != null)
				continue;

			var grantRequest = {
				ItemIds: [catalog[i].ItemId],
				PlayFabId: player
			};
			PlayFabServer.GrantItemsToUser(grantRequest, function(error, result) {
				if (error) onPlayFabError(error);
			});
		}

		console.log("Finished.");
	});
}

function createListing(request) {
	const sql = "INSERT INTO listings (playfab_id, instance_id, item_id, price, address) VALUES ?";
	const args = [[
		request.PlayFabId,
		request.InstanceId,
		request.ItemId,
		request.Price,
		getAddress(request.PrivateKey),
	]];
	queryDB(sql, [args], result => {});
}

function purchaseMarketItem(listingId, buyerAddress, buyerPlayFabId) {
	queryDB('SELECT * FROM listings WHERE id = ?', [[[listingId]]], (listing) => {
		listing = listing[0];

		// Transfer the tokens.
		const allowance = contract.allowance(listing.address, accountAddress);
		const price = new BigNumber(listing.price);
		if (allowance.gte(price)) {
			// The parameters are "from", "to", and "amount".
			sendTx("transferFrom", [buyerAddress, listing.address, price]);

			// Transfer the inventory item.
			const revokeRequest = {
				"PlayFabId": listing.playfab_id,
				"ItemInstanceId": listing.instance_id,
			};
			PlayFabServer.RevokeInventoryItem(revokeRequest, (error, result) => {
				if (error) onPlayFabError(error);

				const grantRequest = {
					"PlayFabId": buyerPlayFabId,
					"Annotation": "Market sale.",
					"ItemIds": [listing.item_id]
				};
				PlayFabServer.GrantItemsToUser(grantRequest, (error, result) => {
					if (error) onPlayFabError(error);
					
					// Delete the listing.
					var updateSql = "UPDATE `listings` SET `state` = 'Sold' WHERE `id` = ?";
					queryDB(updateSql, [[[listingId]]], result => {

						// Register the sale.
						var insertSql = 'INSERT INTO `market_sales`(from_playfab_id, to_playfab_id, from_address, 					to_address, amount, item_id, listing_id) VALUES ?';
						var args = [[
							listing.playfab_id,
							buyerPlayFabId,
							buyerAddress,
							listing.address,
							web3.toHex(price),
							listing.item_id,
							listingId
						]];
						queryDB(insertSql, [args], result => {
							console.log(result);
						})
					});
				});
			});
		}
	});
}