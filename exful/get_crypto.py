import requests

def crypto_prices_view():
    url = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest"
    params = {
        "symbol": "BTC,ETH,LTC,BNB,SOL,USDT,USDC,XRP,TON,DOGE,ADA,TRX,AVAX,LINK,MATIC,ATOM,EOS,XLM,NEO,VET,THETA,FIL,UNI,DOT",
        "convert": "USD"
    }
    headers = {
        "Accepts": "application/json",
        "X-CMC_PRO_API_KEY": "877fff13-5b22-441c-8ba9-f0cf19ea69a5"
    }
    response = requests.get(url, params=params, headers=headers)

    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            crypto_prices = []
            for crypto, info in data["data"].items():
                price = info["quote"]["USD"]["price"]
                formatted_price = "{:,.2f}".format(price)  # Format the price with commas and no decimals
                price_change_24h = info["quote"]["USD"]["percent_change_24h"]
                market_cap = info["quote"]["USD"]["market_cap"]
                formatted_market_cap = "{:,.0f}".format(market_cap)
                volume_24h = info["quote"]["USD"]["volume_24h"] 
                formatted_volume_24h = "${:,.0f}".format(volume_24h)
                formatted_price_change_24h = "{}{:.2f}%".format("+" if price_change_24h >= 0 else "-", abs(price_change_24h))

                # Get the logo image URL from the cryptocurrency info endpoint
                info_url = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/info"
                info_params = {
                    "symbol": crypto
                }
                info_response = requests.get(info_url, params=info_params, headers=headers)
                if info_response.status_code == 200:
                    info_data = info_response.json()
                    if 'data' in info_data:
                        logo_url = info_data["data"][crypto]["logo"]
                    else:
                        logo_url = None  # or some default value
                else:
                    logo_url = None  # or some default value

                # Get the circulating supply from the cryptocurrency supply endpoint
                supply_url = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/supply"
                supply_params = {
                    "symbol": crypto
                }
                supply_response = requests.get(supply_url, params=supply_params, headers=headers)
                if supply_response.status_code == 200:
                    supply_data = supply_response.json()
                    if 'data' in supply_data:
                        circulating_supply = supply_data["data"][crypto]["circulating_supply"]
                        formatted_circulating_supply = "{:,.0f}".format(circulating_supply)
                    else:
                        circulating_supply = None  # or some default value
                        formatted_circulating_supply = "N/A"
                else:
                    circulating_supply = None  # or some default value
                    formatted_circulating_supply = "N/A"

                crypto_prices.append({
                    "name": info["name"],
                    "price": formatted_price,
                    "price_change_24h": formatted_price_change_24h,
                    "market_cap": formatted_market_cap,
                    "volume_24h": formatted_volume_24h,
                    "circulating_supply": formatted_circulating_supply,
                    "logo_url": logo_url
                })

            return crypto_prices
        else:
            return []  # or some default value
    else:
        return []  # or some default value