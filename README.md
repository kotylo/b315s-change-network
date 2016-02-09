# b315s-change-network
Huawei B315s router automatic LTE signal recovery

This console application is looking at your local router and monitors the status of Huawei B315s-22.
You can keep it running at the startup of the Windows.

The reason it can exist is because of buggy software of Huawei's router.
Sometimes when you're in the Auto Network mode, LTE may disappear and you will stay at 3G for a long time, not really noticing, but loosing a lot of bandwidth. The thing is if at this moment login to the router and change Network type from Auto to LTE and back to Auto, it recognizes LTE networks and keeps it alive.

So what this Application does is:
- Goes to the home page of router
- Checks the status every 30 seconds of the network. In case it's not LTE:
- Performs Login with entered in App.config username/password for Router.
- Switches network type → LTE → Auto.
- Cycle repeats itself here

The temporary lost of Internet is predictable, but it usually doesn't take more than 1-5 seconds.

Enjoy!
