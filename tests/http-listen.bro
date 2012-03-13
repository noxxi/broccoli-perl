
@load frameworks/communication/listen
redef Communication::listen_port = 47758/tcp;

redef Communication::nodes += {
	["http"] = [$host = 127.0.0.1, $events = /./, $connect=F, $ssl=F]
};

