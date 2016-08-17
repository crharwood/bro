# chris bro sample detecting minecraft

@load base/utils/site
@load base/frameworks/notice

module HTTP;

export {
	redef enum Notice::Type += {
		Minecraft
	};
}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( /mojang/ in c$http$host && c$http$status_code == 200 )
		NOTICE([$note=HTTP::Minecraft,
			$msg=fmt("Kids are playing minecraft: %s", c$id$resp_h),
			$conn=c,
			$identifier=cat(c$id$resp_h)]);
	}
