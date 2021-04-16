@load base/frameworks/sumstats
event http_reply(c: connection, version: string, code: count, reason: string)
	{
		SumStats::observe("response",[$host=c$id$orig_h],[$num=1]);
		if(code == 404)
		{
			SumStats::observe("response404",[$host=c$id$orig_h],[$num=1]);
			SumStats::observe("unique404",[$host=c$id$orig_h],[$str=c$http$uri]);
		}
	}
	
event zeek_init()
	{
		local allResponse = SumStats::Reducer($stream="response", $apply=set(SumStats::SUM));
		local all404 = SumStats::Reducer($stream="response404", $apply=set(SumStats::SUM));
		local unique404 = SumStats::Reducer($stream="unique404", $apply=set(SumStats::UNIQUE));
		
		SumStats::create([
		$name="detectScan", 
		$epoch=10min, 
		$reducers=set(allResponse, all404, unique404), 
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
        	local r1 = result["response"];
        	local r2 = result["response404"];
        	local r3 = result["unique404"];
        
	        if (r2$sum > 2) 
	        {
	            if (r2$sum / r1$sum > 0.2) 
	            {
	                if (r3$unique / r2$sum > 0.5) 
	                {
	                    print fmt(" %s is a scanner with %.0f scan attemps on %d urls", key$host, r2$sum, r3$unique);
	                } 
	            }
	        }
	    }]);
	}
