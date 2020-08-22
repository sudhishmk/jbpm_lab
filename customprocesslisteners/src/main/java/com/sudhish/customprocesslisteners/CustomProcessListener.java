package com.sudhish.customprocesslisteners;

import org.kie.api.event.process.DefaultProcessEventListener;
import org.kie.api.event.process.ProcessStartedEvent;

public class CustomProcessListener extends DefaultProcessEventListener{
	
	public void afterProcessStarted(ProcessStartedEvent event) {
        
		System.out.println("Process Started -: Event listener fired");
    }

}
