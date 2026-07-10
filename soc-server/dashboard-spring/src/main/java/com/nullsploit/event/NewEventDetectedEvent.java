package com.nullsploit.event;

import org.springframework.context.ApplicationEvent;
import java.util.Map;

public class NewEventDetectedEvent extends ApplicationEvent {
    private final Map<String, Object> eventData;

    public NewEventDetectedEvent(Object source, Map<String, Object> eventData) {
        super(source);
        this.eventData = eventData;
    }

    public Map<String, Object> getEventData() {
        return eventData;
    }
}
