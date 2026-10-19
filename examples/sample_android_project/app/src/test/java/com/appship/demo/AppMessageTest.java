package com.appship.demo;

import static org.junit.Assert.assertTrue;
import org.junit.Test;

public final class AppMessageTest {
    @Test
    public void welcomeMessageIsNotEmpty() {
        assertTrue(AppMessage.welcome().startsWith("AppShip Demo"));
    }
}
