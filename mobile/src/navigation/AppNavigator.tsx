import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { Text } from 'react-native-paper';
import { HomeScreen } from '../screens/HomeScreen';
import { ThesisDetailScreen } from '../screens/ThesisDetailScreen';
import { NotificationsScreen } from '../screens/NotificationsScreen';
import { SettingsScreen } from '../screens/SettingsScreen';
import { HistoryScreen } from '../screens/HistoryScreen';
import { VerifyScreen } from '../screens/VerifyScreen';

const Tab = createBottomTabNavigator();
const Stack = createNativeStackNavigator();

function Tabs({ onLogout }: { onLogout: () => void }) {
  return (
    <Tab.Navigator
      screenOptions={{
        headerStyle: { backgroundColor: '#0a1f44' },
        headerTintColor: 'white',
        tabBarActiveTintColor: '#0a1f44',
      }}
    >
      <Tab.Screen
        name="Home"
        component={HomeScreen}
        options={{ title: 'Theses', tabBarIcon: ({ color }) => <Text style={{ color }}>📄</Text> }}
      />
      <Tab.Screen
        name="Notifications"
        component={NotificationsScreen}
        options={{ title: 'Inbox', tabBarBadge: undefined, tabBarIcon: ({ color }) => <Text style={{ color }}>🔔</Text> }}
      />
      <Tab.Screen
        name="Settings"
        children={() => <SettingsScreen onLogout={onLogout} />}
        options={{ tabBarIcon: ({ color }) => <Text style={{ color }}>⚙️</Text> }}
      />
    </Tab.Navigator>
  );
}

export function AppNavigator({ onLogout }: { onLogout: () => void }) {
  return (
    <NavigationContainer
      linking={{
        prefixes: ['vhsm://'],
        config: { screens: { ThesisDetail: 'thesis/:thesisId', Home: 'home' } },
      }}
    >
      <Stack.Navigator
        screenOptions={{
          headerStyle: { backgroundColor: '#0a1f44' },
          headerTintColor: 'white',
        }}
      >
        <Stack.Screen name="Tabs" options={{ headerShown: false }}>
          {() => <Tabs onLogout={onLogout} />}
        </Stack.Screen>
        <Stack.Screen name="ThesisDetail" component={ThesisDetailScreen} options={{ title: 'Thesis' }} />
        <Stack.Screen name="History" component={HistoryScreen} options={{ title: 'History' }} />
        <Stack.Screen name="Verify" component={VerifyScreen} options={{ title: 'Verify' }} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
