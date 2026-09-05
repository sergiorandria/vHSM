import React, { useCallback, useEffect, useState } from 'react';
import { FlatList, RefreshControl, StyleSheet, View } from 'react-native';
import { ActivityIndicator, Text, Searchbar } from 'react-native-paper';
import { fetchTheses } from '../services/api';
import { Thesis } from '../types';
import { ThesisCard } from '../components/ThesisCard';

export function HomeScreen({ navigation }: any) {
  const [theses, setTheses] = useState<Thesis[]>([]);
  const [filtered, setFiltered] = useState<Thesis[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [query, setQuery] = useState('');

  const load = useCallback(async () => {
    try {
      const raw = await fetchTheses();
      const list: Thesis[] = Array.isArray(raw) ? raw : raw.theses || raw || [];
      setTheses(list);
      setFiltered(list);
    } catch (e) {
      console.log('fetch theses failed', e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!query) setFiltered(theses);
    else {
      const q = query.toLowerCase();
      setFiltered(
        theses.filter(
          (t) =>
            t.thesisId.toLowerCase().includes(q) ||
            t.metadata?.title?.toLowerCase().includes(q) ||
            t.student?.fullName?.toLowerCase().includes(q)
        )
      );
    }
  }, [query, theses]);

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator />
        <Text style={styles.hint}>Loading theses…</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Searchbar
        placeholder="Search thesis, student, title"
        value={query}
        onChangeText={setQuery}
        style={styles.search}
      />
      <FlatList
        data={filtered}
        keyExtractor={(item) => item.thesisId}
        renderItem={({ item }) => (
          <ThesisCard thesis={item} onPress={() => navigation.navigate('ThesisDetail', { thesisId: item.thesisId })} />
        )}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); load(); }} />}
        ListEmptyComponent={
          <View style={styles.center}>
            <Text>No theses found</Text>
          </View>
        }
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f5f7fb' },
  search: { margin: 12, backgroundColor: 'white' },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 },
  hint: { marginTop: 8, color: '#666' },
});
