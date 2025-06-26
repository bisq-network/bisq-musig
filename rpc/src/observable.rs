use futures_util::Stream;
use std::borrow::Borrow;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;

#[derive(Default)]
pub struct Observable<T> {
    value: T,
    senders: Vec<mpsc::UnboundedSender<T>>,
}

struct StillObservedError<T>(Observable<T>);

impl<T> Observable<T> {
    pub const fn new(value: T) -> Self {
        Self { value, senders: Vec::new() }
    }

    fn try_into_unobserved(mut self) -> Result<T, StillObservedError<T>> {
        self.senders.retain(|s| !s.is_closed());
        shrink_amortized(&mut self.senders);
        if self.senders.is_empty() { Ok(self.value) } else { Err(StillObservedError(self)) }
    }
}

impl<T: Clone> Observable<T> {
    pub fn observe(&mut self) -> impl Stream<Item=T> {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(self.value.clone()).unwrap();
        self.senders.push(tx);
        UnboundedReceiverStream::new(rx)
    }
}

impl<T: Clone + PartialEq> Observable<T> {
    pub fn replace(&mut self, value: T) -> T {
        let old_value = std::mem::replace(&mut self.value, value);
        let new_value = &self.value;
        if old_value == *new_value {
            self.senders.retain(|s| !s.is_closed());
        } else {
            self.senders.retain(|s| s.send(new_value.clone()).is_ok());
        }
        shrink_amortized(&mut self.senders);
        old_value
    }
}

impl<T: Clone + Default + PartialEq> Observable<T> {
    pub fn take(&mut self) -> T { self.replace(T::default()) }
}

fn shrink_amortized<T>(vec: &mut Vec<T>) {
    if vec.len() < vec.capacity() / 4 {
        vec.shrink_to(vec.len() * 2);
    }
}

pub struct ObservableHashMap<K, V> {
    map: HashMap<K, Observable<Option<V>>>,
}

impl<K, V> Default for ObservableHashMap<K, V> {
    fn default() -> Self { Self { map: HashMap::default() } }
}

impl<K, V> ObservableHashMap<K, V> {
    pub fn new() -> Self { Self::default() }
}

impl<K, V> ObservableHashMap<K, V>
    where K: Eq + Hash,
          V: Clone
{
    pub fn observe(&mut self, key: K) -> impl Stream<Item=Option<V>> {
        match self.map.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Observable::default())
        }.observe()
    }
}

impl<K, V> ObservableHashMap<K, V>
    where K: Eq + Hash,
          V: Clone + PartialEq
{
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.map.entry(key) {
            Entry::Occupied(entry) =>
                entry.into_mut().replace(Some(value)),
            Entry::Vacant(entry) => {
                entry.insert(Observable::new(Some(value)));
                None
            }
        }
    }

    pub fn remove<Q>(&mut self, k: &Q) -> Option<V>
        where K: Borrow<Q>,
              Q: Eq + Hash + ?Sized
    {
        let (key, observed_value) = self.map.remove_entry(k)?;
        observed_value.try_into_unobserved()
            .unwrap_or_else(|StillObservedError(mut o)| {
                let taken = o.take();
                self.map.insert(key, o);
                taken
            })
    }
}

impl<K, V> ObservableHashMap<K, V>
    where K: Clone + Eq + Hash,
          V: Clone + PartialEq
{
    pub fn sync(&mut self, entries: impl IntoIterator<Item=(K, V)>) {
        let mut remaining_keys: HashSet<K> = self.map.keys().cloned().collect();
        for (key, value) in entries {
            remaining_keys.remove(&key);
            self.insert(key, value);
        }
        for key in remaining_keys {
            self.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt as _;

    use super::*;

    #[tokio::test]
    async fn test_singly_observed_value() {
        let mut observable = Observable::new("foo".to_owned());
        let mut stream = observable.observe();
        assert_eq!(stream.next().await, Some("foo".to_owned()),
            "first streamed item should match starting value");

        let v = observable.replace("foo".to_owned());
        assert_eq!(v, "foo");
        // Replaced with the same value -- nothing should be streamed.

        let v = observable.replace("bar".to_owned());
        assert_eq!(v, "foo");
        assert_eq!(stream.next().await, Some("bar".to_owned()),
            "second streamed item should match next _new_ value");

        drop(observable);
        assert_eq!(stream.next().await, None,
            "stream should close upon dropping the observable");
    }

    #[tokio::test]
    async fn test_multiply_observed_value() {
        let mut observable = Observable::new('a');
        let mut stream1 = observable.observe();
        let v = observable.replace('b');
        assert_eq!(v, 'a');
        let mut stream2 = observable.observe();

        assert_eq!(stream1.next().await, Some('a'),
            "first item from `stream1` should match first observable value");
        assert_eq!(stream1.next().await, Some('b'),
            "second item from `stream1` should match second observable value");
        assert_eq!(stream2.next().await, Some('b'),
            "first item from `stream2` should match second observable value");

        let v = observable.replace('c');
        assert_eq!(v, 'b');
        let mut stream3 = observable.observe();

        assert_eq!(stream1.next().await, Some('c'),
            "third item from `stream1` should match third observable value");
        assert_eq!(stream2.next().await, Some('c'),
            "second item from `stream2` should match third observable value");
        assert_eq!(stream3.next().await, Some('c'),
            "first item from `stream3` should match third observable value");

        let Err(StillObservedError(mut observable)) = observable.try_into_unobserved() else {
            panic!("`try_into_unobserved` should fail while streams are still attached");
        };

        drop(stream1);
        let v = observable.replace('c'); // Replaced with the same value -- nothing should be streamed.
        assert_eq!(v, 'c');
        assert_eq!(observable.senders.len(), 2,
            "`replace` should force lazy purge of `senders` list of dropped observers");

        let Err(StillObservedError(mut observable)) = observable.try_into_unobserved() else {
            panic!("`try_into_unobserved` should fail while streams are still attached");
        };

        drop(stream2);
        let v = observable.replace('d');
        assert_eq!(v, 'c');
        assert_eq!(observable.senders.len(), 1,
            "`replace` should force lazy purge of `senders` list of dropped observers");
        assert_eq!(stream3.next().await, Some('d'),
            "second item from `stream3` should match fourth observable value");
        drop(stream3);

        assert!(matches!(observable.try_into_unobserved(), Ok('d')),
            "`try_into_unobserved` should succeed with the current value when no streams are attached");
    }

    #[tokio::test]
    async fn test_observable_map_insert_and_remove() {
        let mut map = ObservableHashMap::new();
        let mut stream1 = map.observe('a');
        assert_eq!(stream1.next().await, Some(None),
            "first streamed item from missing key 'a' should be `None`");

        let v = map.insert('a', 1);
        assert_eq!(v, None);
        let v = map.insert('a', 1); // Inserted the same value -- nothing should be streamed.
        assert_eq!(v, Some(1));
        let v = map.insert('a', 2);
        assert_eq!(v, Some(1));
        let v = map.insert('b', 3);
        assert_eq!(v, None);

        let mut stream2 = map.observe('b');
        assert_eq!(stream1.next().await, Some(Some(1)),
            "second streamed item from key 'a' should be its first inserted value");
        assert_eq!(stream1.next().await, Some(Some(2)),
            "third streamed item from key 'a' should be its third inserted value");
        assert_eq!(stream2.next().await, Some(Some(3)),
            "first streamed item from key 'b' should be its first inserted value");

        let v = map.remove(&'a');
        assert_eq!(v, Some(2));
        let v = map.remove(&'a'); // Removed the same key -- nothing should be streamed.
        assert_eq!(v, None);
        let v = map.remove(&'c'); // Key was never inserted or observed
        assert_eq!(v, None);
        let v = map.insert('a', 4);
        assert_eq!(v, None);

        assert_eq!(stream1.next().await, Some(None),
            "fourth streamed item from key 'a' should be `None`");
        assert_eq!(stream1.next().await, Some(Some(4)),
            "fifth streamed item from key 'a' should be its fourth inserted value");

        drop(stream1);
        let v = map.remove(&'a');
        assert_eq!(v, Some(4));
        assert_eq!(map.map.keys().copied().collect::<String>(), "b",
            "only key 'b' should remain in the internal map after removing 'a' while unobserved");

        drop(map);
        assert_eq!(stream2.next().await, None,
            "stream from key 'b' should close upon dropping the observable map");
    }

    #[tokio::test]
    async fn test_observable_map_sync() {
        let mut map = ObservableHashMap::new();
        map.sync([('a', 1)]);

        let mut stream1 = map.observe('a');
        let mut stream2 = map.observe('b');
        assert_eq!(stream1.next().await, Some(Some(1)),
            "first streamed item from key 'a' should be its first synced value");
        assert_eq!(stream2.next().await, Some(None),
            "first streamed item from missing key 'b' should be `None`");

        map.sync([('a', 2), ('b', 3)]);

        let mut stream3 = map.observe('b');
        assert_eq!(stream1.next().await, Some(Some(2)),
            "second streamed item from key 'a' should be its second synced value");
        assert_eq!(stream2.next().await, Some(Some(3)),
            "second streamed item from key 'b' should be its first synced value");
        assert_eq!(stream3.next().await, Some(Some(3)),
            "first duplicate streamed item from key 'b' should be its first synced value");

        map.sync([('b', 3), ('a', 2)]); // Syncing to differently ordered list -- nothing should be streamed.
        map.sync([('b', 3), ('c', 4)]);

        assert_eq!(stream1.next().await, Some(None),
            "third streamed item from removed key 'a' should be `None`");

        drop(stream1);
        drop(stream2);
        map.sync([('b', 3), ('c', 4)]); // Syncing to the same list -- nothing should be streamed.
        assert!(!map.map.contains_key(&'a'),
            "syncing should force lazy purge of internal map of unobserved absent keys");
        assert_eq!(map.map.get(&'b')
            .expect("key 'b' should still be present").senders.len(), 1,
            "syncing should force lazy purge of internal `senders` lists of dropped observers");

        drop(map);
        assert_eq!(stream3.next().await, None,
            "duplicate stream from key 'b' should close upon dropping the observable map");
    }
}
