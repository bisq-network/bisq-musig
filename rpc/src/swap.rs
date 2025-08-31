use rand::RngCore;

pub trait Swap: Sized {
    fn len(&self) -> usize;

    /// # Panics
    /// Will panic if `i` or `j` are out of bounds
    fn swap(self, i: usize, j: usize) -> Self;

    /// # Panics
    /// Will panic if `self.len()` is greater than `u32::MAX`
    fn shuffle(mut self, rng: &mut impl RngCore) -> Self {
        for j in (1..self.len()).rev() {
            let i = loop {
                let j_plus_1 = u32::try_from(j + 1).expect("cannot shuffle if len > u32::MAX");
                let x = rng.next_u32();
                if x / j_plus_1 < u32::MAX / j_plus_1 || u32::MAX % j_plus_1 == 0 {
                    break (x % j_plus_1) as usize;
                }
                // De-biasing branch. (This isn't actually all that useful for our purpose, because
                // for any reasonable number of Deposit Tx inputs & outputs, one would likely need
                // to carry out many billions of shuffles for any bias to start to become apparent.)
            };
            self = self.swap(i, j);
        }
        self
    }
}

impl<T> Swap for &mut [T] {
    fn len(&self) -> usize {
        (**self).len()
    }

    fn swap(self, i: usize, j: usize) -> Self {
        (*self).swap(i, j);
        self
    }
}

impl<T: Swap, U: Swap> Swap for (T, U) {
    fn len(&self) -> usize {
        self.0.len().min(self.1.len())
    }

    fn swap(self, i: usize, j: usize) -> Self {
        assert!(i.max(j) < self.len());
        (self.0.swap(i, j), self.1.swap(i, j))
    }
}

impl Swap for &mut u32 {
    fn len(&self) -> usize {
        u32::MAX as usize
    }

    fn swap(self, i: usize, j: usize) -> Self {
        assert!(i.max(j) < self.len());
        #[expect(clippy::cast_possible_truncation, reason = "range check ensures no truncation")]
        let (i, j) = (i as u32, j as u32);
        if *self == i {
            *self = j;
        } else if *self == j {
            *self = i;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng as _;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn test_unbiased_shuffle() {
        // 8_997_264 is the smallest u32 causing the de-biasing branch of the shuffle algorithm to
        // be hit, when using a seed of this form -- that is, the need to retry when taking r % LEN
        // to rejection sample uniformly in the range 0..<LEN, because r was too close to u32::MAX.
        let seed = [8_997_264_u32.to_le_bytes(); 8];
        let mut rng = ChaCha20Rng::from_seed(seed.as_flattened().try_into().unwrap());

        let mut xs = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        xs.shuffle(&mut rng);
        assert_eq!(b"QFWHDYCTZVIUOBPESAMNRKJXLG", &xs);
    }

    #[test]
    fn test_trivial_shuffles() {
        let seed = [1u32.to_le_bytes(); 8];
        let mut rng = ChaCha20Rng::from_seed(seed.as_flattened().try_into().unwrap());

        let mut xs = *b"";
        xs.shuffle(&mut rng);

        let mut xs = *b"X";
        xs.shuffle(&mut rng);
        assert_eq!(b"X", &xs);
    }

    #[test]
    fn test_shuffle_with_markers() {
        let seed = [2u32.to_le_bytes(); 8];
        let mut rng = ChaCha20Rng::from_seed(seed.as_flattened().try_into().unwrap());

        let mut xs = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let [mut i_m, mut i_n] = [12, 13u32];
        (xs.as_mut_slice(), (&mut i_m, &mut i_n)).shuffle(&mut rng);

        assert_eq!(b"XIVHYQLEPRBGSZKTWNMOFADCJU", &xs);
        assert_eq!(b"MN", &[xs[i_m as usize], xs[i_n as usize]]);
    }

    #[test]
    fn test_parallel_shuffle() {
        let seed = [3u32.to_le_bytes(); 8];
        let mut rng = ChaCha20Rng::from_seed(seed.as_flattened().try_into().unwrap());

        let mut xs = *b"ABCDEFGHI";
        let mut ys = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        (xs.as_mut_slice(), ys.as_mut_slice()).shuffle(&mut rng);

        assert_eq!(b"BIEAHGCFD", &xs);
        assert_eq!([2, 9, 5, 1, 8, 7, 3, 6, 4], ys);
    }
}
