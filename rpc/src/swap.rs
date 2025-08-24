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
