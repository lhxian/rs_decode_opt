struct Pool {
    pub capacity: usize,
    pub pool: Vec<Vec<i32>>,
}
impl Pool {
    fn new(capacity: usize,n:usize) -> Self{
        let mut res =Pool{
            capacity: capacity,
            pool: Vec::with_capacity(capacity),
        };
        for _ in 0..capacity {
            res.pool.push(Vec::with_capacity(n));
        }
        res
    }
    fn borrow(&mut self) -> Option<Vec<i32>> {
        self.pool.pop()
    }
    fn release(&mut self, mut v: Vec<i32>) {
        self.pool.push(v);
    }
}