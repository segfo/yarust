use std::collections::{VecDeque,HashMap};
// リソースプール
pub struct ResourceAllocator<K,V>{
    pool:VecDeque<V>,
    used_pool:HashMap<K,V>
}

impl<K,V> ResourceAllocator<K,V>
    where K:std::cmp::Eq+std::hash::Hash+Clone{
    pub fn new()->Self{
        ResourceAllocator{
            pool:VecDeque::new(),
            used_pool:HashMap::new()
        }
    }

    // リソースプールの空き状況（個数）を返却する
    pub fn free_pool_count(&self)->usize{
        self.pool.len()
    }
    // 使用中のリソース状況（個数）を返却する
    #[allow(dead_code)]
    pub fn using_pool_count(&self)->usize{
        self.used_pool.len()
    }

    // リソースの参照を取得する
    // もし、複数スレッドでの共有をしたいリソースであれば
    // Arc<Mutex<V>>で対象の型 V をラップしなければならない
    pub fn get(&mut self,k:K)->Option<&mut V>{
        if self.used_pool.contains_key(&k){
            return None;
        }
        match self.pool.pop_back(){
            Some(inner)=>{
                self.used_pool.insert(k.clone(),inner);
                self.used_pool.get_mut(&k)
            },
            None=>None
        }
    }
    // リソースを返却する
    pub fn free(&mut self,key:K){
        let v = self.used_pool.remove(&key).unwrap();
        self.pool.push_front(v);
    }
    // リソースプールにリソースを登録する。
    pub fn register_resource_pool(&mut self,v:V){
        self.pool.push_front(v);
    }
}
