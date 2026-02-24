use std::env;

use libafl_cc::{CfgEdge, ControlFlowGraph, HasWeight};

pub fn main() {
    let args: Vec<String> = env::args().collect();
    struct TestMetadata {}

    impl HasWeight<TestMetadata> for TestMetadata {
        fn compute(_metadata: Option<&TestMetadata>) -> u32 {
            1
        }
    }

    for i in 1..args.len() {
        let file = &args[i];
        let _cfg = ControlFlowGraph::<TestMetadata>::from_file(&file);

        println!("{} is a valid file", file);
    }
}
