fn main() {
    let x = Some(5);
    if true && let Some(y) = x {
        println!("y = {}", y);
    }
}
