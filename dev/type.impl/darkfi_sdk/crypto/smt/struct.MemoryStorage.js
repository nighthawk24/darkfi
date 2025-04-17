(function() {
    var type_impls = Object.fromEntries([["darkfi_sdk",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-MemoryStorage%3CF%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#106\">Source</a><a href=\"#impl-Clone-for-MemoryStorage%3CF%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"darkfi_sdk/crypto/smt/util/trait.FieldElement.html\" title=\"trait darkfi_sdk::crypto::smt::util::FieldElement\">FieldElement</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"darkfi_sdk/crypto/smt/struct.MemoryStorage.html\" title=\"struct darkfi_sdk::crypto::smt::MemoryStorage\">MemoryStorage</a>&lt;F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#106\">Source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.86.0/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"darkfi_sdk/crypto/smt/struct.MemoryStorage.html\" title=\"struct darkfi_sdk::crypto::smt::MemoryStorage\">MemoryStorage</a>&lt;F&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.86.0/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.86.0/src/core/clone.rs.html#174\">Source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.86.0/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.86.0/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","darkfi_sdk::crypto::smt::MemoryStorageFp"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-MemoryStorage%3CF%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#106\">Source</a><a href=\"#impl-Default-for-MemoryStorage%3CF%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"darkfi_sdk/crypto/smt/util/trait.FieldElement.html\" title=\"trait darkfi_sdk::crypto::smt::util::FieldElement\">FieldElement</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"darkfi_sdk/crypto/smt/struct.MemoryStorage.html\" title=\"struct darkfi_sdk::crypto::smt::MemoryStorage\">MemoryStorage</a>&lt;F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#106\">Source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; <a class=\"struct\" href=\"darkfi_sdk/crypto/smt/struct.MemoryStorage.html\" title=\"struct darkfi_sdk::crypto::smt::MemoryStorage\">MemoryStorage</a>&lt;F&gt;</h4></section></summary><div class='docblock'>Returns the “default value” for a type. <a href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html#tymethod.default\">Read more</a></div></details></div></details>","Default","darkfi_sdk::crypto::smt::MemoryStorageFp"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MemoryStorage%3CF%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#111-115\">Source</a><a href=\"#impl-MemoryStorage%3CF%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;F: <a class=\"trait\" href=\"darkfi_sdk/crypto/smt/util/trait.FieldElement.html\" title=\"trait darkfi_sdk::crypto::smt::util::FieldElement\">FieldElement</a>&gt; <a class=\"struct\" href=\"darkfi_sdk/crypto/smt/struct.MemoryStorage.html\" title=\"struct darkfi_sdk::crypto::smt::MemoryStorage\">MemoryStorage</a>&lt;F&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#112-114\">Source</a><h4 class=\"code-header\">pub fn <a href=\"darkfi_sdk/crypto/smt/struct.MemoryStorage.html#tymethod.new\" class=\"fn\">new</a>() -&gt; Self</h4></section></div></details>",0,"darkfi_sdk::crypto::smt::MemoryStorageFp"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-StorageAdapter-for-MemoryStorage%3CF%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#117-133\">Source</a><a href=\"#impl-StorageAdapter-for-MemoryStorage%3CF%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;F: <a class=\"trait\" href=\"darkfi_sdk/crypto/smt/util/trait.FieldElement.html\" title=\"trait darkfi_sdk::crypto::smt::util::FieldElement\">FieldElement</a>&gt; <a class=\"trait\" href=\"darkfi_sdk/crypto/smt/trait.StorageAdapter.html\" title=\"trait darkfi_sdk::crypto::smt::StorageAdapter\">StorageAdapter</a> for <a class=\"struct\" href=\"darkfi_sdk/crypto/smt/struct.MemoryStorage.html\" title=\"struct darkfi_sdk::crypto::smt::MemoryStorage\">MemoryStorage</a>&lt;F&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"associatedtype.Value\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#118\">Source</a><a href=\"#associatedtype.Value\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"darkfi_sdk/crypto/smt/trait.StorageAdapter.html#associatedtype.Value\" class=\"associatedtype\">Value</a> = F</h4></section><section id=\"method.put\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#120-123\">Source</a><a href=\"#method.put\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"darkfi_sdk/crypto/smt/trait.StorageAdapter.html#tymethod.put\" class=\"fn\">put</a>(&amp;mut self, key: <a class=\"struct\" href=\"https://docs.rs/num-bigint/0.4/num_bigint/biguint/struct.BigUint.html\" title=\"struct num_bigint::biguint::BigUint\">BigUint</a>, value: F) -&gt; <a class=\"type\" href=\"darkfi_sdk/error/type.ContractResult.html\" title=\"type darkfi_sdk::error::ContractResult\">ContractResult</a></h4></section><section id=\"method.get\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#125-127\">Source</a><a href=\"#method.get\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"darkfi_sdk/crypto/smt/trait.StorageAdapter.html#tymethod.get\" class=\"fn\">get</a>(&amp;self, key: &amp;<a class=\"struct\" href=\"https://docs.rs/num-bigint/0.4/num_bigint/biguint/struct.BigUint.html\" title=\"struct num_bigint::biguint::BigUint\">BigUint</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.86.0/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;F&gt;</h4></section><section id=\"method.del\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/darkfi_sdk/crypto/smt/mod.rs.html#129-132\">Source</a><a href=\"#method.del\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"darkfi_sdk/crypto/smt/trait.StorageAdapter.html#tymethod.del\" class=\"fn\">del</a>(&amp;mut self, key: &amp;<a class=\"struct\" href=\"https://docs.rs/num-bigint/0.4/num_bigint/biguint/struct.BigUint.html\" title=\"struct num_bigint::biguint::BigUint\">BigUint</a>) -&gt; <a class=\"type\" href=\"darkfi_sdk/error/type.ContractResult.html\" title=\"type darkfi_sdk::error::ContractResult\">ContractResult</a></h4></section></div></details>","StorageAdapter","darkfi_sdk::crypto::smt::MemoryStorageFp"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[8787]}