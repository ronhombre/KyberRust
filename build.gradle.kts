/*
 * Copyright 2026 Ron Lauren Hombre
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *        
 *        and included as LICENSE.txt in this Project.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import asia.hombre.neorust.option.PanicFlag

plugins {
    id("asia.hombre.neorust")
}

group = "asia.hombre.keccak"
version = "0.0.1"

repositories {
    mavenCentral()
}

dependencies {
    crate("zeroize:1.8.2") {
        defaultFeatures = false
        features.add("zeroize_derive")
    }
    crate("hex:0.4.3") {
        optional = true
    }
    crate("rand:0.10.3") {
        defaultFeatures = false
    }
    crate(project(":keccakrust")) {
        defaultFeatures = false
        features.add("standalone")
    }
    devCrate("hex:0.4.3")
    devCrate("criterion:0.8.2")
}

rust {
    authors.add("Ron Lauren Hombre <ronlauren@hombre.asia>")
    edition = "2024"

    library {
        crateType.add("rlib") //We are adding this to avoid double linking when running our binary executables
    }

    features {
        feature("default", "standalone", "panic_handler")
        feature("standalone")
        feature("std", "rand/std_rng", "rand/sys_rng")
        feature("ffi", "keccakrust/ffi")
        feature("executable", "dep:hex", "std")
        feature("panic_handler")
    }

    profiles {
        val dev by getting {
            panic = PanicFlag.abort
        }
        val release by getting {
            panic = PanicFlag.abort
        }
    }

    binaries {
        val main by getting {
            noDefaultFeatures = true
            buildFeatures.add("executable")
        }
    }
}
