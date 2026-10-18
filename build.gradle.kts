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
        feature("default", "standalone")
        feature("standalone")
        feature("std", "rand/std_rng", "rand/sys_rng")
        feature("ffi")
        feature("executable", "dep:hex", "std")
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
