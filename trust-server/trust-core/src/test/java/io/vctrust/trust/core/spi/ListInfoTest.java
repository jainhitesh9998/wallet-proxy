package io.vctrust.trust.core.spi;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ListInfoTest {

    @Test
    void detailsKeepTheOrderTheSourceGaveThem() {
        Map<String, Object> given = new LinkedHashMap<>();
        for (String key : new String[] {"format", "pages", "territory", "version", "operator", "scheme", "type", "count"}) {
            given.put(key, key.length());
        }
        ListInfo info = new ListInfo(null, null, null, null, ListInfo.SignatureStatus.NOT_SIGNED, given);
        assertThat(info.details().keySet()).containsExactly("format", "pages", "territory", "version", "operator", "scheme", "type", "count");
        // A copy: what the source does to its own map afterwards changes nothing, and the details cannot be changed.
        given.put("later", 1);
        assertThat(info.details()).doesNotContainKey("later");
        assertThatThrownBy(() -> info.details().put("x", 1)).isInstanceOf(UnsupportedOperationException.class);
    }
}
