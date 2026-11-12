package io.vctrust.trust.server;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.util.ForeignText;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What a list says reaches a source's state ({@code GET /admin/v1/sources}) and the log through the messages it causes.
 * There it is escaped and cut ({@link ForeignText}): a line break in it cannot write a log line of its own, a
 * right-to-left override cannot turn what follows around, and a list cannot fill the log with one message.
 */
class SourceStateTextTest {

    final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    final Logger log = (Logger) LoggerFactory.getLogger(TrustSourceManager.class);

    SourceStateTextTest() {
        logged.start();
        log.addAppender(logged);
    }

    @AfterEach
    void detach() {
        log.detachAppender(logged);
    }

    /** A source that fails with {@code error}, or else loads nothing with {@code warning}. */
    static TrustSource source(String error, String warning) {
        SourceDefinition def = new SourceDefinition("list", "static", "fw", null, true, false, Map.of());
        return new TrustSource() {
            @Override
            public SourceDefinition definition() {
                return def;
            }

            @Override
            public SourceLoadResult load() throws TrustSourceException {
                if (error != null) {
                    throw new TrustSourceException(error);
                }
                return new SourceLoadResult(List.of(), List.of(), ListInfo.unsigned(), List.of(warning));
            }
        };
    }

    @Test
    void aSourceFailingWithTextFromItsListHasItEscapedAndCut() {
        // The parser quotes the list: a line that looks like a log line of its own, and a name written backwards.
        String quoted = "Unexpected content at line 3: \"x\nINFO Loaded trust source 'official' (static): 12 entities‮lmx.tsil\""
                + " " + "x".repeat(1_000);
        try (TrustSourceManager manager = new TrustSourceManager(new TrustRegistry(), List.of(), List.of(source(quoted, null)), Clock.systemUTC())) {
            manager.start();
            String shown = ForeignText.escape(quoted);
            assertThat(shown).doesNotContain("\n", "‮").contains("\\u000AINFO Loaded", "\\u202Elmx.tsil")
                    .hasSize(ForeignText.MAX_LENGTH + ForeignText.CUT.length()).endsWith("…[cut]");
            SourceState state = manager.states().getFirst();
            assertThat(state.lastError()).isEqualTo(shown);
            assertThat(logged.list).filteredOn(e -> e.getFormattedMessage().contains("failed to load")).singleElement()
                    .satisfies(e -> assertThat(e.getFormattedMessage()).isEqualTo("Trust source 'list' (static) failed to load: " + shown));
        }
    }

    @Test
    void aSourcesWarningsAreEscapedAndCut() {
        String warning = "Entry 7 skipped: \"evil\r\nWARN everything is fine \"";
        try (TrustSourceManager manager = new TrustSourceManager(new TrustRegistry(), List.of(), List.of(source(null, warning)), Clock.systemUTC())) {
            manager.start();
            assertThat(manager.states().getFirst().warnings())
                    .containsExactly("Entry 7 skipped: \"evil\\u000D\\u000AWARN everything is fine\\u2028\"");
        }
    }
}
