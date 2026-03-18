.class public final Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider;
    }
.end annotation


# instance fields
.field private final clientRequestHeaders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final clientResponseHeaders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final emitExperimentalHttpClientTelemetry:Z

.field private final emitExperimentalHttpServerTelemetry:Z

.field private final enduserConfig:Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;

.field private final knownHttpRequestMethods:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final loggingSpanIdKey:Ljava/lang/String;

.field private final loggingTraceFlagsKey:Ljava/lang/String;

.field private final loggingTraceIdKey:Ljava/lang/String;

.field private final peerServiceResolver:Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;

.field private final redactQueryParameters:Z

.field private final serverRequestHeaders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final serverResponseHeaders:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final sqlCommenterEnabled:Z

.field private final statementSanitizationEnabled:Z


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;-><init>(I)V

    .line 8
    .line 9
    .line 10
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 11
    .line 12
    new-instance v2, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct {v2, p1, v3}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;I)V

    .line 16
    .line 17
    .line 18
    invoke-static {p1, v0, v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getFromConfigProviderOrFallback(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider;Ljava/lang/Object;Ljava/util/function/Supplier;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Ljava/util/Map;

    .line 23
    .line 24
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;->create(Ljava/util/Map;)Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->peerServiceResolver:Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;

    .line 29
    .line 30
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;-><init>(I)V

    .line 34
    .line 35
    .line 36
    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 37
    .line 38
    new-instance v2, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;

    .line 39
    .line 40
    const/4 v3, 0x1

    .line 41
    invoke-direct {v2, p1, v3}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {p1, v0, v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getFromConfigProviderOrFallback(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider;Ljava/lang/Object;Ljava/util/function/Supplier;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Ljava/util/List;

    .line 49
    .line 50
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->clientRequestHeaders:Ljava/util/List;

    .line 51
    .line 52
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;

    .line 53
    .line 54
    const/4 v2, 0x2

    .line 55
    invoke-direct {v0, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;-><init>(I)V

    .line 56
    .line 57
    .line 58
    new-instance v2, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;

    .line 59
    .line 60
    const/4 v3, 0x2

    .line 61
    invoke-direct {v2, p1, v3}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;I)V

    .line 62
    .line 63
    .line 64
    invoke-static {p1, v0, v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getFromConfigProviderOrFallback(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider;Ljava/lang/Object;Ljava/util/function/Supplier;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    check-cast v0, Ljava/util/List;

    .line 69
    .line 70
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->clientResponseHeaders:Ljava/util/List;

    .line 71
    .line 72
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;

    .line 73
    .line 74
    const/4 v2, 0x3

    .line 75
    invoke-direct {v0, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;-><init>(I)V

    .line 76
    .line 77
    .line 78
    new-instance v2, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;

    .line 79
    .line 80
    const/4 v3, 0x3

    .line 81
    invoke-direct {v2, p1, v3}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;I)V

    .line 82
    .line 83
    .line 84
    invoke-static {p1, v0, v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getFromConfigProviderOrFallback(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider;Ljava/lang/Object;Ljava/util/function/Supplier;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    check-cast v0, Ljava/util/List;

    .line 89
    .line 90
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->serverRequestHeaders:Ljava/util/List;

    .line 91
    .line 92
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;

    .line 93
    .line 94
    const/4 v2, 0x4

    .line 95
    invoke-direct {v0, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/a;-><init>(I)V

    .line 96
    .line 97
    .line 98
    new-instance v2, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;

    .line 99
    .line 100
    const/4 v3, 0x4

    .line 101
    invoke-direct {v2, p1, v3}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;I)V

    .line 102
    .line 103
    .line 104
    invoke-static {p1, v0, v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->getFromConfigProviderOrFallback(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider;Ljava/lang/Object;Ljava/util/function/Supplier;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    check-cast v0, Ljava/util/List;

    .line 109
    .line 110
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->serverResponseHeaders:Ljava/util/List;

    .line 111
    .line 112
    new-instance v0, Ljava/util/HashSet;

    .line 113
    .line 114
    new-instance v1, Ljava/util/ArrayList;

    .line 115
    .line 116
    sget-object v2, Lio/opentelemetry/instrumentation/api/internal/HttpConstants;->KNOWN_METHODS:Ljava/util/Set;

    .line 117
    .line 118
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 119
    .line 120
    .line 121
    const-string v2, "otel.instrumentation.http.known-methods"

    .line 122
    .line 123
    invoke-interface {p1, v2, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getList(Ljava/lang/String;Ljava/util/List;)Ljava/util/List;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 128
    .line 129
    .line 130
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->knownHttpRequestMethods:Ljava/util/Set;

    .line 131
    .line 132
    const-string v0, "otel.instrumentation.common.db-statement-sanitizer.enabled"

    .line 133
    .line 134
    const/4 v1, 0x1

    .line 135
    invoke-interface {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getBoolean(Ljava/lang/String;Z)Z

    .line 136
    .line 137
    .line 138
    move-result v0

    .line 139
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->statementSanitizationEnabled:Z

    .line 140
    .line 141
    const-string v0, "otel.instrumentation.common.experimental.db-sqlcommenter.enabled"

    .line 142
    .line 143
    const/4 v2, 0x0

    .line 144
    invoke-interface {p1, v0, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getBoolean(Ljava/lang/String;Z)Z

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->sqlCommenterEnabled:Z

    .line 149
    .line 150
    const-string v0, "otel.instrumentation.http.client.emit-experimental-telemetry"

    .line 151
    .line 152
    invoke-interface {p1, v0, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getBoolean(Ljava/lang/String;Z)Z

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->emitExperimentalHttpClientTelemetry:Z

    .line 157
    .line 158
    const-string v0, "otel.instrumentation.http.client.experimental.redact-query-parameters"

    .line 159
    .line 160
    invoke-interface {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getBoolean(Ljava/lang/String;Z)Z

    .line 161
    .line 162
    .line 163
    move-result v0

    .line 164
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->redactQueryParameters:Z

    .line 165
    .line 166
    const-string v0, "otel.instrumentation.http.server.emit-experimental-telemetry"

    .line 167
    .line 168
    invoke-interface {p1, v0, v2}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getBoolean(Ljava/lang/String;Z)Z

    .line 169
    .line 170
    .line 171
    move-result v0

    .line 172
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->emitExperimentalHttpServerTelemetry:Z

    .line 173
    .line 174
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;

    .line 175
    .line 176
    invoke-direct {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)V

    .line 177
    .line 178
    .line 179
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->enduserConfig:Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;

    .line 180
    .line 181
    const-string v0, "otel.instrumentation.common.logging.trace-id"

    .line 182
    .line 183
    const-string v1, "trace_id"

    .line 184
    .line 185
    invoke-interface {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->loggingTraceIdKey:Ljava/lang/String;

    .line 190
    .line 191
    const-string v0, "otel.instrumentation.common.logging.span-id"

    .line 192
    .line 193
    const-string v1, "span_id"

    .line 194
    .line 195
    invoke-interface {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->loggingSpanIdKey:Ljava/lang/String;

    .line 200
    .line 201
    const-string v0, "otel.instrumentation.common.logging.trace-flags"

    .line 202
    .line 203
    const-string v1, "trace_flags"

    .line 204
    .line 205
    invoke-interface {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object p1

    .line 209
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->loggingTraceFlagsKey:Ljava/lang/String;

    .line 210
    .line 211
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->lambda$new$1(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->lambda$new$4(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/Map;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->lambda$new$0(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->lambda$new$3(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->lambda$new$2(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static getFromConfigProviderOrFallback(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider;Ljava/lang/Object;Ljava/util/function/Supplier;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;",
            "Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider<",
            "TT;>;TT;",
            "Ljava/util/function/Supplier<",
            "TT;>;)TT;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getConfigProvider()Lio/opentelemetry/api/incubator/config/ConfigProvider;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    invoke-interface {p1, p0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig$ValueProvider;->get(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    return-object p2

    .line 15
    :cond_1
    invoke-interface {p3}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private static synthetic lambda$new$0(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/Map;
    .locals 2

    .line 1
    const-string v0, "otel.instrumentation.common.peer-service-mapping"

    .line 2
    .line 3
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 4
    .line 5
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getMap(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static synthetic lambda$new$1(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;
    .locals 1

    .line 1
    const-string v0, "otel.instrumentation.http.client.capture-request-headers"

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getList(Ljava/lang/String;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static synthetic lambda$new$2(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;
    .locals 1

    .line 1
    const-string v0, "otel.instrumentation.http.client.capture-response-headers"

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getList(Ljava/lang/String;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static synthetic lambda$new$3(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;
    .locals 1

    .line 1
    const-string v0, "otel.instrumentation.http.server.capture-request-headers"

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getList(Ljava/lang/String;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static synthetic lambda$new$4(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)Ljava/util/List;
    .locals 1

    .line 1
    const-string v0, "otel.instrumentation.http.server.capture-response-headers"

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getList(Ljava/lang/String;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method


# virtual methods
.method public getClientRequestHeaders()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->clientRequestHeaders:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getClientResponseHeaders()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->clientResponseHeaders:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEnduserConfig()Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->enduserConfig:Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public getKnownHttpRequestMethods()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->knownHttpRequestMethods:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPeerServiceResolver()Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->peerServiceResolver:Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;

    .line 2
    .line 3
    return-object p0
.end method

.method public getServerRequestHeaders()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->serverRequestHeaders:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getServerResponseHeaders()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->serverResponseHeaders:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSpanIdKey()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->loggingSpanIdKey:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTraceFlagsKey()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->loggingTraceFlagsKey:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTraceIdKey()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->loggingTraceIdKey:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public isSqlCommenterEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->sqlCommenterEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isStatementSanitizationEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->statementSanitizationEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public redactQueryParameters()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->redactQueryParameters:Z

    .line 2
    .line 3
    return p0
.end method

.method public shouldEmitExperimentalHttpClientTelemetry()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->emitExperimentalHttpClientTelemetry:Z

    .line 2
    .line 3
    return p0
.end method

.method public shouldEmitExperimentalHttpServerTelemetry()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;->emitExperimentalHttpServerTelemetry:Z

    .line 2
    .line 3
    return p0
.end method
