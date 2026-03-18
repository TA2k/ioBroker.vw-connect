.class Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizerUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final sanitizer:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->create(Z)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizerUtil;->sanitizer:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Ljava/lang/String;)Ljava/util/HashMap;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizerUtil;->lambda$sanitize$0(Ljava/lang/String;)Ljava/util/HashMap;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$sanitize$0(Ljava/lang/String;)Ljava/util/HashMap;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public static sanitize(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 4

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-string v1, "sanitized-sql-map"

    .line 8
    .line 9
    invoke-static {v1, v0}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext;->computeIfAbsent(Ljava/lang/String;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Ljava/util/Map;

    .line 14
    .line 15
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizerUtil;->sanitizer:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;

    .line 16
    .line 17
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    new-instance v2, Lfx0/e;

    .line 21
    .line 22
    const/4 v3, 0x3

    .line 23
    invoke-direct {v2, v1, v3}, Lfx0/e;-><init>(Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    invoke-interface {v0, p0, v2}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 31
    .line 32
    return-object p0
.end method
