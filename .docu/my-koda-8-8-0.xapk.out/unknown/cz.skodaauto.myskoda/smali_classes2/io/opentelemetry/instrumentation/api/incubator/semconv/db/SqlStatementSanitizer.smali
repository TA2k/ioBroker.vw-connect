.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;
    }
.end annotation


# static fields
.field private static final LARGE_STATEMENT_THRESHOLD:I = 0x2800

.field private static final sqlToStatementInfoCache:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/internal/cache/Cache<",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;",
            ">;"
        }
    .end annotation
.end field

.field private static final supportability:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;


# instance fields
.field private final statementSanitizationEnabled:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->instance()Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->supportability:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 6
    .line 7
    const/16 v0, 0x3e8

    .line 8
    .line 9
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->bounded(I)Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->sqlToStatementInfoCache:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 14
    .line 15
    return-void
.end method

.method private constructor <init>(Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->statementSanitizationEnabled:Z

    .line 5
    .line 6
    return-void
.end method

.method public static synthetic a(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->lambda$sanitize$0(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static create(Z)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;-><init>(Z)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static isCached(Ljava/lang/String;)Z
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->sqlToStatementInfoCache:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->DEFAULT:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 4
    .line 5
    invoke-static {p0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;->create(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-interface {v0, p0}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method private static synthetic lambda$sanitize$0(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->sanitizeImpl(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static sanitizeImpl(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->supportability:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 2
    .line 3
    const-string v1, "SqlStatementSanitizer cache miss"

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->incrementCounter(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->sanitize(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method


# virtual methods
.method public sanitize(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->DEFAULT:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    invoke-virtual {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->sanitize(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    move-result-object p0

    return-object p0
.end method

.method public sanitize(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 2
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 2
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->statementSanitizationEnabled:Z

    if-eqz p0, :cond_2

    if-nez p1, :cond_0

    goto :goto_0

    .line 3
    :cond_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p0

    const/16 v0, 0x2800

    if-le p0, v0, :cond_1

    .line 4
    invoke-static {p1, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->sanitizeImpl(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    move-result-object p0

    return-object p0

    .line 5
    :cond_1
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->sqlToStatementInfoCache:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 6
    invoke-static {p1, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;->create(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;

    move-result-object v0

    new-instance v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/b;

    invoke-direct {v1, p1, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/b;-><init>(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)V

    .line 7
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    return-object p0

    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 8
    invoke-static {p1, p0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    move-result-object p0

    return-object p0
.end method
