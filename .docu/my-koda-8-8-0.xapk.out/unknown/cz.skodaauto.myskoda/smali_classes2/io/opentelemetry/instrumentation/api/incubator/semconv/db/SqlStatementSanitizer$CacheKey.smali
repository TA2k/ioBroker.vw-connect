.class abstract Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "CacheKey"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;-><init>(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public abstract getDialect()Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;
.end method

.method public abstract getStatement()Ljava/lang/String;
.end method
