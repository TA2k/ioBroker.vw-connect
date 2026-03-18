.class final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final dialect:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

.field private final statement:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_1

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->statement:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->dialect:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 14
    .line 15
    const-string p1, "Null dialect"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0

    .line 21
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 22
    .line 23
    const-string p1, "Null statement"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->statement:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;->getStatement()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->dialect:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 25
    .line 26
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;->getDialect()Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_1

    .line 35
    .line 36
    return v0

    .line 37
    :cond_1
    return v2
.end method

.method public getDialect()Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->dialect:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 2
    .line 3
    return-object p0
.end method

.method public getStatement()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->statement:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->statement:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xf4243

    .line 8
    .line 9
    .line 10
    xor-int/2addr v0, v1

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->dialect:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    xor-int/2addr p0, v0

    .line 19
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "CacheKey{statement="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->statement:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", dialect="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoValue_SqlStatementSanitizer_CacheKey;->dialect:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, "}"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
