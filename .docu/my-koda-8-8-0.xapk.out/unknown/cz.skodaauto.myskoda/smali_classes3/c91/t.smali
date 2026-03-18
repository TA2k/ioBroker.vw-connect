.class public final Lc91/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/data/LogRecordData;


# instance fields
.field public final synthetic a:Lc91/s;


# direct methods
.method public constructor <init>(Lc91/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc91/t;->a:Lc91/s;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/s;->e:Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getBody()Lio/opentelemetry/sdk/logs/data/Body;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/s;->d:Lio/opentelemetry/sdk/logs/data/Body;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getBodyValue()Lio/opentelemetry/api/common/Value;
    .locals 3

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/s;->d:Lio/opentelemetry/sdk/logs/data/Body;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p0, :cond_1

    .line 7
    .line 8
    invoke-interface {p0}, Lio/opentelemetry/sdk/logs/data/Body;->getType()Lio/opentelemetry/sdk/logs/data/Body$Type;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    sget-object v2, Lio/opentelemetry/sdk/logs/data/Body$Type;->EMPTY:Lio/opentelemetry/sdk/logs/data/Body$Type;

    .line 13
    .line 14
    if-ne v1, v2, :cond_0

    .line 15
    .line 16
    return-object v0

    .line 17
    :cond_0
    invoke-interface {p0}, Lio/opentelemetry/sdk/logs/data/Body;->asString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-static {p0}, Lio/opentelemetry/api/common/Value;->of(Ljava/lang/String;)Lio/opentelemetry/api/common/Value;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_1
    return-object v0
.end method

.method public final getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 2

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-object v0, p0, Lc91/s;->g:Ljava/lang/String;

    .line 4
    .line 5
    invoke-static {v0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->builder(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lc91/s;->h:Ljava/lang/String;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setVersion(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 14
    .line 15
    .line 16
    :cond_0
    iget-object v1, p0, Lc91/s;->i:Ljava/lang/String;

    .line 17
    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 21
    .line 22
    .line 23
    :cond_1
    iget-object p0, p0, Lc91/s;->j:Lio/opentelemetry/api/common/Attributes;

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->build()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "build(...)"

    .line 34
    .line 35
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-object p0
.end method

.method public final getObservedTimestampEpochNanos()J
    .locals 2

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-wide v0, p0, Lc91/s;->l:J

    .line 4
    .line 5
    return-wide v0
.end method

.method public final getResource()Lio/opentelemetry/sdk/resources/Resource;
    .locals 1

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-object v0, p0, Lc91/s;->m:Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    iget-object p0, p0, Lc91/s;->n:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {v0, p0}, Lio/opentelemetry/sdk/resources/Resource;->create(Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Lio/opentelemetry/sdk/resources/Resource;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v0, "create(...)"

    .line 12
    .line 13
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public final getSeverity()Lio/opentelemetry/api/logs/Severity;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/s;->b:Lio/opentelemetry/api/logs/Severity;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getSeverityText()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/s;->c:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/s;->a:Lio/opentelemetry/api/trace/SpanContext;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getTimestampEpochNanos()J
    .locals 2

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget-wide v0, p0, Lc91/s;->k:J

    .line 4
    .line 5
    return-wide v0
.end method

.method public final getTotalAttributeCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/t;->a:Lc91/s;

    .line 2
    .line 3
    iget p0, p0, Lc91/s;->f:I

    .line 4
    .line 5
    return p0
.end method
