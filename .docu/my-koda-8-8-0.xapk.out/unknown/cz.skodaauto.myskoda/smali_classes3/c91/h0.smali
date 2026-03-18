.class public final Lc91/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/data/SpanData;


# instance fields
.field public final synthetic a:Lc91/g0;


# direct methods
.method public constructor <init>(Lc91/g0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc91/h0;->a:Lc91/g0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/g0;->h:Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getEndEpochNanos()J
    .locals 2

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-wide v0, p0, Lc91/g0;->k:J

    .line 4
    .line 5
    return-wide v0
.end method

.method public final getEvents()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/g0;->i:Ljava/util/List;

    .line 4
    .line 5
    check-cast p0, Ljava/util/Collection;

    .line 6
    .line 7
    invoke-static {p0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final getInstrumentationLibraryInfo()Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lc91/h0;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/InstrumentationScopeUtil;->toInstrumentationLibraryInfo(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "toInstrumentationLibraryInfo(...)"

    .line 10
    .line 11
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 2

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object v0, p0, Lc91/g0;->p:Ljava/lang/String;

    .line 4
    .line 5
    invoke-static {v0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->builder(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lc91/g0;->q:Ljava/lang/String;

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
    iget-object v1, p0, Lc91/g0;->r:Ljava/lang/String;

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
    iget-object p0, p0, Lc91/g0;->s:Lio/opentelemetry/api/common/Attributes;

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

.method public final getKind()Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/g0;->b:Lio/opentelemetry/api/trace/SpanKind;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getLinks()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/g0;->j:Ljava/util/List;

    .line 4
    .line 5
    check-cast p0, Ljava/util/Collection;

    .line 6
    .line 7
    invoke-static {p0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/g0;->a:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/g0;->d:Lio/opentelemetry/api/trace/SpanContext;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getResource()Lio/opentelemetry/sdk/resources/Resource;
    .locals 1

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object v0, p0, Lc91/g0;->t:Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    iget-object p0, p0, Lc91/g0;->u:Ljava/lang/String;

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

.method public final getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object p0, p0, Lc91/g0;->c:Lio/opentelemetry/api/trace/SpanContext;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getStartEpochNanos()J
    .locals 2

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-wide v0, p0, Lc91/g0;->g:J

    .line 4
    .line 5
    return-wide v0
.end method

.method public final getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;
    .locals 1

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-object v0, p0, Lc91/g0;->f:Lio/opentelemetry/api/trace/StatusCode;

    .line 4
    .line 5
    iget-object p0, p0, Lc91/g0;->e:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {v0, p0}, Lio/opentelemetry/sdk/trace/data/StatusData;->create(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/sdk/trace/data/StatusData;

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

.method public final getTotalAttributeCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget p0, p0, Lc91/g0;->o:I

    .line 4
    .line 5
    return p0
.end method

.method public final getTotalRecordedEvents()I
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget p0, p0, Lc91/g0;->m:I

    .line 4
    .line 5
    return p0
.end method

.method public final getTotalRecordedLinks()I
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget p0, p0, Lc91/g0;->n:I

    .line 4
    .line 5
    return p0
.end method

.method public final hasEnded()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lc91/h0;->a:Lc91/g0;

    .line 2
    .line 3
    iget-boolean p0, p0, Lc91/g0;->l:Z

    .line 4
    .line 5
    return p0
.end method
