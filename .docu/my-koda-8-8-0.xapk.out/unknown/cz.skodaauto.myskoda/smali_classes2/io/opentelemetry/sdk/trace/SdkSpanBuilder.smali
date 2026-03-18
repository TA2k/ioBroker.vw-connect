.class Lio/opentelemetry/sdk/trace/SdkSpanBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/trace/SpanBuilder;


# instance fields
.field private attributes:Lio/opentelemetry/sdk/internal/AttributesMap;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

.field private links:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private parent:Lio/opentelemetry/context/Context;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private spanKind:Lio/opentelemetry/api/trace/SpanKind;

.field private final spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

.field private final spanName:Ljava/lang/String;

.field private startEpochNanos:J

.field private totalNumberOfLinksAdded:I

.field private final tracerSharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/trace/SpanLimits;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lio/opentelemetry/api/trace/SpanKind;->INTERNAL:Lio/opentelemetry/api/trace/SpanKind;

    .line 5
    .line 6
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanKind:Lio/opentelemetry/api/trace/SpanKind;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->totalNumberOfLinksAdded:I

    .line 10
    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    iput-wide v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->startEpochNanos:J

    .line 14
    .line 15
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanName:Ljava/lang/String;

    .line 16
    .line 17
    iput-object p2, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 18
    .line 19
    iput-object p3, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->tracerSharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 20
    .line 21
    iput-object p4, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 22
    .line 23
    return-void
.end method

.method private addLink(Lio/opentelemetry/sdk/trace/data/LinkData;)V
    .locals 2

    .line 12
    iget v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->totalNumberOfLinksAdded:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->totalNumberOfLinksAdded:I

    .line 13
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->links:Ljava/util/List;

    if-nez v0, :cond_0

    .line 14
    new-instance v0, Ljava/util/ArrayList;

    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfLinks()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->links:Ljava/util/List;

    .line 15
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->links:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfLinks()I

    move-result v1

    if-ne v0, v1, :cond_1

    return-void

    .line 16
    :cond_1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->links:Ljava/util/List;

    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method private attributes()Lio/opentelemetry/sdk/internal/AttributesMap;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 6
    .line 7
    invoke-virtual {v0}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributes()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    int-to-long v0, v0

    .line 12
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 13
    .line 14
    invoke-virtual {v2}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxAttributeValueLength()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    invoke-static {v0, v1, v2}, Lio/opentelemetry/sdk/internal/AttributesMap;->create(JI)Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 23
    .line 24
    :cond_0
    return-object v0
.end method

.method public static synthetic b(Lio/opentelemetry/sdk/trace/SdkSpanBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->lambda$startSpan$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static isRecording(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;)Z
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;->RECORD_ONLY:Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;->RECORD_AND_SAMPLE:Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public static isSampled(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;)Z
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;->RECORD_AND_SAMPLE:Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method private synthetic lambda$startSpan$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->attributes()Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/internal/AttributesMap;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public addLink(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 1

    if-eqz p1, :cond_1

    .line 1
    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    .line 2
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->create(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/sdk/trace/data/LinkData;

    move-result-object p1

    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->addLink(Lio/opentelemetry/sdk/trace/data/LinkData;)V

    :cond_1
    :goto_0
    return-object p0
.end method

.method public addLink(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 3

    if-eqz p1, :cond_2

    .line 3
    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    if-nez p2, :cond_1

    .line 4
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object p2

    .line 5
    :cond_1
    invoke-interface {p2}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v0

    .line 6
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 7
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributesPerLink()I

    move-result v1

    iget-object v2, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 8
    invoke-virtual {v2}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxAttributeValueLength()I

    move-result v2

    .line 9
    invoke-static {p2, v1, v2}, Lio/opentelemetry/sdk/internal/AttributeUtil;->applyAttributesLimit(Lio/opentelemetry/api/common/Attributes;II)Lio/opentelemetry/api/common/Attributes;

    move-result-object p2

    .line 10
    invoke-static {p1, p2, v0}, Lio/opentelemetry/sdk/trace/data/LinkData;->create(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/LinkData;

    move-result-object p1

    .line 11
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->addLink(Lio/opentelemetry/sdk/trace/data/LinkData;)V

    :cond_2
    :goto_0
    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/trace/SpanBuilder;"
        }
    .end annotation

    if-eqz p1, :cond_1

    .line 5
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1

    if-nez p2, :cond_0

    goto :goto_0

    .line 6
    :cond_0
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->attributes()Lio/opentelemetry/sdk/internal/AttributesMap;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/internal/AttributesMap;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    :goto_0
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;D)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 3
    invoke-static {p1}, Lio/opentelemetry/api/common/AttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;J)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 2
    invoke-static {p1}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-static {p1}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;Z)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 4
    invoke-static {p1}, Lio/opentelemetry/api/common/AttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setNoParent()Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/context/Context;->root()Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->parent:Lio/opentelemetry/context/Context;

    .line 6
    .line 7
    return-object p0
.end method

.method public setParent(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-object p0

    .line 4
    :cond_0
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->parent:Lio/opentelemetry/context/Context;

    .line 5
    .line 6
    return-object p0
.end method

.method public setSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-object p0

    .line 4
    :cond_0
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanKind:Lio/opentelemetry/api/trace/SpanKind;

    .line 5
    .line 6
    return-object p0
.end method

.method public setStartTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-ltz v0, :cond_1

    .line 6
    .line 7
    if-nez p3, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 11
    .line 12
    .line 13
    move-result-wide p1

    .line 14
    iput-wide p1, p0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->startEpochNanos:J

    .line 15
    .line 16
    :cond_1
    :goto_0
    return-object p0
.end method

.method public startSpan()Lio/opentelemetry/api/trace/Span;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->parent:Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    :cond_0
    move-object v3, v1

    .line 12
    invoke-static {v3}, Lio/opentelemetry/api/trace/Span;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-interface {v1}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 17
    .line 18
    .line 19
    move-result-object v9

    .line 20
    iget-object v2, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->tracerSharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 21
    .line 22
    invoke-virtual {v2}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getIdGenerator()Lio/opentelemetry/sdk/trace/IdGenerator;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/IdGenerator;->generateSpanId()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v11

    .line 30
    invoke-interface {v9}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    if-nez v4, :cond_1

    .line 35
    .line 36
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/IdGenerator;->generateTraceId()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    :goto_0
    move-object v4, v2

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    invoke-interface {v9}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    goto :goto_0

    .line 47
    :goto_1
    iget-object v10, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->links:Ljava/util/List;

    .line 48
    .line 49
    if-nez v10, :cond_2

    .line 50
    .line 51
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 52
    .line 53
    :goto_2
    move-object v8, v2

    .line 54
    goto :goto_3

    .line 55
    :cond_2
    invoke-static {v10}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    goto :goto_2

    .line 60
    :goto_3
    const/4 v12, 0x0

    .line 61
    iput-object v12, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->links:Ljava/util/List;

    .line 62
    .line 63
    iget-object v2, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 64
    .line 65
    if-nez v2, :cond_3

    .line 66
    .line 67
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    :cond_3
    move-object v7, v2

    .line 72
    iget-object v2, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->tracerSharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 73
    .line 74
    invoke-virtual {v2}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getSampler()Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    iget-object v5, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanName:Ljava/lang/String;

    .line 79
    .line 80
    iget-object v6, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanKind:Lio/opentelemetry/api/trace/SpanKind;

    .line 81
    .line 82
    invoke-interface/range {v2 .. v8}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->shouldSample(Lio/opentelemetry/context/Context;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/samplers/SamplingResult;->getDecision()Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    invoke-interface {v9}, Lio/opentelemetry/api/trace/SpanContext;->getTraceState()Lio/opentelemetry/api/trace/TraceState;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    invoke-interface {v2, v6}, Lio/opentelemetry/sdk/trace/samplers/SamplingResult;->getUpdatedTraceState(Lio/opentelemetry/api/trace/TraceState;)Lio/opentelemetry/api/trace/TraceState;

    .line 95
    .line 96
    .line 97
    move-result-object v13

    .line 98
    invoke-static {v5}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->isSampled(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;)Z

    .line 99
    .line 100
    .line 101
    move-result v6

    .line 102
    if-eqz v6, :cond_4

    .line 103
    .line 104
    invoke-static {}, Lio/opentelemetry/api/trace/TraceFlags;->getSampled()Lio/opentelemetry/api/trace/TraceFlags;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    goto :goto_4

    .line 109
    :cond_4
    invoke-static {}, Lio/opentelemetry/api/trace/TraceFlags;->getDefault()Lio/opentelemetry/api/trace/TraceFlags;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    :goto_4
    iget-object v7, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->tracerSharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 114
    .line 115
    invoke-virtual {v7}, Lio/opentelemetry/sdk/trace/TracerSharedState;->isIdGeneratorSafeToSkipIdValidation()Z

    .line 116
    .line 117
    .line 118
    move-result v15

    .line 119
    const/4 v14, 0x0

    .line 120
    move-object/from16 v18, v10

    .line 121
    .line 122
    move-object v10, v4

    .line 123
    move-object/from16 v4, v18

    .line 124
    .line 125
    move-object/from16 v18, v12

    .line 126
    .line 127
    move-object v12, v6

    .line 128
    move-object/from16 v6, v18

    .line 129
    .line 130
    invoke-static/range {v10 .. v15}, Lio/opentelemetry/api/internal/ImmutableSpanContext;->create(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;ZZ)Lio/opentelemetry/api/trace/SpanContext;

    .line 131
    .line 132
    .line 133
    move-result-object v7

    .line 134
    invoke-static {v5}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->isRecording(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;)Z

    .line 135
    .line 136
    .line 137
    move-result v5

    .line 138
    if-nez v5, :cond_5

    .line 139
    .line 140
    invoke-static {v7}, Lio/opentelemetry/api/trace/Span;->wrap(Lio/opentelemetry/api/trace/SpanContext;)Lio/opentelemetry/api/trace/Span;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    return-object v0

    .line 145
    :cond_5
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/samplers/SamplingResult;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    invoke-interface {v2}, Lio/opentelemetry/api/common/Attributes;->isEmpty()Z

    .line 150
    .line 151
    .line 152
    move-result v5

    .line 153
    if-nez v5, :cond_6

    .line 154
    .line 155
    new-instance v5, Lio/opentelemetry/sdk/trace/c;

    .line 156
    .line 157
    const/4 v8, 0x0

    .line 158
    invoke-direct {v5, v0, v8}, Lio/opentelemetry/sdk/trace/c;-><init>(Ljava/lang/Object;I)V

    .line 159
    .line 160
    .line 161
    invoke-interface {v2, v5}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    .line 162
    .line 163
    .line 164
    :cond_6
    iget-object v13, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 165
    .line 166
    iput-object v6, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->attributes:Lio/opentelemetry/sdk/internal/AttributesMap;

    .line 167
    .line 168
    move-object v2, v7

    .line 169
    move-object v7, v3

    .line 170
    iget-object v3, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanName:Ljava/lang/String;

    .line 171
    .line 172
    move-object v14, v4

    .line 173
    iget-object v4, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 174
    .line 175
    iget-object v5, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanKind:Lio/opentelemetry/api/trace/SpanKind;

    .line 176
    .line 177
    iget-object v8, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->spanLimits:Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 178
    .line 179
    iget-object v6, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->tracerSharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 180
    .line 181
    invoke-virtual {v6}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getActiveSpanProcessor()Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 182
    .line 183
    .line 184
    move-result-object v9

    .line 185
    iget-object v6, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->tracerSharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 186
    .line 187
    invoke-virtual {v6}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getExceptionAttributesResolver()Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 188
    .line 189
    .line 190
    move-result-object v10

    .line 191
    iget-object v6, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->tracerSharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 192
    .line 193
    invoke-virtual {v6}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getClock()Lio/opentelemetry/sdk/common/Clock;

    .line 194
    .line 195
    .line 196
    move-result-object v11

    .line 197
    iget-object v6, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->tracerSharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 198
    .line 199
    invoke-virtual {v6}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 200
    .line 201
    .line 202
    move-result-object v12

    .line 203
    iget v15, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->totalNumberOfLinksAdded:I

    .line 204
    .line 205
    move-object v6, v1

    .line 206
    iget-wide v0, v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;->startEpochNanos:J

    .line 207
    .line 208
    move-wide/from16 v16, v0

    .line 209
    .line 210
    invoke-static/range {v2 .. v17}, Lio/opentelemetry/sdk/trace/SdkSpan;->startSpan(Lio/opentelemetry/api/trace/SpanContext;Ljava/lang/String;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/Span;Lio/opentelemetry/context/Context;Lio/opentelemetry/sdk/trace/SpanLimits;Lio/opentelemetry/sdk/trace/SpanProcessor;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/internal/AttributesMap;Ljava/util/List;IJ)Lio/opentelemetry/sdk/trace/SdkSpan;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    return-object v0
.end method
