.class public final Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/Aggregation;
.implements Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;


# static fields
.field private static final INSTANCE:Lio/opentelemetry/sdk/metrics/Aggregation;

.field private static final logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;->INSTANCE:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 9
    .line 10
    const-class v1, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-static {v1}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 24
    .line 25
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

.method public static getInstance()Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;->INSTANCE:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 2
    .line 3
    return-object v0
.end method

.method private static resolve(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Z)Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation$1;->$SwitchMap$io$opentelemetry$sdk$metrics$InstrumentType:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    aget v0, v0, v1

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object p1, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 17
    .line 18
    sget-object v0, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 19
    .line 20
    new-instance v1, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v2, "Unable to find default aggregation for instrument: "

    .line 23
    .line 24
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/DropAggregation;->getInstance()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :pswitch_0
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/LastValueAggregation;->getInstance()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_1
    if-eqz p1, :cond_0

    .line 48
    .line 49
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getAdvice()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;->getExplicitBucketBoundaries()Ljava/util/List;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-eqz p1, :cond_0

    .line 58
    .line 59
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getAdvice()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;->getExplicitBucketBoundaries()Ljava/util/List;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/view/ExplicitBucketHistogramAggregation;->create(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :cond_0
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/ExplicitBucketHistogramAggregation;->getDefault()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0

    .line 77
    :pswitch_2
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/SumAggregation;->getInstance()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public createAggregator(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/common/export/MemoryMode;)Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T::",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">(",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;",
            "Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;",
            "Lio/opentelemetry/sdk/common/export/MemoryMode;",
            ")",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator<",
            "TT;>;"
        }
    .end annotation

    .line 1
    const/4 p0, 0x1

    .line 2
    invoke-static {p1, p0}, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;->resolve(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Z)Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;->createAggregator(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/common/export/MemoryMode;)Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public isCompatibleWithInstrument(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    invoke-static {p1, p0}, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;->resolve(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Z)Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;->isCompatibleWithInstrument(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "DefaultAggregation"

    .line 2
    .line 3
    return-object p0
.end method
