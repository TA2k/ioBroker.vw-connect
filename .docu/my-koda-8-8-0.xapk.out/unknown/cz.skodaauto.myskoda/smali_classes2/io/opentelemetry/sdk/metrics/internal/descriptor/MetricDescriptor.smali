.class public abstract Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# instance fields
.field private hashcode:I

.field private final viewSourceInfo:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->viewSourceInfo:Ljava/util/concurrent/atomic/AtomicReference;

    .line 10
    .line 11
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;
    .locals 3

    .line 6
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/View;->getName()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getName()Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/View;->getName()Ljava/lang/String;

    move-result-object v0

    .line 7
    :goto_0
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/View;->getDescription()Ljava/lang/String;

    move-result-object v1

    if-nez v1, :cond_1

    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getDescription()Ljava/lang/String;

    move-result-object v1

    goto :goto_1

    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/View;->getDescription()Ljava/lang/String;

    move-result-object v1

    .line 8
    :goto_1
    new-instance v2, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_MetricDescriptor;

    invoke-direct {v2, v0, v1, p0, p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_MetricDescriptor;-><init>(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)V

    .line 9
    iget-object p0, v2, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->viewSourceInfo:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    return-object v2
.end method

.method public static create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;
    .locals 8

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/View;->builder()Lio/opentelemetry/sdk/metrics/ViewBuilder;

    move-result-object v0

    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/ViewBuilder;->build()Lio/opentelemetry/sdk/metrics/View;

    move-result-object v0

    .line 2
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;->fromCurrentStack()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    move-result-object v1

    sget-object v5, Lio/opentelemetry/sdk/metrics/InstrumentType;->OBSERVABLE_GAUGE:Lio/opentelemetry/sdk/metrics/InstrumentType;

    sget-object v6, Lio/opentelemetry/sdk/metrics/InstrumentValueType;->DOUBLE:Lio/opentelemetry/sdk/metrics/InstrumentValueType;

    .line 3
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;->empty()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

    move-result-object v7

    move-object v2, p0

    move-object v3, p1

    move-object v4, p2

    .line 4
    invoke-static/range {v2 .. v7}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/InstrumentType;Lio/opentelemetry/sdk/metrics/InstrumentValueType;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;)Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    move-result-object p0

    .line 5
    invoke-static {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->create(Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
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
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 11
    .line 12
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getName()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getName()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-virtual {v1, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getDescription()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getDescription()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_1

    .line 39
    .line 40
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-eqz v1, :cond_1

    .line 53
    .line 54
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    if-eqz p0, :cond_1

    .line 67
    .line 68
    return v0

    .line 69
    :cond_1
    return v2
.end method

.method public getAggregationName()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregationUtil;->aggregationName(Lio/opentelemetry/sdk/metrics/Aggregation;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public abstract getDescription()Ljava/lang/String;
.end method

.method public abstract getName()Ljava/lang/String;
.end method

.method public abstract getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;
.end method

.method public abstract getView()Lio/opentelemetry/sdk/metrics/View;
.end method

.method public final getViewSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->viewSourceInfo:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;->noSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :cond_0
    return-object p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->hashcode:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const v1, 0xf4243

    .line 20
    .line 21
    .line 22
    xor-int/2addr v0, v1

    .line 23
    mul-int/2addr v0, v1

    .line 24
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getDescription()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    xor-int/2addr v0, v2

    .line 33
    mul-int/2addr v0, v1

    .line 34
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    xor-int/2addr v0, v2

    .line 43
    mul-int/2addr v0, v1

    .line 44
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    xor-int/2addr v0, v1

    .line 53
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->hashcode:I

    .line 54
    .line 55
    :cond_0
    return v0
.end method
