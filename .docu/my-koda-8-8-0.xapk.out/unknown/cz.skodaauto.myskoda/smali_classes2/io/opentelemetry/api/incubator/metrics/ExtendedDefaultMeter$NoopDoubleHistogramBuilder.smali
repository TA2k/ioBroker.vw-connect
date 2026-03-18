.class Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleHistogramBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "NoopDoubleHistogramBuilder"
.end annotation


# static fields
.field private static final NOOP:Lio/opentelemetry/api/metrics/DoubleHistogram;

.field private static final NOOP_LONG_HISTOGRAM_BUILDER:Lio/opentelemetry/api/metrics/LongHistogramBuilder;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleHistogram;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleHistogram;-><init>(Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$1;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleHistogramBuilder;->NOOP:Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 8
    .line 9
    new-instance v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongHistogramBuilder;

    .line 10
    .line 11
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongHistogramBuilder;-><init>(Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$1;)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleHistogramBuilder;->NOOP_LONG_HISTOGRAM_BUILDER:Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 15
    .line 16
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleHistogramBuilder;-><init>()V

    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/api/metrics/DoubleHistogram;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleHistogramBuilder;->NOOP:Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 2
    .line 3
    return-object p0
.end method

.method public ofLongs()Lio/opentelemetry/api/metrics/LongHistogramBuilder;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleHistogramBuilder;->NOOP_LONG_HISTOGRAM_BUILDER:Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 2
    .line 3
    return-object p0
.end method

.method public setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;
    .locals 0

    .line 1
    return-object p0
.end method
