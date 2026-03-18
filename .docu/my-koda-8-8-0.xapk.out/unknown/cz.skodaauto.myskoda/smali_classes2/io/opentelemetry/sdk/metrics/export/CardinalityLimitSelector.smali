.class public interface abstract Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Ljava/lang/FunctionalInterface;
.end annotation


# direct methods
.method public static synthetic a(Lio/opentelemetry/sdk/metrics/InstrumentType;)I
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;->lambda$defaultCardinalityLimitSelector$0(Lio/opentelemetry/sdk/metrics/InstrumentType;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static defaultCardinalityLimitSelector()Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/export/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static synthetic lambda$defaultCardinalityLimitSelector$0(Lio/opentelemetry/sdk/metrics/InstrumentType;)I
    .locals 0

    .line 1
    const/16 p0, 0x7d0

    .line 2
    .line 3
    return p0
.end method


# virtual methods
.method public abstract getCardinalityLimit(Lio/opentelemetry/sdk/metrics/InstrumentType;)I
.end method
