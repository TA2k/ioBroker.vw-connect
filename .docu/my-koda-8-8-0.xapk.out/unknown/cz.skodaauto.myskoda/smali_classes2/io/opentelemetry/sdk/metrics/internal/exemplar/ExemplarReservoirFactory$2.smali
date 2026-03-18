.class Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->noSamples()Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
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


# virtual methods
.method public createDoubleExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/NoopExemplarReservoir;->INSTANCE:Lio/opentelemetry/sdk/metrics/internal/exemplar/NoopExemplarReservoir;

    .line 2
    .line 3
    return-object p0
.end method

.method public createLongExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/NoopExemplarReservoir;->INSTANCE:Lio/opentelemetry/sdk/metrics/internal/exemplar/NoopExemplarReservoir;

    .line 2
    .line 3
    return-object p0
.end method
