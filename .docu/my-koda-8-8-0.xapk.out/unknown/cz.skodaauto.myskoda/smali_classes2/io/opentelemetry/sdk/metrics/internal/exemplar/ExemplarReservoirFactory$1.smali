.class Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->filtered(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic val$filter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

.field final synthetic val$original:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$1;->val$filter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$1;->val$original:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public createDoubleExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleFilteredExemplarReservoir;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$1;->val$filter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$1;->val$original:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 6
    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->createDoubleExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleFilteredExemplarReservoir;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public createLongExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongFilteredExemplarReservoir;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$1;->val$filter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$1;->val$original:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 6
    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->createLongExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongFilteredExemplarReservoir;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method
