.class Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->fixedSizeReservoir(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic val$clock:Lio/opentelemetry/sdk/common/Clock;

.field final synthetic val$randomSupplier:Ljava/util/function/Supplier;

.field final synthetic val$size:I


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;->val$clock:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    iput p2, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;->val$size:I

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;->val$randomSupplier:Ljava/util/function/Supplier;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public createDoubleExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;->val$clock:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;->val$size:I

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;->val$randomSupplier:Ljava/util/function/Supplier;

    .line 6
    .line 7
    invoke-static {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;->create(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public createLongExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;->val$clock:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;->val$size:I

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;->val$randomSupplier:Ljava/util/function/Supplier;

    .line 6
    .line 7
    invoke-static {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;->create(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
