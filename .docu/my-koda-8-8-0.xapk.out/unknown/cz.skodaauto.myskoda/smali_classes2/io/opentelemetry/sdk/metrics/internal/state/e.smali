.class public final synthetic Lio/opentelemetry/sdk/metrics/internal/state/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;

.field public final synthetic b:J

.field public final synthetic c:J

.field public final synthetic d:Z

.field public final synthetic e:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;JJZLjava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->a:Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;

    .line 5
    .line 6
    iput-wide p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->b:J

    .line 7
    .line 8
    iput-wide p4, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->c:J

    .line 9
    .line 10
    iput-boolean p6, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->d:Z

    .line 11
    .line 12
    iput-object p7, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->e:Ljava/util/List;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 9

    .line 1
    move-object v7, p1

    .line 2
    check-cast v7, Lio/opentelemetry/api/common/Attributes;

    .line 3
    .line 4
    move-object v8, p2

    .line 5
    check-cast v8, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 6
    .line 7
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->a:Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;

    .line 8
    .line 9
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->b:J

    .line 10
    .line 11
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->c:J

    .line 12
    .line 13
    iget-boolean v5, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->d:Z

    .line 14
    .line 15
    iget-object v6, p0, Lio/opentelemetry/sdk/metrics/internal/state/e;->e:Ljava/util/List;

    .line 16
    .line 17
    invoke-static/range {v0 .. v8}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;->b(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;JJZLjava/util/List;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
