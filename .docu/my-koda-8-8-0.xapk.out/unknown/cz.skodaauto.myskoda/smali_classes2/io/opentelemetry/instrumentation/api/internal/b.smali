.class public final synthetic Lio/opentelemetry/instrumentation/api/internal/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;


# instance fields
.field public final synthetic a:Ljava/util/function/BiConsumer;

.field public final synthetic b:Ljava/lang/String;

.field public final synthetic c:Ljava/util/function/Function;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/util/function/Function;Ljava/util/function/BiConsumer;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lio/opentelemetry/instrumentation/api/internal/b;->a:Ljava/util/function/BiConsumer;

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/b;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/internal/b;->c:Ljava/util/function/Function;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final create(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/b;->b:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/internal/b;->c:Ljava/util/function/Function;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/b;->a:Ljava/util/function/BiConsumer;

    .line 6
    .line 7
    invoke-static {p0, v0, v1, p1}, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->a(Ljava/util/function/BiConsumer;Ljava/lang/String;Ljava/util/function/Function;Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
