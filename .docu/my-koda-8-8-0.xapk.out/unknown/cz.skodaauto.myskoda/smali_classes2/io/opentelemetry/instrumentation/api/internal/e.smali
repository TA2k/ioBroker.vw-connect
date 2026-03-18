.class public final synthetic Lio/opentelemetry/instrumentation/api/internal/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/e;->d:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/e;->d:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->report()V

    .line 4
    .line 5
    .line 6
    return-void
.end method
