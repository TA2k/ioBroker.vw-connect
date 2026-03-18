.class public final synthetic Lio/opentelemetry/sdk/metrics/internal/state/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic a:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

.field public final synthetic b:J

.field public final synthetic c:J


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/d;->a:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 5
    .line 6
    iput-wide p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/d;->b:J

    .line 7
    .line 8
    iput-wide p4, p0, Lio/opentelemetry/sdk/metrics/internal/state/d;->c:J

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 6

    .line 1
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/state/d;->c:J

    .line 2
    .line 3
    move-object v5, p1

    .line 4
    check-cast v5, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/d;->a:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 7
    .line 8
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/d;->b:J

    .line 9
    .line 10
    invoke-static/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->b(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJLio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method
