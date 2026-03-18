.class public final synthetic Lio/opentelemetry/sdk/metrics/export/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lio/opentelemetry/sdk/common/CompletableResultCode;

.field public final synthetic f:Lio/opentelemetry/sdk/common/CompletableResultCode;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lio/opentelemetry/sdk/metrics/export/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/export/e;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/export/e;->f:Lio/opentelemetry/sdk/common/CompletableResultCode;

    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/export/e;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;I)V
    .locals 0

    .line 2
    iput p4, p0, Lio/opentelemetry/sdk/metrics/export/e;->d:I

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/export/e;->g:Ljava/lang/Object;

    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/export/e;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/export/e;->f:Lio/opentelemetry/sdk/common/CompletableResultCode;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/export/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/export/e;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/export/e;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 11
    .line 12
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/export/e;->f:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 13
    .line 14
    invoke-static {v1, p0, v0}, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader;->h(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/export/e;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader;

    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/export/e;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 23
    .line 24
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/export/e;->f:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 25
    .line 26
    invoke-static {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader;->k(Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :pswitch_1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/export/e;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader$Scheduled;

    .line 33
    .line 34
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/export/e;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 35
    .line 36
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/export/e;->f:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 37
    .line 38
    invoke-static {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader$Scheduled;->a(Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader$Scheduled;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
