.class public final synthetic Lio/opentelemetry/sdk/logs/export/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic a:Ljava/util/Queue;


# direct methods
.method public synthetic constructor <init>(Ljava/util/Queue;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/export/a;->a:Ljava/util/Queue;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/a;->a:Ljava/util/Queue;

    .line 2
    .line 3
    check-cast p1, Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 4
    .line 5
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->a(Ljava/util/Queue;Lio/opentelemetry/api/metrics/ObservableLongMeasurement;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
