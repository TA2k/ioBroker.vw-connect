.class public final synthetic Lxt/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcom/google/firebase/perf/session/gauges/GaugeManager;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Lau/i;


# direct methods
.method public synthetic constructor <init>(Lcom/google/firebase/perf/session/gauges/GaugeManager;Ljava/lang/String;Lau/i;I)V
    .locals 0

    .line 1
    iput p4, p0, Lxt/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxt/c;->e:Lcom/google/firebase/perf/session/gauges/GaugeManager;

    .line 4
    .line 5
    iput-object p2, p0, Lxt/c;->f:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Lxt/c;->g:Lau/i;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    .line 1
    iget v0, p0, Lxt/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxt/c;->f:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v1, p0, Lxt/c;->g:Lau/i;

    .line 9
    .line 10
    iget-object p0, p0, Lxt/c;->e:Lcom/google/firebase/perf/session/gauges/GaugeManager;

    .line 11
    .line 12
    invoke-static {p0, v0, v1}, Lcom/google/firebase/perf/session/gauges/GaugeManager;->a(Lcom/google/firebase/perf/session/gauges/GaugeManager;Ljava/lang/String;Lau/i;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    iget-object v0, p0, Lxt/c;->f:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v1, p0, Lxt/c;->g:Lau/i;

    .line 19
    .line 20
    iget-object p0, p0, Lxt/c;->e:Lcom/google/firebase/perf/session/gauges/GaugeManager;

    .line 21
    .line 22
    invoke-static {p0, v0, v1}, Lcom/google/firebase/perf/session/gauges/GaugeManager;->d(Lcom/google/firebase/perf/session/gauges/GaugeManager;Ljava/lang/String;Lau/i;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
