.class public final Lt41/u;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt41/z;

.field public final synthetic f:Lorg/altbeacon/beacon/Region;


# direct methods
.method public synthetic constructor <init>(Lt41/z;Lorg/altbeacon/beacon/Region;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lt41/u;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt41/u;->e:Lt41/z;

    .line 4
    .line 5
    iput-object p2, p0, Lt41/u;->f:Lorg/altbeacon/beacon/Region;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Lt41/u;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lt41/u;

    .line 7
    .line 8
    iget-object v0, p0, Lt41/u;->f:Lorg/altbeacon/beacon/Region;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lt41/u;->e:Lt41/z;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lt41/u;-><init>(Lt41/z;Lorg/altbeacon/beacon/Region;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lt41/u;

    .line 18
    .line 19
    iget-object v0, p0, Lt41/u;->f:Lorg/altbeacon/beacon/Region;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lt41/u;->e:Lt41/z;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lt41/u;-><init>(Lt41/z;Lorg/altbeacon/beacon/Region;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lt41/u;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lt41/u;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lt41/u;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lt41/u;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lt41/u;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lt41/u;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lt41/u;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    return-object p1

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lt41/u;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lt41/u;->f:Lorg/altbeacon/beacon/Region;

    .line 4
    .line 5
    iget-object p0, p0, Lt41/u;->e:Lt41/z;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lt41/z;->a()Lorg/altbeacon/beacon/BeaconManager;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0, v1}, Lorg/altbeacon/beacon/BeaconManager;->stopMonitoring(Lorg/altbeacon/beacon/Region;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v1}, Lorg/altbeacon/beacon/BeaconManager;->stopRangingBeacons(Lorg/altbeacon/beacon/Region;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 27
    .line 28
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Lt41/z;->a()Lorg/altbeacon/beacon/BeaconManager;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p0, v1}, Lorg/altbeacon/beacon/BeaconManager;->stopRangingBeacons(Lorg/altbeacon/beacon/Region;)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
