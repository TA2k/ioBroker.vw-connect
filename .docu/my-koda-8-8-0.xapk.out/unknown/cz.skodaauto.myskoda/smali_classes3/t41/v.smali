.class public final Lt41/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/MonitorNotifier;


# instance fields
.field public final synthetic a:Lt41/z;


# direct methods
.method public constructor <init>(Lt41/z;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt41/v;->a:Lt41/z;

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lt41/v;Lt41/b;Z)V
    .locals 1

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    new-instance p2, Landroid/content/Intent;

    .line 4
    .line 5
    const-string v0, "technology.cariad.cat.beaconscanner.action.BEACON_LOST"

    .line 6
    .line 7
    invoke-direct {p2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    new-instance p2, Landroid/content/Intent;

    .line 12
    .line 13
    const-string v0, "technology.cariad.cat.beaconscanner.action.BEACON_FOUND"

    .line 14
    .line 15
    invoke-direct {p2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    :goto_0
    const-string v0, "EXTRA_BEACON"

    .line 19
    .line 20
    invoke-virtual {p2, v0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lt41/v;->a:Lt41/z;

    .line 24
    .line 25
    iget-object p0, p0, Lt41/z;->d:Landroid/content/Context;

    .line 26
    .line 27
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance v0, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string p1, ".beaconscanner.permission.BEACONS"

    .line 40
    .line 41
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-virtual {p0, p2, p1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    return-void
.end method


# virtual methods
.method public final b(Lorg/altbeacon/beacon/Region;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lt41/v;->a:Lt41/z;

    .line 2
    .line 3
    iget-object v1, v0, Lt41/z;->j:Ljava/util/Set;

    .line 4
    .line 5
    invoke-interface {v1, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_1

    .line 10
    .line 11
    iget-object v1, v0, Lt41/z;->k:Ljava/util/Set;

    .line 12
    .line 13
    invoke-interface {v1, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v5, Lt41/s;

    .line 21
    .line 22
    const/4 v1, 0x2

    .line 23
    invoke-direct {v5, v1, p1}, Lt41/s;-><init>(ILorg/altbeacon/beacon/Region;)V

    .line 24
    .line 25
    .line 26
    new-instance v2, Lt51/j;

    .line 27
    .line 28
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v7

    .line 32
    const-string v3, "getName(...)"

    .line 33
    .line 34
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v8

    .line 38
    const-string v3, "BeaconScanner"

    .line 39
    .line 40
    sget-object v4, Lt51/f;->a:Lt51/f;

    .line 41
    .line 42
    const/4 v6, 0x0

    .line 43
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 47
    .line 48
    .line 49
    iget-object v2, v0, Lt41/z;->k:Ljava/util/Set;

    .line 50
    .line 51
    invoke-static {v2, p1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    iput-object v2, v0, Lt41/z;->k:Ljava/util/Set;

    .line 56
    .line 57
    sget-object v2, Lvy0/p0;->a:Lcz0/e;

    .line 58
    .line 59
    sget-object v2, Laz0/m;->a:Lwy0/c;

    .line 60
    .line 61
    new-instance v3, Lt41/t;

    .line 62
    .line 63
    const/4 v4, 0x0

    .line 64
    invoke-direct {v3, v0, p1, p0, v4}, Lt41/t;-><init>(Lt41/z;Lorg/altbeacon/beacon/Region;Lt41/v;Lkotlin/coroutines/Continuation;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v0, v2, v4, v3, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 68
    .line 69
    .line 70
    :cond_1
    :goto_0
    return-void
.end method

.method public final c(Lorg/altbeacon/beacon/Region;)V
    .locals 12

    .line 1
    iget-object v0, p0, Lt41/v;->a:Lt41/z;

    .line 2
    .line 3
    iget-object v1, v0, Lt41/z;->k:Ljava/util/Set;

    .line 4
    .line 5
    invoke-interface {v1, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object v1, v0, Lt41/z;->k:Ljava/util/Set;

    .line 13
    .line 14
    invoke-static {v1, p1}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    iput-object v1, v0, Lt41/z;->k:Ljava/util/Set;

    .line 19
    .line 20
    sget-object v1, Lvy0/p0;->a:Lcz0/e;

    .line 21
    .line 22
    sget-object v1, Laz0/m;->a:Lwy0/c;

    .line 23
    .line 24
    new-instance v2, Lt41/u;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    invoke-direct {v2, v0, p1, v4, v3}, Lt41/u;-><init>(Lt41/z;Lorg/altbeacon/beacon/Region;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    invoke-static {v0, v1, v4, v2, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 33
    .line 34
    .line 35
    iget-object v2, v0, Lt41/z;->j:Ljava/util/Set;

    .line 36
    .line 37
    invoke-interface {v2, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    invoke-static {p1}, Lkp/i9;->i(Lorg/altbeacon/beacon/Region;)Lt41/b;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    new-instance v8, Lo51/c;

    .line 48
    .line 49
    const/16 v5, 0x1a

    .line 50
    .line 51
    invoke-direct {v8, v5, p1, v2}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    new-instance v5, Lt51/j;

    .line 55
    .line 56
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v10

    .line 60
    const-string v6, "getName(...)"

    .line 61
    .line 62
    invoke-static {v6}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v11

    .line 66
    const-string v6, "BeaconScanner"

    .line 67
    .line 68
    sget-object v7, Lt51/f;->a:Lt51/f;

    .line 69
    .line 70
    const/4 v9, 0x0

    .line 71
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 75
    .line 76
    .line 77
    iget-object v5, v0, Lt41/z;->m:Ljava/util/LinkedHashMap;

    .line 78
    .line 79
    invoke-interface {v5, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    iget-object v5, v0, Lt41/z;->n:Ljava/util/LinkedHashMap;

    .line 83
    .line 84
    invoke-interface {v5, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    new-instance v5, Ls10/a0;

    .line 88
    .line 89
    const/4 v6, 0x3

    .line 90
    invoke-direct {v5, v6, v0, v2, v4}, Ls10/a0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 91
    .line 92
    .line 93
    invoke-static {v0, v4, v4, v5, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 94
    .line 95
    .line 96
    new-instance v2, Lt41/t;

    .line 97
    .line 98
    invoke-direct {v2, v0, p0, p1, v4}, Lt41/t;-><init>(Lt41/z;Lt41/v;Lorg/altbeacon/beacon/Region;Lkotlin/coroutines/Continuation;)V

    .line 99
    .line 100
    .line 101
    invoke-static {v0, v1, v4, v2, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 102
    .line 103
    .line 104
    :cond_1
    :goto_0
    return-void
.end method

.method public final didDetermineStateForRegion(ILorg/altbeacon/beacon/Region;)V
    .locals 8

    .line 1
    const-string v0, "region"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Lba0/h;

    .line 7
    .line 8
    const/4 v0, 0x7

    .line 9
    invoke-direct {v4, p2, p1, v0}, Lba0/h;-><init>(Ljava/lang/Object;II)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string v0, "getName(...)"

    .line 19
    .line 20
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "BeaconScanner"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    const/4 v0, 0x1

    .line 36
    if-ne p1, v0, :cond_0

    .line 37
    .line 38
    invoke-virtual {p0, p2}, Lt41/v;->b(Lorg/altbeacon/beacon/Region;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_0
    invoke-virtual {p0, p2}, Lt41/v;->c(Lorg/altbeacon/beacon/Region;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public final didEnterRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 8

    .line 1
    const-string v0, "region"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Lt41/s;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {v4, v0, p1}, Lt41/s;-><init>(ILorg/altbeacon/beacon/Region;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string v0, "getName(...)"

    .line 19
    .line 20
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "BeaconScanner"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lt41/v;->b(Lorg/altbeacon/beacon/Region;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final didExitRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 8

    .line 1
    const-string v0, "region"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Lt41/s;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    invoke-direct {v4, v0, p1}, Lt41/s;-><init>(ILorg/altbeacon/beacon/Region;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string v0, "getName(...)"

    .line 19
    .line 20
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "BeaconScanner"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lt41/v;->c(Lorg/altbeacon/beacon/Region;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method
