.class public final Lt41/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt41/o;
.implements Lvy0/b0;


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Lpx0/g;

.field public final f:Lez0/c;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/l1;

.field public final i:Lyy0/q1;

.field public j:Ljava/util/Set;

.field public k:Ljava/util/Set;

.field public l:Z

.field public final m:Ljava/util/LinkedHashMap;

.field public final n:Ljava/util/LinkedHashMap;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lvy0/i1;Lvy0/x;)V
    .locals 2

    .line 1
    const-string v0, "ioDispatcher"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lt41/z;->d:Landroid/content/Context;

    .line 10
    .line 11
    new-instance p1, Lvy0/k1;

    .line 12
    .line 13
    invoke-direct {p1, p2}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 14
    .line 15
    .line 16
    invoke-static {p1, p3}, Ljp/ce;->a(Lpx0/g;Lpx0/g;)Lpx0/g;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    new-instance p2, Lvy0/a0;

    .line 21
    .line 22
    const-string p3, "BeaconScanner"

    .line 23
    .line 24
    invoke-direct {p2, p3}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-interface {p1, p2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p2, Lil/i;

    .line 32
    .line 33
    invoke-direct {p2, p0}, Lil/i;-><init>(Lt41/z;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {p1, p2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iput-object p1, p0, Lt41/z;->e:Lpx0/g;

    .line 41
    .line 42
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    iput-object p1, p0, Lt41/z;->f:Lez0/c;

    .line 47
    .line 48
    sget-object p1, Lmx0/u;->d:Lmx0/u;

    .line 49
    .line 50
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    iput-object p2, p0, Lt41/z;->g:Lyy0/c2;

    .line 55
    .line 56
    new-instance p3, Lyy0/l1;

    .line 57
    .line 58
    invoke-direct {p3, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 59
    .line 60
    .line 61
    iput-object p3, p0, Lt41/z;->h:Lyy0/l1;

    .line 62
    .line 63
    const/4 p2, 0x7

    .line 64
    const/4 p3, 0x0

    .line 65
    const/4 v0, 0x0

    .line 66
    invoke-static {p3, p2, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    iput-object p2, p0, Lt41/z;->i:Lyy0/q1;

    .line 71
    .line 72
    iput-object p1, p0, Lt41/z;->j:Ljava/util/Set;

    .line 73
    .line 74
    iput-object p1, p0, Lt41/z;->k:Ljava/util/Set;

    .line 75
    .line 76
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 77
    .line 78
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 79
    .line 80
    .line 81
    iput-object p1, p0, Lt41/z;->m:Ljava/util/LinkedHashMap;

    .line 82
    .line 83
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 84
    .line 85
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 86
    .line 87
    .line 88
    iput-object p1, p0, Lt41/z;->n:Ljava/util/LinkedHashMap;

    .line 89
    .line 90
    new-instance p1, Lt41/p;

    .line 91
    .line 92
    invoke-direct {p1, p0}, Lt41/p;-><init>(Lt41/z;)V

    .line 93
    .line 94
    .line 95
    new-instance p2, Lt41/v;

    .line 96
    .line 97
    invoke-direct {p2, p0}, Lt41/v;-><init>(Lt41/z;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0}, Lt41/z;->a()Lorg/altbeacon/beacon/BeaconManager;

    .line 101
    .line 102
    .line 103
    move-result-object p3

    .line 104
    invoke-virtual {p3}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 105
    .line 106
    .line 107
    move-result-object p3

    .line 108
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser;

    .line 109
    .line 110
    invoke-direct {v0}, Lorg/altbeacon/beacon/BeaconParser;-><init>()V

    .line 111
    .line 112
    .line 113
    const-string v1, "m:2-3=0215,i:4-19,i:20-21,i:22-23,p:24-24"

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Lorg/altbeacon/beacon/BeaconParser;->setBeaconLayout(Ljava/lang/String;)Lorg/altbeacon/beacon/BeaconParser;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    invoke-interface {p3, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    invoke-virtual {p0}, Lt41/z;->a()Lorg/altbeacon/beacon/BeaconManager;

    .line 123
    .line 124
    .line 125
    move-result-object p3

    .line 126
    invoke-virtual {p3, p2}, Lorg/altbeacon/beacon/BeaconManager;->addMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {p0}, Lt41/z;->a()Lorg/altbeacon/beacon/BeaconManager;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    invoke-virtual {p2, p1}, Lorg/altbeacon/beacon/BeaconManager;->addRangeNotifier(Lorg/altbeacon/beacon/RangeNotifier;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p0}, Lt41/z;->a()Lorg/altbeacon/beacon/BeaconManager;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->revertSettings()V

    .line 141
    .line 142
    .line 143
    return-void
.end method

.method public static d(DLt41/b;)Lt41/g;
    .locals 3

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmpg-double v2, p0, v0

    .line 4
    .line 5
    if-gez v2, :cond_0

    .line 6
    .line 7
    new-instance p0, Lt41/f;

    .line 8
    .line 9
    invoke-direct {p0, p2}, Lt41/f;-><init>(Lt41/b;)V

    .line 10
    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    cmpg-double v0, v0, p0

    .line 14
    .line 15
    const-wide/high16 v1, 0x3fe0000000000000L    # 0.5

    .line 16
    .line 17
    if-gtz v0, :cond_1

    .line 18
    .line 19
    cmpg-double v0, p0, v1

    .line 20
    .line 21
    if-gtz v0, :cond_1

    .line 22
    .line 23
    new-instance p0, Lt41/e;

    .line 24
    .line 25
    invoke-direct {p0, p2}, Lt41/e;-><init>(Lt41/b;)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_1
    cmpg-double v0, v1, p0

    .line 30
    .line 31
    const-wide/high16 v1, 0x4014000000000000L    # 5.0

    .line 32
    .line 33
    if-gtz v0, :cond_2

    .line 34
    .line 35
    cmpg-double v0, p0, v1

    .line 36
    .line 37
    if-gtz v0, :cond_2

    .line 38
    .line 39
    new-instance p0, Lt41/d;

    .line 40
    .line 41
    invoke-direct {p0, p2}, Lt41/d;-><init>(Lt41/b;)V

    .line 42
    .line 43
    .line 44
    return-object p0

    .line 45
    :cond_2
    cmpl-double p0, p0, v1

    .line 46
    .line 47
    if-lez p0, :cond_3

    .line 48
    .line 49
    new-instance p0, Lt41/c;

    .line 50
    .line 51
    invoke-direct {p0, p2}, Lt41/c;-><init>(Lt41/b;)V

    .line 52
    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_3
    new-instance p0, Lt41/f;

    .line 56
    .line 57
    invoke-direct {p0, p2}, Lt41/f;-><init>(Lt41/b;)V

    .line 58
    .line 59
    .line 60
    return-object p0
.end method


# virtual methods
.method public final a()Lorg/altbeacon/beacon/BeaconManager;
    .locals 1

    .line 1
    iget-object p0, p0, Lt41/z;->d:Landroid/content/Context;

    .line 2
    .line 3
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "getInstanceForApplication(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final b()Ljava/util/ArrayList;
    .locals 2

    .line 1
    iget-object p0, p0, Lt41/z;->j:Ljava/util/Set;

    .line 2
    .line 3
    check-cast p0, Ljava/lang/Iterable;

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    const/16 v1, 0xa

    .line 8
    .line 9
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lorg/altbeacon/beacon/Region;

    .line 31
    .line 32
    invoke-static {v1}, Lkp/i9;->i(Lorg/altbeacon/beacon/Region;)Lt41/b;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    return-object v0
.end method

.method public final close()V
    .locals 7

    .line 1
    new-instance v3, Lqf0/d;

    .line 2
    .line 3
    const/16 v0, 0x18

    .line 4
    .line 5
    invoke-direct {v3, v0}, Lqf0/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "BeaconScanner"

    .line 21
    .line 22
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    new-instance v0, Lrp0/a;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    const/16 v2, 0xd

    .line 35
    .line 36
    invoke-direct {v0, p0, v1, v2}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Lt41/z;->e:Lpx0/g;

    .line 40
    .line 41
    invoke-static {v1, v0}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    const-string v0, "close()"

    .line 45
    .line 46
    invoke-static {p0, v0}, Lvy0/e0;->l(Lvy0/b0;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final f()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lt41/z;->b()Ljava/util/ArrayList;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-boolean p0, p0, Lt41/z;->l:Z

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final g(Ljava/util/List;Lrx0/c;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v4, p0

    .line 2
    .line 3
    move-object/from16 v0, p2

    .line 4
    .line 5
    const-string v1, "getName(...)"

    .line 6
    .line 7
    sget-object v7, Lt51/g;->a:Lt51/g;

    .line 8
    .line 9
    instance-of v2, v0, Lt41/w;

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Lt41/w;

    .line 15
    .line 16
    iget v3, v2, Lt41/w;->p:I

    .line 17
    .line 18
    const/high16 v5, -0x80000000

    .line 19
    .line 20
    and-int v6, v3, v5

    .line 21
    .line 22
    if-eqz v6, :cond_0

    .line 23
    .line 24
    sub-int/2addr v3, v5

    .line 25
    iput v3, v2, Lt41/w;->p:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v2, Lt41/w;

    .line 29
    .line 30
    invoke-direct {v2, v4, v0}, Lt41/w;-><init>(Lt41/z;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v0, v2, Lt41/w;->n:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v12, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v3, v2, Lt41/w;->p:I

    .line 38
    .line 39
    const/4 v13, 0x3

    .line 40
    const/4 v14, 0x2

    .line 41
    const/4 v15, 0x1

    .line 42
    const/4 v5, 0x0

    .line 43
    if-eqz v3, :cond_4

    .line 44
    .line 45
    if-eq v3, v15, :cond_3

    .line 46
    .line 47
    if-eq v3, v14, :cond_2

    .line 48
    .line 49
    if-ne v3, v13, :cond_1

    .line 50
    .line 51
    iget-object v1, v2, Lt41/w;->h:Ljava/util/Set;

    .line 52
    .line 53
    check-cast v1, Ljava/util/Set;

    .line 54
    .line 55
    iget-object v1, v2, Lt41/w;->g:Ljava/util/Set;

    .line 56
    .line 57
    check-cast v1, Ljava/util/Set;

    .line 58
    .line 59
    iget-object v1, v2, Lt41/w;->f:Ljava/util/Set;

    .line 60
    .line 61
    check-cast v1, Ljava/util/Set;

    .line 62
    .line 63
    iget-object v1, v2, Lt41/w;->e:Lez0/a;

    .line 64
    .line 65
    iget-object v2, v2, Lt41/w;->d:Ljava/util/List;

    .line 66
    .line 67
    check-cast v2, Ljava/util/List;

    .line 68
    .line 69
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 70
    .line 71
    .line 72
    const/4 v14, 0x0

    .line 73
    goto/16 :goto_d

    .line 74
    .line 75
    :catchall_0
    move-exception v0

    .line 76
    :goto_1
    const/4 v14, 0x0

    .line 77
    goto/16 :goto_e

    .line 78
    .line 79
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 80
    .line 81
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 82
    .line 83
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v0

    .line 87
    :cond_2
    iget v1, v2, Lt41/w;->m:I

    .line 88
    .line 89
    iget v3, v2, Lt41/w;->l:I

    .line 90
    .line 91
    iget v5, v2, Lt41/w;->k:I

    .line 92
    .line 93
    iget-object v7, v2, Lt41/w;->j:Lorg/altbeacon/beacon/Region;

    .line 94
    .line 95
    iget-object v8, v2, Lt41/w;->i:Ljava/util/Iterator;

    .line 96
    .line 97
    iget-object v9, v2, Lt41/w;->h:Ljava/util/Set;

    .line 98
    .line 99
    check-cast v9, Ljava/util/Set;

    .line 100
    .line 101
    iget-object v10, v2, Lt41/w;->g:Ljava/util/Set;

    .line 102
    .line 103
    check-cast v10, Ljava/util/Set;

    .line 104
    .line 105
    iget-object v11, v2, Lt41/w;->f:Ljava/util/Set;

    .line 106
    .line 107
    check-cast v11, Ljava/util/Set;

    .line 108
    .line 109
    iget-object v6, v2, Lt41/w;->e:Lez0/a;

    .line 110
    .line 111
    iget-object v13, v2, Lt41/w;->d:Ljava/util/List;

    .line 112
    .line 113
    check-cast v13, Ljava/util/List;

    .line 114
    .line 115
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 116
    .line 117
    .line 118
    move v0, v3

    .line 119
    move v3, v1

    .line 120
    move-object v1, v6

    .line 121
    goto/16 :goto_6

    .line 122
    .line 123
    :catchall_1
    move-exception v0

    .line 124
    move-object v1, v6

    .line 125
    goto :goto_1

    .line 126
    :cond_3
    iget v3, v2, Lt41/w;->k:I

    .line 127
    .line 128
    iget-object v6, v2, Lt41/w;->e:Lez0/a;

    .line 129
    .line 130
    iget-object v8, v2, Lt41/w;->d:Ljava/util/List;

    .line 131
    .line 132
    check-cast v8, Ljava/util/List;

    .line 133
    .line 134
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    move v13, v3

    .line 138
    move-object v3, v6

    .line 139
    move-object v0, v8

    .line 140
    goto :goto_2

    .line 141
    :cond_4
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    move-object/from16 v0, p1

    .line 145
    .line 146
    check-cast v0, Ljava/util/List;

    .line 147
    .line 148
    iput-object v0, v2, Lt41/w;->d:Ljava/util/List;

    .line 149
    .line 150
    iget-object v0, v4, Lt41/z;->f:Lez0/c;

    .line 151
    .line 152
    iput-object v0, v2, Lt41/w;->e:Lez0/a;

    .line 153
    .line 154
    iput v5, v2, Lt41/w;->k:I

    .line 155
    .line 156
    iput v15, v2, Lt41/w;->p:I

    .line 157
    .line 158
    invoke-virtual {v0, v2}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    if-ne v3, v12, :cond_5

    .line 163
    .line 164
    goto/16 :goto_b

    .line 165
    .line 166
    :cond_5
    move-object v3, v0

    .line 167
    move v13, v5

    .line 168
    move-object/from16 v0, p1

    .line 169
    .line 170
    :goto_2
    :try_start_2
    new-instance v8, Ld01/v;

    .line 171
    .line 172
    const/16 v6, 0xb

    .line 173
    .line 174
    invoke-direct {v8, v0, v6}, Ld01/v;-><init>(Ljava/util/List;I)V

    .line 175
    .line 176
    .line 177
    const-string v6, "BeaconScanner"

    .line 178
    .line 179
    move v9, v5

    .line 180
    new-instance v5, Lt51/j;

    .line 181
    .line 182
    invoke-static {v4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v10

    .line 186
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 187
    .line 188
    .line 189
    move-result-object v11

    .line 190
    invoke-virtual {v11}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v11

    .line 194
    invoke-static {v11, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_8

    .line 195
    .line 196
    .line 197
    move/from16 v16, v9

    .line 198
    .line 199
    const/4 v9, 0x0

    .line 200
    const/4 v14, 0x0

    .line 201
    :try_start_3
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 205
    .line 206
    .line 207
    iget-object v5, v4, Lt41/z;->j:Ljava/util/Set;

    .line 208
    .line 209
    check-cast v0, Ljava/lang/Iterable;

    .line 210
    .line 211
    new-instance v6, Ljava/util/ArrayList;

    .line 212
    .line 213
    const/16 v8, 0xa

    .line 214
    .line 215
    invoke-static {v0, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 216
    .line 217
    .line 218
    move-result v8

    .line 219
    invoke-direct {v6, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 220
    .line 221
    .line 222
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 227
    .line 228
    .line 229
    move-result v8

    .line 230
    if-eqz v8, :cond_6

    .line 231
    .line 232
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v8

    .line 236
    check-cast v8, Lt41/b;

    .line 237
    .line 238
    invoke-static {v8}, Lkp/i9;->j(Lt41/b;)Lorg/altbeacon/beacon/Region;

    .line 239
    .line 240
    .line 241
    move-result-object v8

    .line 242
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    goto :goto_3

    .line 246
    :catchall_2
    move-exception v0

    .line 247
    :goto_4
    move-object v1, v3

    .line 248
    goto/16 :goto_e

    .line 249
    .line 250
    :cond_6
    invoke-static {v6}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    iput-object v0, v4, Lt41/z;->j:Ljava/util/Set;

    .line 255
    .line 256
    move-object v6, v0

    .line 257
    check-cast v6, Ljava/lang/Iterable;

    .line 258
    .line 259
    invoke-static {v5, v6}, Ljp/m1;->f(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;

    .line 260
    .line 261
    .line 262
    move-result-object v6

    .line 263
    check-cast v6, Ljava/lang/Iterable;

    .line 264
    .line 265
    invoke-static {v6}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 266
    .line 267
    .line 268
    move-result-object v6

    .line 269
    iget-object v8, v4, Lt41/z;->k:Ljava/util/Set;

    .line 270
    .line 271
    move-object v9, v6

    .line 272
    check-cast v9, Ljava/lang/Iterable;

    .line 273
    .line 274
    invoke-static {v8, v9}, Ljp/m1;->f(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;

    .line 275
    .line 276
    .line 277
    move-result-object v9

    .line 278
    iput-object v9, v4, Lt41/z;->k:Ljava/util/Set;

    .line 279
    .line 280
    move-object v9, v6

    .line 281
    check-cast v9, Ljava/util/Collection;

    .line 282
    .line 283
    invoke-interface {v9}, Ljava/util/Collection;->isEmpty()Z

    .line 284
    .line 285
    .line 286
    move-result v9
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 287
    if-nez v9, :cond_d

    .line 288
    .line 289
    move-object v9, v8

    .line 290
    :try_start_4
    new-instance v8, Li61/b;

    .line 291
    .line 292
    invoke-direct {v8, v15, v6}, Li61/b;-><init>(ILjava/util/Set;)V

    .line 293
    .line 294
    .line 295
    move-object v10, v6

    .line 296
    const-string v6, "BeaconScanner"

    .line 297
    .line 298
    move-object v11, v5

    .line 299
    new-instance v5, Lt51/j;

    .line 300
    .line 301
    move-object/from16 v17, v10

    .line 302
    .line 303
    invoke-static {v4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 304
    .line 305
    .line 306
    move-result-object v10

    .line 307
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 308
    .line 309
    .line 310
    move-result-object v18

    .line 311
    invoke-virtual/range {v18 .. v18}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v14

    .line 315
    invoke-static {v14, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    move-object v1, v9

    .line 319
    const/4 v9, 0x0

    .line 320
    move-object/from16 v20, v14

    .line 321
    .line 322
    move-object v14, v1

    .line 323
    move-object v1, v11

    .line 324
    move-object/from16 v11, v20

    .line 325
    .line 326
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 330
    .line 331
    .line 332
    move-object/from16 v6, v17

    .line 333
    .line 334
    check-cast v6, Ljava/lang/Iterable;

    .line 335
    .line 336
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 337
    .line 338
    .line 339
    move-result-object v5
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 340
    move-object v10, v0

    .line 341
    move-object v11, v1

    .line 342
    move-object v1, v3

    .line 343
    move-object v8, v5

    .line 344
    move v5, v13

    .line 345
    move-object v9, v14

    .line 346
    move/from16 v0, v16

    .line 347
    .line 348
    move v3, v0

    .line 349
    :goto_5
    :try_start_5
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 350
    .line 351
    .line 352
    move-result v6

    .line 353
    if-eqz v6, :cond_c

    .line 354
    .line 355
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object v6

    .line 359
    move-object v7, v6

    .line 360
    check-cast v7, Lorg/altbeacon/beacon/Region;

    .line 361
    .line 362
    sget-object v6, Lvy0/p0;->a:Lcz0/e;

    .line 363
    .line 364
    sget-object v6, Laz0/m;->a:Lwy0/c;

    .line 365
    .line 366
    new-instance v13, Lt41/u;

    .line 367
    .line 368
    const/4 v14, 0x0

    .line 369
    invoke-direct {v13, v4, v7, v14, v15}, Lt41/u;-><init>(Lt41/z;Lorg/altbeacon/beacon/Region;Lkotlin/coroutines/Continuation;I)V

    .line 370
    .line 371
    .line 372
    iput-object v14, v2, Lt41/w;->d:Ljava/util/List;

    .line 373
    .line 374
    iput-object v1, v2, Lt41/w;->e:Lez0/a;

    .line 375
    .line 376
    move-object v14, v11

    .line 377
    check-cast v14, Ljava/util/Set;

    .line 378
    .line 379
    iput-object v14, v2, Lt41/w;->f:Ljava/util/Set;

    .line 380
    .line 381
    move-object v14, v10

    .line 382
    check-cast v14, Ljava/util/Set;

    .line 383
    .line 384
    iput-object v14, v2, Lt41/w;->g:Ljava/util/Set;

    .line 385
    .line 386
    move-object v14, v9

    .line 387
    check-cast v14, Ljava/util/Set;

    .line 388
    .line 389
    iput-object v14, v2, Lt41/w;->h:Ljava/util/Set;

    .line 390
    .line 391
    iput-object v8, v2, Lt41/w;->i:Ljava/util/Iterator;

    .line 392
    .line 393
    iput-object v7, v2, Lt41/w;->j:Lorg/altbeacon/beacon/Region;

    .line 394
    .line 395
    iput v5, v2, Lt41/w;->k:I

    .line 396
    .line 397
    iput v0, v2, Lt41/w;->l:I

    .line 398
    .line 399
    iput v3, v2, Lt41/w;->m:I

    .line 400
    .line 401
    const/4 v14, 0x2

    .line 402
    iput v14, v2, Lt41/w;->p:I

    .line 403
    .line 404
    invoke-static {v6, v13, v2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v6

    .line 408
    if-ne v6, v12, :cond_7

    .line 409
    .line 410
    goto/16 :goto_b

    .line 411
    .line 412
    :cond_7
    :goto_6
    invoke-static {v7}, Lkp/i9;->i(Lorg/altbeacon/beacon/Region;)Lt41/b;

    .line 413
    .line 414
    .line 415
    move-result-object v6

    .line 416
    iget-object v13, v4, Lt41/z;->m:Ljava/util/LinkedHashMap;

    .line 417
    .line 418
    invoke-interface {v13, v6}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    iget-object v13, v4, Lt41/z;->n:Ljava/util/LinkedHashMap;

    .line 422
    .line 423
    invoke-interface {v13, v6}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    invoke-interface {v9, v7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 427
    .line 428
    .line 429
    move-result v7

    .line 430
    if-eqz v7, :cond_b

    .line 431
    .line 432
    iget-object v7, v4, Lt41/z;->g:Lyy0/c2;

    .line 433
    .line 434
    :goto_7
    invoke-virtual {v7}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    move-result-object v13

    .line 438
    move-object/from16 v16, v13

    .line 439
    .line 440
    check-cast v16, Ljava/util/Set;

    .line 441
    .line 442
    check-cast v16, Ljava/lang/Iterable;

    .line 443
    .line 444
    new-instance v14, Ljava/util/ArrayList;

    .line 445
    .line 446
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 447
    .line 448
    .line 449
    invoke-interface/range {v16 .. v16}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 450
    .line 451
    .line 452
    move-result-object v16

    .line 453
    :goto_8
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->hasNext()Z

    .line 454
    .line 455
    .line 456
    move-result v17

    .line 457
    if-eqz v17, :cond_9

    .line 458
    .line 459
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    move-result-object v15

    .line 463
    move-object/from16 v18, v15

    .line 464
    .line 465
    check-cast v18, Lt41/g;

    .line 466
    .line 467
    move/from16 v19, v0

    .line 468
    .line 469
    invoke-virtual/range {v18 .. v18}, Lt41/g;->a()Lt41/b;

    .line 470
    .line 471
    .line 472
    move-result-object v0

    .line 473
    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 474
    .line 475
    .line 476
    move-result v0

    .line 477
    if-nez v0, :cond_8

    .line 478
    .line 479
    invoke-virtual {v14, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 480
    .line 481
    .line 482
    :cond_8
    move/from16 v0, v19

    .line 483
    .line 484
    const/4 v15, 0x1

    .line 485
    goto :goto_8

    .line 486
    :cond_9
    move/from16 v19, v0

    .line 487
    .line 488
    invoke-static {v14}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    invoke-virtual {v7, v13, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 493
    .line 494
    .line 495
    move-result v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 496
    if-eqz v0, :cond_a

    .line 497
    .line 498
    goto :goto_9

    .line 499
    :cond_a
    move/from16 v0, v19

    .line 500
    .line 501
    const/4 v14, 0x2

    .line 502
    const/4 v15, 0x1

    .line 503
    goto :goto_7

    .line 504
    :cond_b
    move/from16 v19, v0

    .line 505
    .line 506
    :goto_9
    move/from16 v0, v19

    .line 507
    .line 508
    const/4 v15, 0x1

    .line 509
    goto/16 :goto_5

    .line 510
    .line 511
    :cond_c
    move v8, v0

    .line 512
    move-object v6, v1

    .line 513
    move-object v7, v2

    .line 514
    move v13, v5

    .line 515
    move-object v2, v10

    .line 516
    move-object v3, v11

    .line 517
    goto :goto_a

    .line 518
    :catchall_3
    move-exception v0

    .line 519
    move-object v1, v3

    .line 520
    goto/16 :goto_1

    .line 521
    .line 522
    :cond_d
    move-object v1, v5

    .line 523
    move-object v7, v2

    .line 524
    move-object v6, v3

    .line 525
    move/from16 v8, v16

    .line 526
    .line 527
    move-object v2, v0

    .line 528
    move-object v3, v1

    .line 529
    :goto_a
    :try_start_6
    invoke-virtual {v4}, Lt41/z;->f()Z

    .line 530
    .line 531
    .line 532
    move-result v0

    .line 533
    if-eqz v0, :cond_e

    .line 534
    .line 535
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 536
    .line 537
    sget-object v9, Laz0/m;->a:Lwy0/c;

    .line 538
    .line 539
    new-instance v0, Lqh/a;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 540
    .line 541
    const/4 v1, 0x5

    .line 542
    const/4 v5, 0x0

    .line 543
    :try_start_7
    invoke-direct/range {v0 .. v5}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    .line 544
    .line 545
    .line 546
    move-object v14, v5

    .line 547
    :try_start_8
    iput-object v14, v7, Lt41/w;->d:Ljava/util/List;

    .line 548
    .line 549
    iput-object v6, v7, Lt41/w;->e:Lez0/a;

    .line 550
    .line 551
    iput-object v14, v7, Lt41/w;->f:Ljava/util/Set;

    .line 552
    .line 553
    iput-object v14, v7, Lt41/w;->g:Ljava/util/Set;

    .line 554
    .line 555
    iput-object v14, v7, Lt41/w;->h:Ljava/util/Set;

    .line 556
    .line 557
    iput-object v14, v7, Lt41/w;->i:Ljava/util/Iterator;

    .line 558
    .line 559
    iput-object v14, v7, Lt41/w;->j:Lorg/altbeacon/beacon/Region;

    .line 560
    .line 561
    iput v13, v7, Lt41/w;->k:I

    .line 562
    .line 563
    iput v8, v7, Lt41/w;->l:I

    .line 564
    .line 565
    const/4 v1, 0x3

    .line 566
    iput v1, v7, Lt41/w;->p:I

    .line 567
    .line 568
    invoke-static {v9, v0, v7}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 569
    .line 570
    .line 571
    move-result-object v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    .line 572
    if-ne v0, v12, :cond_f

    .line 573
    .line 574
    :goto_b
    return-object v12

    .line 575
    :catchall_4
    move-exception v0

    .line 576
    :goto_c
    move-object v1, v6

    .line 577
    goto :goto_e

    .line 578
    :catchall_5
    move-exception v0

    .line 579
    move-object v14, v5

    .line 580
    goto :goto_c

    .line 581
    :catchall_6
    move-exception v0

    .line 582
    const/4 v14, 0x0

    .line 583
    goto :goto_c

    .line 584
    :cond_e
    const/4 v14, 0x0

    .line 585
    :cond_f
    move-object v1, v6

    .line 586
    :goto_d
    :try_start_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_7

    .line 587
    .line 588
    invoke-interface {v1, v14}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 589
    .line 590
    .line 591
    return-object v0

    .line 592
    :catchall_7
    move-exception v0

    .line 593
    goto :goto_e

    .line 594
    :catchall_8
    move-exception v0

    .line 595
    const/4 v14, 0x0

    .line 596
    goto/16 :goto_4

    .line 597
    .line 598
    :goto_e
    invoke-interface {v1, v14}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 599
    .line 600
    .line 601
    throw v0
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lt41/z;->e:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h(Lrx0/c;)Ljava/io/Serializable;
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    sget-object v2, Lt41/l;->a:Lt41/l;

    .line 6
    .line 7
    iget-object v3, v1, Lt41/z;->d:Landroid/content/Context;

    .line 8
    .line 9
    instance-of v4, v0, Lt41/x;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v0

    .line 14
    check-cast v4, Lt41/x;

    .line 15
    .line 16
    iget v5, v4, Lt41/x;->h:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lt41/x;->h:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lt41/x;

    .line 29
    .line 30
    invoke-direct {v4, v1, v0}, Lt41/x;-><init>(Lt41/z;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v0, v4, Lt41/x;->f:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lt41/x;->h:I

    .line 38
    .line 39
    const/4 v7, 0x2

    .line 40
    const/4 v8, 0x1

    .line 41
    const/4 v9, 0x0

    .line 42
    if-eqz v6, :cond_3

    .line 43
    .line 44
    if-eq v6, v8, :cond_2

    .line 45
    .line 46
    if-ne v6, v7, :cond_1

    .line 47
    .line 48
    iget-object v2, v4, Lt41/x;->d:Lez0/a;

    .line 49
    .line 50
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    .line 52
    .line 53
    goto/16 :goto_7

    .line 54
    .line 55
    :catchall_0
    move-exception v0

    .line 56
    goto/16 :goto_8

    .line 57
    .line 58
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 61
    .line 62
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw v0

    .line 66
    :cond_2
    iget v6, v4, Lt41/x;->e:I

    .line 67
    .line 68
    iget-object v10, v4, Lt41/x;->d:Lez0/a;

    .line 69
    .line 70
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-object v0, v1, Lt41/z;->f:Lez0/c;

    .line 78
    .line 79
    iput-object v0, v4, Lt41/x;->d:Lez0/a;

    .line 80
    .line 81
    const/4 v6, 0x0

    .line 82
    iput v6, v4, Lt41/x;->e:I

    .line 83
    .line 84
    iput v8, v4, Lt41/x;->h:I

    .line 85
    .line 86
    invoke-virtual {v0, v4}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v10

    .line 90
    if-ne v10, v5, :cond_4

    .line 91
    .line 92
    goto/16 :goto_6

    .line 93
    .line 94
    :cond_4
    move-object v10, v0

    .line 95
    :goto_1
    :try_start_1
    iget-boolean v0, v1, Lt41/z;->l:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 96
    .line 97
    if-eqz v0, :cond_5

    .line 98
    .line 99
    invoke-interface {v10, v9}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    return-object v9

    .line 103
    :cond_5
    :try_start_2
    new-instance v14, Lqf0/d;

    .line 104
    .line 105
    const/16 v0, 0x1a

    .line 106
    .line 107
    invoke-direct {v14, v0}, Lqf0/d;-><init>(I)V

    .line 108
    .line 109
    .line 110
    const-string v12, "BeaconScanner"

    .line 111
    .line 112
    new-instance v11, Lt51/j;

    .line 113
    .line 114
    sget-object v13, Lt51/g;->a:Lt51/g;

    .line 115
    .line 116
    invoke-static {v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v16

    .line 120
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-virtual {v0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    const-string v15, "getName(...)"

    .line 129
    .line 130
    invoke-static {v0, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    const/4 v15, 0x0

    .line 134
    move-object/from16 v17, v0

    .line 135
    .line 136
    invoke-direct/range {v11 .. v17}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    invoke-static {v11}, Lt51/a;->a(Lt51/j;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 140
    .line 141
    .line 142
    :try_start_3
    invoke-static {v3}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->checkAvailability()Z

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    if-nez v0, :cond_6

    .line 151
    .line 152
    sget-object v0, Lt41/m;->a:Lt41/m;
    :try_end_3
    .catch Lorg/altbeacon/beacon/BleNotAvailableException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :catch_0
    move-exception v0

    .line 156
    goto :goto_2

    .line 157
    :cond_6
    move-object v0, v2

    .line 158
    goto :goto_3

    .line 159
    :goto_2
    :try_start_4
    new-instance v11, Lt41/n;

    .line 160
    .line 161
    invoke-direct {v11, v0}, Lt41/n;-><init>(Lorg/altbeacon/beacon/BleNotAvailableException;)V

    .line 162
    .line 163
    .line 164
    move-object v0, v11

    .line 165
    :goto_3
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v2

    .line 169
    if-nez v2, :cond_7

    .line 170
    .line 171
    new-instance v1, Lt41/i;

    .line 172
    .line 173
    invoke-direct {v1, v0}, Lt41/i;-><init>(Lkp/h9;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 174
    .line 175
    .line 176
    invoke-interface {v10, v9}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 177
    .line 178
    .line 179
    return-object v1

    .line 180
    :catchall_1
    move-exception v0

    .line 181
    move-object v2, v10

    .line 182
    goto :goto_8

    .line 183
    :cond_7
    :try_start_5
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 184
    .line 185
    const/16 v2, 0x1f

    .line 186
    .line 187
    if-ge v0, v2, :cond_9

    .line 188
    .line 189
    const-string v11, "android.permission.ACCESS_FINE_LOCATION"

    .line 190
    .line 191
    invoke-virtual {v3, v11}, Landroid/content/Context;->checkSelfPermission(Ljava/lang/String;)I

    .line 192
    .line 193
    .line 194
    move-result v11

    .line 195
    if-nez v11, :cond_8

    .line 196
    .line 197
    goto :goto_4

    .line 198
    :cond_8
    sget-object v0, Lt41/j;->e:Lt41/j;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 199
    .line 200
    invoke-interface {v10, v9}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    return-object v0

    .line 204
    :cond_9
    :goto_4
    if-lt v0, v2, :cond_b

    .line 205
    .line 206
    :try_start_6
    const-string v0, "android.permission.BLUETOOTH_SCAN"

    .line 207
    .line 208
    invoke-virtual {v3, v0}, Landroid/content/Context;->checkSelfPermission(Ljava/lang/String;)I

    .line 209
    .line 210
    .line 211
    move-result v0

    .line 212
    if-nez v0, :cond_a

    .line 213
    .line 214
    goto :goto_5

    .line 215
    :cond_a
    sget-object v0, Lt41/h;->e:Lt41/h;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 216
    .line 217
    invoke-interface {v10, v9}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    return-object v0

    .line 221
    :cond_b
    :goto_5
    :try_start_7
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 222
    .line 223
    sget-object v0, Laz0/m;->a:Lwy0/c;

    .line 224
    .line 225
    new-instance v2, Lm70/f1;

    .line 226
    .line 227
    const/16 v3, 0x12

    .line 228
    .line 229
    invoke-direct {v2, v1, v9, v3}, Lm70/f1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 230
    .line 231
    .line 232
    iput-object v10, v4, Lt41/x;->d:Lez0/a;

    .line 233
    .line 234
    iput v6, v4, Lt41/x;->e:I

    .line 235
    .line 236
    iput v7, v4, Lt41/x;->h:I

    .line 237
    .line 238
    invoke-static {v0, v2, v4}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 242
    if-ne v0, v5, :cond_c

    .line 243
    .line 244
    :goto_6
    return-object v5

    .line 245
    :cond_c
    move-object v2, v10

    .line 246
    :goto_7
    :try_start_8
    iput-boolean v8, v1, Lt41/z;->l:Z
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 247
    .line 248
    invoke-interface {v2, v9}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    return-object v9

    .line 252
    :goto_8
    invoke-interface {v2, v9}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    throw v0
.end method

.method public final j(Lrx0/c;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Lt41/y;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lt41/y;

    .line 11
    .line 12
    iget v3, v2, Lt41/y;->h:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lt41/y;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lt41/y;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lt41/y;-><init>(Lt41/z;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lt41/y;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lt41/y;->h:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    sget-object v6, Lmx0/u;->d:Lmx0/u;

    .line 38
    .line 39
    const/4 v7, 0x2

    .line 40
    const/4 v8, 0x1

    .line 41
    const/4 v9, 0x0

    .line 42
    const/4 v10, 0x0

    .line 43
    if-eqz v4, :cond_3

    .line 44
    .line 45
    if-eq v4, v8, :cond_2

    .line 46
    .line 47
    if-ne v4, v7, :cond_1

    .line 48
    .line 49
    iget-object v2, v2, Lt41/y;->d:Lez0/a;

    .line 50
    .line 51
    :try_start_0
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    .line 53
    .line 54
    goto/16 :goto_4

    .line 55
    .line 56
    :catchall_0
    move-exception v0

    .line 57
    goto/16 :goto_5

    .line 58
    .line 59
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :cond_2
    iget v4, v2, Lt41/y;->e:I

    .line 68
    .line 69
    iget-object v8, v2, Lt41/y;->d:Lez0/a;

    .line 70
    .line 71
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    move-object v1, v8

    .line 75
    goto :goto_1

    .line 76
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iget-object v1, v0, Lt41/z;->f:Lez0/c;

    .line 80
    .line 81
    iput-object v1, v2, Lt41/y;->d:Lez0/a;

    .line 82
    .line 83
    iput v9, v2, Lt41/y;->e:I

    .line 84
    .line 85
    iput v8, v2, Lt41/y;->h:I

    .line 86
    .line 87
    invoke-virtual {v1, v2}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    if-ne v4, v3, :cond_4

    .line 92
    .line 93
    goto :goto_3

    .line 94
    :cond_4
    move v4, v9

    .line 95
    :goto_1
    :try_start_1
    iget-boolean v8, v0, Lt41/z;->l:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 96
    .line 97
    const-string v11, "getName(...)"

    .line 98
    .line 99
    sget-object v14, Lt51/g;->a:Lt51/g;

    .line 100
    .line 101
    if-nez v8, :cond_5

    .line 102
    .line 103
    :try_start_2
    new-instance v15, Lqf0/d;

    .line 104
    .line 105
    const/16 v8, 0x19

    .line 106
    .line 107
    invoke-direct {v15, v8}, Lqf0/d;-><init>(I)V

    .line 108
    .line 109
    .line 110
    const-string v13, "BeaconScanner"

    .line 111
    .line 112
    new-instance v12, Lt51/j;

    .line 113
    .line 114
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v17

    .line 118
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 119
    .line 120
    .line 121
    move-result-object v8

    .line 122
    invoke-virtual {v8}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v8

    .line 126
    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    const/16 v16, 0x0

    .line 130
    .line 131
    move-object/from16 v18, v8

    .line 132
    .line 133
    invoke-direct/range {v12 .. v18}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    invoke-static {v12}, Lt51/a;->a(Lt51/j;)V

    .line 137
    .line 138
    .line 139
    goto :goto_2

    .line 140
    :catchall_1
    move-exception v0

    .line 141
    move-object v2, v1

    .line 142
    goto :goto_5

    .line 143
    :cond_5
    :goto_2
    new-instance v15, Lr1/b;

    .line 144
    .line 145
    const/16 v8, 0x12

    .line 146
    .line 147
    invoke-direct {v15, v0, v8}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 148
    .line 149
    .line 150
    const-string v13, "BeaconScanner"

    .line 151
    .line 152
    new-instance v12, Lt51/j;

    .line 153
    .line 154
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v17

    .line 158
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 159
    .line 160
    .line 161
    move-result-object v8

    .line 162
    invoke-virtual {v8}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v8

    .line 166
    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    const/16 v16, 0x0

    .line 170
    .line 171
    move-object/from16 v18, v8

    .line 172
    .line 173
    invoke-direct/range {v12 .. v18}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    invoke-static {v12}, Lt51/a;->a(Lt51/j;)V

    .line 177
    .line 178
    .line 179
    iget-object v8, v0, Lt41/z;->g:Lyy0/c2;

    .line 180
    .line 181
    iput-object v1, v2, Lt41/y;->d:Lez0/a;

    .line 182
    .line 183
    iput v4, v2, Lt41/y;->e:I

    .line 184
    .line 185
    iput v7, v2, Lt41/y;->h:I

    .line 186
    .line 187
    invoke-virtual {v8, v6, v2}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 188
    .line 189
    .line 190
    if-ne v5, v3, :cond_6

    .line 191
    .line 192
    :goto_3
    return-object v3

    .line 193
    :cond_6
    move-object v2, v1

    .line 194
    :goto_4
    :try_start_3
    iput-object v6, v0, Lt41/z;->k:Ljava/util/Set;

    .line 195
    .line 196
    iget-object v1, v0, Lt41/z;->m:Ljava/util/LinkedHashMap;

    .line 197
    .line 198
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->clear()V

    .line 199
    .line 200
    .line 201
    iget-object v1, v0, Lt41/z;->n:Ljava/util/LinkedHashMap;

    .line 202
    .line 203
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->clear()V

    .line 204
    .line 205
    .line 206
    iput-boolean v9, v0, Lt41/z;->l:Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 207
    .line 208
    invoke-interface {v2, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    return-object v5

    .line 212
    :goto_5
    invoke-interface {v2, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 213
    .line 214
    .line 215
    throw v0
.end method
