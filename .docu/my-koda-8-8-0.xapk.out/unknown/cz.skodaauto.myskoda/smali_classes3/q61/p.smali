.class public final Lq61/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;
.implements Ljava/io/Closeable;


# instance fields
.field public final d:Lpw0/a;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/l1;

.field public final g:Lyy0/l1;

.field public final h:Lyy0/l1;

.field public final i:Lyy0/c2;

.field public final j:Lyy0/l1;

.field public final k:Lyy0/l1;

.field public final l:Lyy0/l1;

.field public final m:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lwy0/c;Lvy0/i1;)V
    .locals 3

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "mainDispatcher"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    const-string v0, "RPAViewModel"

    .line 15
    .line 16
    invoke-static {v0, p2, p3}, Llp/h1;->a(Ljava/lang/String;Lvy0/x;Lvy0/i1;)Lpx0/g;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    invoke-static {p2}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    iput-object p2, p0, Lq61/p;->d:Lpw0/a;

    .line 25
    .line 26
    sget-object p3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-static {p3}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 29
    .line 30
    .line 31
    move-result-object p3

    .line 32
    iput-object p3, p0, Lq61/p;->e:Lyy0/c2;

    .line 33
    .line 34
    new-instance v0, Lyy0/l1;

    .line 35
    .line 36
    invoke-direct {v0, p3}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lq61/p;->f:Lyy0/l1;

    .line 40
    .line 41
    sget-object p3, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b:Lyy0/c2;

    .line 42
    .line 43
    new-instance v0, Lyy0/l1;

    .line 44
    .line 45
    invoke-direct {v0, p3}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 46
    .line 47
    .line 48
    new-instance v1, Lpg/m;

    .line 49
    .line 50
    const/4 v2, 0x5

    .line 51
    invoke-direct {v1, p0, v2}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    invoke-static {v0, p2, v1}, Ljp/re;->b(Lyy0/l1;Lvy0/b0;Lay0/k;)Lyy0/l1;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    iput-object v0, p0, Lq61/p;->g:Lyy0/l1;

    .line 59
    .line 60
    new-instance v0, Lyy0/l1;

    .line 61
    .line 62
    invoke-direct {v0, p3}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 63
    .line 64
    .line 65
    new-instance v1, Lod0/n;

    .line 66
    .line 67
    const/16 v2, 0xd

    .line 68
    .line 69
    invoke-direct {v1, v2, p1, p0}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    invoke-static {v0, p2, v1}, Ljp/re;->b(Lyy0/l1;Lvy0/b0;Lay0/k;)Lyy0/l1;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    iput-object p1, p0, Lq61/p;->h:Lyy0/l1;

    .line 77
    .line 78
    const/4 p1, 0x0

    .line 79
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    iput-object p1, p0, Lq61/p;->i:Lyy0/c2;

    .line 84
    .line 85
    new-instance p1, Lyy0/l1;

    .line 86
    .line 87
    invoke-direct {p1, p3}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 88
    .line 89
    .line 90
    new-instance v0, Lp81/c;

    .line 91
    .line 92
    const/16 v1, 0x1a

    .line 93
    .line 94
    invoke-direct {v0, v1}, Lp81/c;-><init>(I)V

    .line 95
    .line 96
    .line 97
    invoke-static {p1, p2, v0}, Ljp/re;->b(Lyy0/l1;Lvy0/b0;Lay0/k;)Lyy0/l1;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    iput-object p1, p0, Lq61/p;->j:Lyy0/l1;

    .line 102
    .line 103
    new-instance p1, Lyy0/l1;

    .line 104
    .line 105
    invoke-direct {p1, p3}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 106
    .line 107
    .line 108
    new-instance v0, Lp81/c;

    .line 109
    .line 110
    const/16 v1, 0x15

    .line 111
    .line 112
    invoke-direct {v0, v1}, Lp81/c;-><init>(I)V

    .line 113
    .line 114
    .line 115
    invoke-static {p1, p2, v0}, Ljp/re;->b(Lyy0/l1;Lvy0/b0;Lay0/k;)Lyy0/l1;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    iput-object p1, p0, Lq61/p;->k:Lyy0/l1;

    .line 120
    .line 121
    new-instance p1, Lyy0/l1;

    .line 122
    .line 123
    invoke-direct {p1, p3}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 124
    .line 125
    .line 126
    new-instance v0, Lp81/c;

    .line 127
    .line 128
    const/16 v1, 0x1b

    .line 129
    .line 130
    invoke-direct {v0, v1}, Lp81/c;-><init>(I)V

    .line 131
    .line 132
    .line 133
    invoke-static {p1, p2, v0}, Ljp/re;->b(Lyy0/l1;Lvy0/b0;Lay0/k;)Lyy0/l1;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    iput-object p1, p0, Lq61/p;->l:Lyy0/l1;

    .line 138
    .line 139
    new-instance p1, Lyy0/l1;

    .line 140
    .line 141
    invoke-direct {p1, p3}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 142
    .line 143
    .line 144
    new-instance p3, Lp81/c;

    .line 145
    .line 146
    const/16 v0, 0x17

    .line 147
    .line 148
    invoke-direct {p3, v0}, Lp81/c;-><init>(I)V

    .line 149
    .line 150
    .line 151
    invoke-static {p1, p2, p3}, Ljp/re;->b(Lyy0/l1;Lvy0/b0;Lay0/k;)Lyy0/l1;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    iput-object p1, p0, Lq61/p;->m:Lyy0/l1;

    .line 156
    .line 157
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 2

    .line 1
    new-instance v0, Lqf0/d;

    .line 2
    .line 3
    const/16 v1, 0x18

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lqf0/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lq61/p;->d:Lpw0/a;

    .line 12
    .line 13
    const-string v0, "close"

    .line 14
    .line 15
    invoke-static {p0, v0}, Lvy0/e0;->l(Lvy0/b0;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final getBackgroundSceneConfig()Lyy0/a2;
    .locals 0

    .line 1
    iget-object p0, p0, Lq61/p;->m:Lyy0/l1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCustomScreenCreator()Lyy0/a2;
    .locals 0

    .line 1
    iget-object p0, p0, Lq61/p;->l:Lyy0/l1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getShowTouchPositionGrid()Lyy0/a2;
    .locals 0

    .line 1
    iget-object p0, p0, Lq61/p;->k:Lyy0/l1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isAnyRPARunning()Lyy0/a2;
    .locals 0

    .line 1
    iget-object p0, p0, Lq61/p;->g:Lyy0/l1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isRPADisplayedPartially()Lyy0/a2;
    .locals 0

    .line 1
    iget-object p0, p0, Lq61/p;->f:Lyy0/l1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final onLifecycleChanged(Ln71/c;)V
    .locals 3

    .line 1
    const-string v0, "lifecycle"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 7
    .line 8
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a()Lcom/google/firebase/messaging/w;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    new-instance v0, Lq61/d;

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    invoke-direct {v0, p1, v1}, Lq61/d;-><init>(Ln71/c;I)V

    .line 18
    .line 19
    .line 20
    invoke-static {p0, v0}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    new-instance v1, Lq61/d;

    .line 25
    .line 26
    const/4 v2, 0x3

    .line 27
    invoke-direct {v1, p1, v2}, Lq61/d;-><init>(Ln71/c;I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0, v1}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 31
    .line 32
    .line 33
    iget-object p0, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;

    .line 36
    .line 37
    invoke-interface {p0, p1}, Lc81/a;->lifecycleChanged(Ln71/c;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public final onTouchPositionChanged(FFFFSZ)V
    .locals 7

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 2
    .line 3
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a()Lcom/google/firebase/messaging/w;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance p3, Lq61/a;

    .line 10
    .line 11
    const/4 p4, 0x1

    .line 12
    invoke-direct {p3, p1, p2, p4, p6}, Lq61/a;-><init>(FFIZ)V

    .line 13
    .line 14
    .line 15
    invoke-static {p0, p3}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object p0, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v0, p0

    .line 22
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;

    .line 23
    .line 24
    move v1, p1

    .line 25
    move v2, p2

    .line 26
    move v3, p3

    .line 27
    move v4, p4

    .line 28
    move v5, p5

    .line 29
    move v6, p6

    .line 30
    invoke-interface/range {v0 .. v6}, Lc81/h;->touchPositionChanged(FFFFSZ)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final startRPA-tZkwj4A(Lg61/d;Lh61/a;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;Lvy0/i1;Lvy0/x;Ln71/a;Lc81/e;Lay0/a;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v9, p8

    .line 6
    .line 7
    const-string v1, "rpaConfiguration"

    .line 8
    .line 9
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "rpaStarterConfiguration"

    .line 13
    .line 14
    move-object/from16 v5, p2

    .line 15
    .line 16
    invoke-static {v5, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v1, "bleTransport"

    .line 20
    .line 21
    move-object/from16 v12, p3

    .line 22
    .line 23
    invoke-static {v12, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, "vehicleAntenna"

    .line 27
    .line 28
    move-object/from16 v11, p4

    .line 29
    .line 30
    invoke-static {v11, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string v1, "ioDispatcher"

    .line 34
    .line 35
    move-object/from16 v15, p6

    .line 36
    .line 37
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const-string v1, "navigationDelegate"

    .line 41
    .line 42
    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const-string v1, "onRPAFinish"

    .line 46
    .line 47
    move-object/from16 v8, p9

    .line 48
    .line 49
    invoke-static {v8, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    new-instance v1, Lpd/f0;

    .line 53
    .line 54
    const/16 v2, 0xc

    .line 55
    .line 56
    invoke-direct {v1, v2}, Lpd/f0;-><init>(I)V

    .line 57
    .line 58
    .line 59
    invoke-static {v0, v1}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 60
    .line 61
    .line 62
    sget-object v1, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 63
    .line 64
    sget-object v1, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b:Lyy0/c2;

    .line 65
    .line 66
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    if-eqz v1, :cond_0

    .line 71
    .line 72
    new-instance v1, Lpd/f0;

    .line 73
    .line 74
    const/16 v2, 0x17

    .line 75
    .line 76
    invoke-direct {v1, v2}, Lpd/f0;-><init>(I)V

    .line 77
    .line 78
    .line 79
    invoke-static {v0, v1}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 80
    .line 81
    .line 82
    sget-object v0, Lg61/r;->d:Lg61/r;

    .line 83
    .line 84
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    return-object v0

    .line 89
    :cond_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 90
    .line 91
    .line 92
    move-result-wide v1

    .line 93
    if-nez p7, :cond_1

    .line 94
    .line 95
    new-instance v3, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;

    .line 96
    .line 97
    invoke-direct {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;-><init>()V

    .line 98
    .line 99
    .line 100
    move-object v7, v3

    .line 101
    goto :goto_0

    .line 102
    :cond_1
    move-object/from16 v7, p7

    .line 103
    .line 104
    :goto_0
    new-instance v6, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 105
    .line 106
    const/4 v13, 0x1

    .line 107
    move-object/from16 v14, p5

    .line 108
    .line 109
    move-object v10, v6

    .line 110
    move-object/from16 v16, v7

    .line 111
    .line 112
    invoke-direct/range {v10 .. v16}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;-><init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;ZLvy0/i1;Lvy0/x;Ln71/a;)V

    .line 113
    .line 114
    .line 115
    move-wide v2, v1

    .line 116
    new-instance v1, Ls61/a;

    .line 117
    .line 118
    invoke-static/range {p4 .. p4}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v16

    .line 122
    new-instance v12, Ll71/w;

    .line 123
    .line 124
    new-instance v10, Lu61/b;

    .line 125
    .line 126
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 127
    .line 128
    .line 129
    invoke-direct {v12, v7, v10}, Ll71/w;-><init>(Ln71/a;Lu61/b;)V

    .line 130
    .line 131
    .line 132
    new-instance v15, Ll71/a;

    .line 133
    .line 134
    invoke-direct {v15}, Ll71/a;-><init>()V

    .line 135
    .line 136
    .line 137
    sget-object v10, Lv71/e;->c:Lv71/e;

    .line 138
    .line 139
    const-string v11, "vehicleDimensions"

    .line 140
    .line 141
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    new-instance v13, Ll71/z;

    .line 145
    .line 146
    move-object/from16 p3, v1

    .line 147
    .line 148
    move-wide/from16 p5, v2

    .line 149
    .line 150
    const-wide/high16 v1, 0x3fe0000000000000L    # 0.5

    .line 151
    .line 152
    invoke-direct {v13, v1, v2, v10}, Ll71/z;-><init>(DLv71/e;)V

    .line 153
    .line 154
    .line 155
    iget-object v1, v4, Lg61/d;->c:Ljava/util/Set;

    .line 156
    .line 157
    check-cast v1, Ljava/lang/Iterable;

    .line 158
    .line 159
    new-instance v14, Ljava/util/ArrayList;

    .line 160
    .line 161
    const/16 v2, 0xa

    .line 162
    .line 163
    invoke-static {v1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    invoke-direct {v14, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 168
    .line 169
    .line 170
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    if-eqz v2, :cond_3

    .line 179
    .line 180
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    check-cast v2, Lg61/f0;

    .line 185
    .line 186
    sget-object v3, Lg61/f0;->a:Lg61/v;

    .line 187
    .line 188
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 189
    .line 190
    .line 191
    const-string v3, "vehiclePlatform"

    .line 192
    .line 193
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    sget-object v3, Lg61/v;->b:Ljava/lang/Object;

    .line 197
    .line 198
    invoke-interface {v3, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v3

    .line 202
    check-cast v3, Ll71/u;

    .line 203
    .line 204
    if-nez v3, :cond_2

    .line 205
    .line 206
    new-instance v3, Ll71/n;

    .line 207
    .line 208
    invoke-interface {v2}, Lg61/f0;->b()I

    .line 209
    .line 210
    .line 211
    move-result v10

    .line 212
    invoke-interface {v2}, Lg61/f0;->a()I

    .line 213
    .line 214
    .line 215
    move-result v2

    .line 216
    invoke-direct {v3, v10, v2}, Ll71/n;-><init>(II)V

    .line 217
    .line 218
    .line 219
    :cond_2
    invoke-virtual {v14, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    goto :goto_1

    .line 223
    :cond_3
    new-instance v10, Lcom/google/firebase/messaging/w;

    .line 224
    .line 225
    move-object v11, v6

    .line 226
    invoke-direct/range {v10 .. v15}, Lcom/google/firebase/messaging/w;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ll71/w;Ll71/z;Ljava/util/ArrayList;Ll71/a;)V

    .line 227
    .line 228
    .line 229
    iget-object v1, v10, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 230
    .line 231
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;

    .line 232
    .line 233
    invoke-virtual {v6, v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->setC2pListener$remoteparkassistplugin_release(Lk71/a;)V

    .line 234
    .line 235
    .line 236
    move-object/from16 v1, p3

    .line 237
    .line 238
    move-object v3, v10

    .line 239
    move-object/from16 v2, v16

    .line 240
    .line 241
    move-wide/from16 v10, p5

    .line 242
    .line 243
    invoke-direct/range {v1 .. v8}, Ls61/a;-><init>(Ljava/lang/String;Lcom/google/firebase/messaging/w;Lg61/d;Lh61/a;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ln71/a;Lay0/a;)V

    .line 244
    .line 245
    .line 246
    new-instance v2, Lg61/f;

    .line 247
    .line 248
    const/4 v4, 0x6

    .line 249
    invoke-direct {v2, v1, v4}, Lg61/f;-><init>(Ls61/a;I)V

    .line 250
    .line 251
    .line 252
    iget-object v3, v3, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;

    .line 255
    .line 256
    invoke-virtual {v3, v9, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->start$remoteparkassistcoremeb_release(Lc81/e;Lay0/a;)V

    .line 257
    .line 258
    .line 259
    sget-object v2, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 260
    .line 261
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b(Ls61/a;)V

    .line 262
    .line 263
    .line 264
    new-instance v1, Lbo0/j;

    .line 265
    .line 266
    const/4 v2, 0x2

    .line 267
    invoke-direct {v1, v10, v11, v2}, Lbo0/j;-><init>(JI)V

    .line 268
    .line 269
    .line 270
    invoke-static {v0, v1}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 271
    .line 272
    .line 273
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 274
    .line 275
    return-object v0
.end method

.method public final stopRPAImmediately()V
    .locals 4

    .line 10
    sget-object v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 11
    sget-object v1, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b:Lyy0/c2;

    .line 12
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    move-result-object v1

    .line 13
    check-cast v1, Ls61/a;

    .line 14
    new-instance v2, Lg61/f;

    const/4 v3, 0x4

    invoke-direct {v2, v1, v3}, Lg61/f;-><init>(Ls61/a;I)V

    invoke-static {p0, v2}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    if-nez v1, :cond_0

    .line 15
    new-instance v0, Lpd/f0;

    const/16 v1, 0xa

    invoke-direct {v0, v1}, Lpd/f0;-><init>(I)V

    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    return-void

    :cond_0
    const/4 p0, 0x0

    .line 16
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b(Ls61/a;)V

    return-void
.end method

.method public final stopRPAImmediately(Ljava/lang/String;)V
    .locals 4

    const-string v0, "vin"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 2
    sget-object v1, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b:Lyy0/c2;

    .line 3
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    move-result-object v1

    .line 4
    check-cast v1, Ls61/a;

    .line 5
    new-instance v2, Lq61/b;

    const/4 v3, 0x1

    invoke-direct {v2, p1, v1, v3}, Lq61/b;-><init>(Ljava/lang/String;Ls61/a;I)V

    invoke-static {p0, v2}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    .line 6
    iget-object v1, v1, Ls61/a;->d:Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object v1, v2

    .line 7
    :goto_0
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1

    .line 8
    new-instance v0, Lq61/c;

    const/4 v1, 0x1

    invoke-direct {v0, p1, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    return-void

    .line 9
    :cond_1
    invoke-virtual {v0, v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b(Ls61/a;)V

    return-void
.end method

.method public final updateDisplayCalculationInDp(Landroid/util/Size;Lw61/a;Z)V
    .locals 8

    .line 1
    const-string v0, "rpaViewSize"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "deviceDisplaySize"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget v0, p2, Lw61/a;->e:I

    .line 12
    .line 13
    iget v1, p2, Lw61/a;->c:I

    .line 14
    .line 15
    iget-object v2, p0, Lq61/p;->i:Lyy0/c2;

    .line 16
    .line 17
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Landroid/util/DisplayMetrics;

    .line 22
    .line 23
    if-nez v2, :cond_0

    .line 24
    .line 25
    goto/16 :goto_4

    .line 26
    .line 27
    :cond_0
    iget v2, v2, Landroid/util/DisplayMetrics;->density:F

    .line 28
    .line 29
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    add-int/2addr v3, v1

    .line 34
    add-int/2addr v3, v0

    .line 35
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    int-to-float v3, v3

    .line 40
    div-float/2addr v3, v2

    .line 41
    int-to-float p1, p1

    .line 42
    div-float/2addr p1, v2

    .line 43
    iget v4, p2, Lw61/a;->a:I

    .line 44
    .line 45
    int-to-float v4, v4

    .line 46
    div-float/2addr v4, v2

    .line 47
    iget p2, p2, Lw61/a;->b:I

    .line 48
    .line 49
    int-to-float p2, p2

    .line 50
    div-float/2addr p2, v2

    .line 51
    sub-float v5, v4, v3

    .line 52
    .line 53
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    sub-float v6, p2, p1

    .line 58
    .line 59
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    int-to-float v1, v1

    .line 64
    div-float/2addr v1, v2

    .line 65
    int-to-float v0, v0

    .line 66
    div-float/2addr v0, v2

    .line 67
    const v2, 0x3e4ccccd    # 0.2f

    .line 68
    .line 69
    .line 70
    mul-float/2addr v2, v4

    .line 71
    cmpl-float v2, v5, v2

    .line 72
    .line 73
    const/4 v5, 0x0

    .line 74
    if-gtz v2, :cond_2

    .line 75
    .line 76
    const/4 v2, 0x2

    .line 77
    int-to-float v2, v2

    .line 78
    cmpl-float v2, v6, v2

    .line 79
    .line 80
    if-gtz v2, :cond_2

    .line 81
    .line 82
    if-eqz p3, :cond_1

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_1
    move v2, v5

    .line 86
    goto :goto_1

    .line 87
    :cond_2
    :goto_0
    const/4 v2, 0x1

    .line 88
    :goto_1
    new-instance v6, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    const-string v7, "updateDisplayCalculationInDp(): is RPA displayed just partly: "

    .line 91
    .line 92
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const-string v7, "\nDeviceDisplay: [WidthDp: "

    .line 99
    .line 100
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v6, p2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string p2, ", HeightDp: "

    .line 107
    .line 108
    invoke-virtual {v6, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    const-string v4, "]\nRPAView: [WidthDp: "

    .line 115
    .line 116
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v6, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string p1, "]\nSystemBars: [StatusBarHeightDp: "

    .line 129
    .line 130
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    const-string p1, ", NavigationBarHeightDp: "

    .line 137
    .line 138
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    const-string p1, "]\nisInMultiWindowMode: "

    .line 145
    .line 146
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v6, p3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    iget-object p2, p0, Lq61/p;->j:Lyy0/l1;

    .line 157
    .line 158
    if-eqz v2, :cond_3

    .line 159
    .line 160
    iget-object p3, p2, Lyy0/l1;->d:Lyy0/a2;

    .line 161
    .line 162
    invoke-interface {p3}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p3

    .line 166
    check-cast p3, Ljava/lang/Boolean;

    .line 167
    .line 168
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 169
    .line 170
    .line 171
    move-result p3

    .line 172
    if-eqz p3, :cond_3

    .line 173
    .line 174
    new-instance p3, Lac0/a;

    .line 175
    .line 176
    const/16 v0, 0x1d

    .line 177
    .line 178
    invoke-direct {p3, p1, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 179
    .line 180
    .line 181
    const/4 p1, 0x0

    .line 182
    invoke-static {p0, p1, p3}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 183
    .line 184
    .line 185
    goto :goto_2

    .line 186
    :cond_3
    if-eqz v2, :cond_4

    .line 187
    .line 188
    new-instance p3, Lac0/a;

    .line 189
    .line 190
    const/16 v0, 0x1d

    .line 191
    .line 192
    invoke-direct {p3, p1, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 193
    .line 194
    .line 195
    invoke-static {p0, p3}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 196
    .line 197
    .line 198
    goto :goto_2

    .line 199
    :cond_4
    new-instance p3, Lac0/a;

    .line 200
    .line 201
    const/16 v0, 0x1d

    .line 202
    .line 203
    invoke-direct {p3, p1, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 204
    .line 205
    .line 206
    invoke-static {p0, p3}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 207
    .line 208
    .line 209
    :cond_5
    :goto_2
    iget-object p1, p0, Lq61/p;->e:Lyy0/c2;

    .line 210
    .line 211
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p3

    .line 215
    move-object v0, p3

    .line 216
    check-cast v0, Ljava/lang/Boolean;

    .line 217
    .line 218
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 219
    .line 220
    .line 221
    iget-object v0, p2, Lyy0/l1;->d:Lyy0/a2;

    .line 222
    .line 223
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    check-cast v0, Ljava/lang/Boolean;

    .line 228
    .line 229
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 230
    .line 231
    .line 232
    move-result v0

    .line 233
    if-eqz v0, :cond_6

    .line 234
    .line 235
    move v0, v2

    .line 236
    goto :goto_3

    .line 237
    :cond_6
    move v0, v5

    .line 238
    :goto_3
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    invoke-virtual {p1, p3, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    move-result p1

    .line 246
    if-eqz p1, :cond_5

    .line 247
    .line 248
    :goto_4
    return-void
.end method

.method public final updateDisplayMetrics(Landroid/util/DisplayMetrics;)V
    .locals 3

    .line 1
    const-string v0, "metrics"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :cond_0
    iget-object v0, p0, Lq61/p;->i:Lyy0/c2;

    .line 7
    .line 8
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    move-object v2, v1

    .line 13
    check-cast v2, Landroid/util/DisplayMetrics;

    .line 14
    .line 15
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    return-void
.end method
