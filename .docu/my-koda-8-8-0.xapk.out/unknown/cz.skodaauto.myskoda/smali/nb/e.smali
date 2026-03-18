.class public abstract Lnb/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0xf

    .line 2
    .line 3
    const/16 v1, 0xe

    .line 4
    .line 5
    const/16 v2, 0xd

    .line 6
    .line 7
    filled-new-array {v2, v0, v1}, [I

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lnb/e;->a:[I

    .line 12
    .line 13
    return-void
.end method

.method public static final a(Lfb/u;Ljava/lang/String;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 2
    .line 3
    const-string v1, "getWorkDatabase(...)"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->s()Lmb/b;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    filled-new-array {p1}, [Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-static {v2}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    :goto_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    const/4 v4, 0x1

    .line 29
    if-nez v3, :cond_1

    .line 30
    .line 31
    invoke-static {v2}, Lmx0/q;->e0(Ljava/util/List;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    check-cast v3, Ljava/lang/String;

    .line 36
    .line 37
    invoke-virtual {v1, v3}, Lmb/s;->d(Ljava/lang/String;)Leb/h0;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    sget-object v6, Leb/h0;->f:Leb/h0;

    .line 42
    .line 43
    if-eq v5, v6, :cond_0

    .line 44
    .line 45
    sget-object v6, Leb/h0;->g:Leb/h0;

    .line 46
    .line 47
    if-eq v5, v6, :cond_0

    .line 48
    .line 49
    iget-object v5, v1, Lmb/s;->a:Lla/u;

    .line 50
    .line 51
    new-instance v6, Lif0/d;

    .line 52
    .line 53
    const/16 v7, 0x14

    .line 54
    .line 55
    invoke-direct {v6, v3, v7}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 56
    .line 57
    .line 58
    const/4 v7, 0x0

    .line 59
    invoke-static {v5, v7, v4, v6}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    check-cast v4, Ljava/lang/Number;

    .line 64
    .line 65
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 66
    .line 67
    .line 68
    :cond_0
    invoke-virtual {v0, v3}, Lmb/b;->a(Ljava/lang/String;)Ljava/util/List;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    check-cast v3, Ljava/util/Collection;

    .line 73
    .line 74
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_1
    iget-object v0, p0, Lfb/u;->f:Lfb/e;

    .line 79
    .line 80
    const-string v1, "getProcessor(...)"

    .line 81
    .line 82
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const-string v1, "Processor cancelling "

    .line 86
    .line 87
    iget-object v2, v0, Lfb/e;->k:Ljava/lang/Object;

    .line 88
    .line 89
    monitor-enter v2

    .line 90
    :try_start_0
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    sget-object v5, Lfb/e;->l:Ljava/lang/String;

    .line 95
    .line 96
    new-instance v6, Ljava/lang/StringBuilder;

    .line 97
    .line 98
    invoke-direct {v6, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    invoke-virtual {v3, v5, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    iget-object v1, v0, Lfb/e;->i:Ljava/util/HashSet;

    .line 112
    .line 113
    invoke-virtual {v1, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    invoke-virtual {v0, p1}, Lfb/e;->b(Ljava/lang/String;)Lfb/f0;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 121
    invoke-static {p1, v0, v4}, Lfb/e;->d(Ljava/lang/String;Lfb/f0;I)Z

    .line 122
    .line 123
    .line 124
    iget-object p0, p0, Lfb/u;->e:Ljava/util/List;

    .line 125
    .line 126
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-eqz v0, :cond_2

    .line 135
    .line 136
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    check-cast v0, Lfb/g;

    .line 141
    .line 142
    invoke-interface {v0, p1}, Lfb/g;->c(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_2
    return-void

    .line 147
    :catchall_0
    move-exception p0

    .line 148
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 149
    throw p0
.end method

.method public static final b(Landroidx/work/impl/WorkDatabase;Leb/b;Lfb/o;)V
    .locals 5

    .line 1
    const-string v0, "workDatabase"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "configuration"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    filled-new-array {p2}, [Lfb/o;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    invoke-static {p2}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    const/4 v0, 0x0

    .line 20
    move v1, v0

    .line 21
    :goto_0
    invoke-virtual {p2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-nez v2, :cond_4

    .line 26
    .line 27
    invoke-static {p2}, Lmx0/q;->e0(Ljava/util/List;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    check-cast v2, Lfb/o;

    .line 32
    .line 33
    iget-object v2, v2, Lfb/o;->d:Ljava/util/List;

    .line 34
    .line 35
    const-string v3, "getWork(...)"

    .line 36
    .line 37
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    check-cast v2, Ljava/lang/Iterable;

    .line 41
    .line 42
    instance-of v3, v2, Ljava/util/Collection;

    .line 43
    .line 44
    if-eqz v3, :cond_0

    .line 45
    .line 46
    move-object v3, v2

    .line 47
    check-cast v3, Ljava/util/Collection;

    .line 48
    .line 49
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eqz v3, :cond_0

    .line 54
    .line 55
    move v3, v0

    .line 56
    goto :goto_2

    .line 57
    :cond_0
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    move v3, v0

    .line 62
    :cond_1
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-eqz v4, :cond_3

    .line 67
    .line 68
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    check-cast v4, Leb/k0;

    .line 73
    .line 74
    iget-object v4, v4, Leb/k0;->b:Lmb/o;

    .line 75
    .line 76
    iget-object v4, v4, Lmb/o;->j:Leb/e;

    .line 77
    .line 78
    invoke-virtual {v4}, Leb/e;->b()Z

    .line 79
    .line 80
    .line 81
    move-result v4

    .line 82
    if-eqz v4, :cond_1

    .line 83
    .line 84
    add-int/lit8 v3, v3, 0x1

    .line 85
    .line 86
    if-ltz v3, :cond_2

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_2
    invoke-static {}, Ljp/k1;->q()V

    .line 90
    .line 91
    .line 92
    const/4 p0, 0x0

    .line 93
    throw p0

    .line 94
    :cond_3
    :goto_2
    add-int/2addr v1, v3

    .line 95
    goto :goto_0

    .line 96
    :cond_4
    if-nez v1, :cond_5

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_5
    invoke-virtual {p0}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    iget-object p0, p0, Lmb/s;->a:Lla/u;

    .line 104
    .line 105
    new-instance p2, Lm40/e;

    .line 106
    .line 107
    const/16 v2, 0xf

    .line 108
    .line 109
    invoke-direct {p2, v2}, Lm40/e;-><init>(I)V

    .line 110
    .line 111
    .line 112
    const/4 v2, 0x1

    .line 113
    invoke-static {p0, v2, v0, p2}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    check-cast p0, Ljava/lang/Number;

    .line 118
    .line 119
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    iget p1, p1, Leb/b;->j:I

    .line 124
    .line 125
    add-int p2, p0, v1

    .line 126
    .line 127
    if-gt p2, p1, :cond_6

    .line 128
    .line 129
    :goto_3
    return-void

    .line 130
    :cond_6
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 131
    .line 132
    const-string v0, ";\nalready enqueued count: "

    .line 133
    .line 134
    const-string v2, ";\ncurrent enqueue operation count: "

    .line 135
    .line 136
    const-string v3, "Too many workers with contentUriTriggers are enqueued:\ncontentUriTrigger workers limit: "

    .line 137
    .line 138
    invoke-static {p1, p0, v3, v0, v2}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    const-string p1, ".\nTo address this issue you can: \n1. enqueue less workers or batch some of workers with content uri triggers together;\n2. increase limit via Configuration.Builder.setContentUriTriggerWorkersLimit;\nPlease beware that workers with content uri triggers immediately occupy slots in JobScheduler so no updates to content uris are missed."

    .line 143
    .line 144
    invoke-static {v1, p1, p0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    throw p2
.end method

.method public static c([I[I)Lnb/d;
    .locals 13

    .line 1
    new-instance v0, Lnb/d;

    .line 2
    .line 3
    new-instance v1, Landroid/net/NetworkRequest$Builder;

    .line 4
    .line 5
    invoke-direct {v1}, Landroid/net/NetworkRequest$Builder;-><init>()V

    .line 6
    .line 7
    .line 8
    array-length v2, p0

    .line 9
    const/4 v3, 0x0

    .line 10
    move v4, v3

    .line 11
    :goto_0
    const/4 v5, 0x5

    .line 12
    const/16 v6, 0x27

    .line 13
    .line 14
    if-ge v4, v2, :cond_1

    .line 15
    .line 16
    aget v7, p0, v4

    .line 17
    .line 18
    :try_start_0
    invoke-virtual {v1, v7}, Landroid/net/NetworkRequest$Builder;->addCapability(I)Landroid/net/NetworkRequest$Builder;
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    goto :goto_1

    .line 22
    :catch_0
    move-exception v8

    .line 23
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 24
    .line 25
    .line 26
    move-result-object v9

    .line 27
    sget-object v10, Lnb/d;->b:Ljava/lang/String;

    .line 28
    .line 29
    sget-object v10, Lnb/d;->b:Ljava/lang/String;

    .line 30
    .line 31
    new-instance v11, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v12, "Ignoring adding capability \'"

    .line 34
    .line 35
    invoke-direct {v11, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v11, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    iget v7, v9, Leb/w;->a:I

    .line 49
    .line 50
    if-gt v7, v5, :cond_0

    .line 51
    .line 52
    invoke-static {v10, v6, v8}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 53
    .line 54
    .line 55
    :cond_0
    :goto_1
    add-int/lit8 v4, v4, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    move v2, v3

    .line 59
    :goto_2
    const/4 v4, 0x3

    .line 60
    if-ge v2, v4, :cond_3

    .line 61
    .line 62
    sget-object v4, Lnb/e;->a:[I

    .line 63
    .line 64
    aget v4, v4, v2

    .line 65
    .line 66
    invoke-static {v4, p0}, Lmx0/n;->d(I[I)Z

    .line 67
    .line 68
    .line 69
    move-result v7

    .line 70
    if-nez v7, :cond_2

    .line 71
    .line 72
    :try_start_1
    invoke-virtual {v1, v4}, Landroid/net/NetworkRequest$Builder;->removeCapability(I)Landroid/net/NetworkRequest$Builder;
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    .line 73
    .line 74
    .line 75
    goto :goto_3

    .line 76
    :catch_1
    move-exception v7

    .line 77
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 78
    .line 79
    .line 80
    move-result-object v8

    .line 81
    sget-object v9, Lnb/d;->b:Ljava/lang/String;

    .line 82
    .line 83
    sget-object v9, Lnb/d;->b:Ljava/lang/String;

    .line 84
    .line 85
    new-instance v10, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    const-string v11, "Ignoring removing default capability \'"

    .line 88
    .line 89
    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v10, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    iget v8, v8, Leb/w;->a:I

    .line 103
    .line 104
    if-gt v8, v5, :cond_2

    .line 105
    .line 106
    invoke-static {v9, v4, v7}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 107
    .line 108
    .line 109
    :cond_2
    :goto_3
    add-int/lit8 v2, v2, 0x1

    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_3
    array-length p0, p1

    .line 113
    :goto_4
    if-ge v3, p0, :cond_4

    .line 114
    .line 115
    aget v2, p1, v3

    .line 116
    .line 117
    invoke-virtual {v1, v2}, Landroid/net/NetworkRequest$Builder;->addTransportType(I)Landroid/net/NetworkRequest$Builder;

    .line 118
    .line 119
    .line 120
    add-int/lit8 v3, v3, 0x1

    .line 121
    .line 122
    goto :goto_4

    .line 123
    :cond_4
    invoke-virtual {v1}, Landroid/net/NetworkRequest$Builder;->build()Landroid/net/NetworkRequest;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    const-string p1, "build(...)"

    .line 128
    .line 129
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    invoke-direct {v0, p0}, Lnb/d;-><init>(Landroid/net/NetworkRequest;)V

    .line 133
    .line 134
    .line 135
    return-object v0
.end method
