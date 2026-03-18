.class public final synthetic Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;
.implements Lj8/l;
.implements Ly4/i;
.implements Lk0/a;
.implements Lgs/e;


# instance fields
.field public final synthetic d:Ljava/lang/Object;

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->d:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->g:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public apply(Ljava/lang/Object;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lu/g1;

    .line 4
    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroid/hardware/camera2/CameraDevice;

    .line 8
    .line 9
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lw/m;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Ljava/util/List;

    .line 16
    .line 17
    check-cast p1, Ljava/util/List;

    .line 18
    .line 19
    iget-object p1, v0, Lu/g1;->u:La8/t1;

    .line 20
    .line 21
    iget-boolean p1, p1, La8/t1;->b:Z

    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    iget-object p1, v0, Lu/g1;->b:Lu/x0;

    .line 26
    .line 27
    invoke-virtual {p1}, Lu/x0;->f()Ljava/util/ArrayList;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_0

    .line 40
    .line 41
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    check-cast v3, Lu/g1;

    .line 46
    .line 47
    invoke-virtual {v3}, Lu/g1;->i()V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    const-string p1, "start openCaptureSession"

    .line 52
    .line 53
    invoke-virtual {v0, p1}, Lu/g1;->k(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object p1, v0, Lu/g1;->a:Ljava/lang/Object;

    .line 57
    .line 58
    monitor-enter p1

    .line 59
    :try_start_0
    iget-boolean v3, v0, Lu/g1;->l:Z

    .line 60
    .line 61
    if-eqz v3, :cond_1

    .line 62
    .line 63
    new-instance p0, Ljava/util/concurrent/CancellationException;

    .line 64
    .line 65
    const-string v0, "Opener is disabled"

    .line 66
    .line 67
    invoke-direct {p0, v0}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    new-instance v0, Lk0/j;

    .line 71
    .line 72
    const/4 v1, 0x1

    .line 73
    invoke-direct {v0, p0, v1}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 74
    .line 75
    .line 76
    monitor-exit p1

    .line 77
    return-object v0

    .line 78
    :catchall_0
    move-exception p0

    .line 79
    goto :goto_1

    .line 80
    :cond_1
    iget-object v3, v0, Lu/g1;->b:Lu/x0;

    .line 81
    .line 82
    iget-object v4, v3, Lu/x0;->b:Ljava/lang/Object;

    .line 83
    .line 84
    monitor-enter v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    :try_start_1
    iget-object v3, v3, Lu/x0;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v3, Ljava/util/LinkedHashSet;

    .line 88
    .line 89
    invoke-interface {v3, v0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 93
    :try_start_2
    new-instance v3, Lt1/j0;

    .line 94
    .line 95
    invoke-direct {v3, v1}, Lt1/j0;-><init>(Landroid/hardware/camera2/CameraDevice;)V

    .line 96
    .line 97
    .line 98
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;

    .line 99
    .line 100
    invoke-direct {v1, v0, p0, v3, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    invoke-static {v1}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    iput-object p0, v0, Lu/g1;->g:Ly4/k;

    .line 108
    .line 109
    new-instance v1, Lpv/g;

    .line 110
    .line 111
    const/16 v2, 0xa

    .line 112
    .line 113
    invoke-direct {v1, v0, v2}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 114
    .line 115
    .line 116
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    new-instance v3, Lk0/g;

    .line 121
    .line 122
    const/4 v4, 0x0

    .line 123
    invoke-direct {v3, v4, p0, v1}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {p0, v2, v3}, Ly4/k;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 127
    .line 128
    .line 129
    iget-object p0, v0, Lu/g1;->g:Ly4/k;

    .line 130
    .line 131
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 136
    return-object p0

    .line 137
    :catchall_1
    move-exception p0

    .line 138
    :try_start_3
    monitor-exit v4
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 139
    :try_start_4
    throw p0

    .line 140
    :goto_1
    monitor-exit p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 141
    throw p0
.end method

.method public d(ILt7/q0;[I)Lhr/x0;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p2

    .line 4
    .line 5
    iget-object v1, v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->d:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v4, v1

    .line 8
    check-cast v4, Lj8/i;

    .line 9
    .line 10
    iget-object v1, v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->e:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v6, v1

    .line 13
    check-cast v6, Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, [I

    .line 18
    .line 19
    iget-object v0, v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->g:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Landroid/graphics/Point;

    .line 22
    .line 23
    aget v7, v1, p1

    .line 24
    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    iget v1, v0, Landroid/graphics/Point;->x:I

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    iget v1, v4, Lt7/u0;->e:I

    .line 31
    .line 32
    :goto_0
    if-eqz v0, :cond_1

    .line 33
    .line 34
    iget v0, v0, Landroid/graphics/Point;->y:I

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    iget v0, v4, Lt7/u0;->f:I

    .line 38
    .line 39
    :goto_1
    iget-boolean v3, v4, Lt7/u0;->h:Z

    .line 40
    .line 41
    const v9, 0x7fffffff

    .line 42
    .line 43
    .line 44
    if-eq v1, v9, :cond_9

    .line 45
    .line 46
    if-ne v0, v9, :cond_2

    .line 47
    .line 48
    goto/16 :goto_7

    .line 49
    .line 50
    :cond_2
    move v8, v9

    .line 51
    const/4 v5, 0x0

    .line 52
    :goto_2
    iget v12, v2, Lt7/q0;->a:I

    .line 53
    .line 54
    if-ge v5, v12, :cond_8

    .line 55
    .line 56
    iget-object v12, v2, Lt7/q0;->d:[Lt7/o;

    .line 57
    .line 58
    aget-object v12, v12, v5

    .line 59
    .line 60
    iget v13, v12, Lt7/o;->u:I

    .line 61
    .line 62
    iget v14, v12, Lt7/o;->v:I

    .line 63
    .line 64
    if-lez v13, :cond_7

    .line 65
    .line 66
    if-lez v14, :cond_7

    .line 67
    .line 68
    if-eqz v3, :cond_5

    .line 69
    .line 70
    if-le v13, v14, :cond_3

    .line 71
    .line 72
    const/4 v15, 0x1

    .line 73
    goto :goto_3

    .line 74
    :cond_3
    const/4 v15, 0x0

    .line 75
    :goto_3
    if-le v1, v0, :cond_4

    .line 76
    .line 77
    const/4 v10, 0x1

    .line 78
    goto :goto_4

    .line 79
    :cond_4
    const/4 v10, 0x0

    .line 80
    :goto_4
    if-eq v15, v10, :cond_5

    .line 81
    .line 82
    move v15, v0

    .line 83
    move v10, v1

    .line 84
    goto :goto_5

    .line 85
    :cond_5
    move v10, v0

    .line 86
    move v15, v1

    .line 87
    :goto_5
    mul-int v11, v13, v10

    .line 88
    .line 89
    mul-int v9, v14, v15

    .line 90
    .line 91
    if-lt v11, v9, :cond_6

    .line 92
    .line 93
    new-instance v10, Landroid/graphics/Point;

    .line 94
    .line 95
    invoke-static {v9, v13}, Lw7/w;->e(II)I

    .line 96
    .line 97
    .line 98
    move-result v9

    .line 99
    invoke-direct {v10, v15, v9}, Landroid/graphics/Point;-><init>(II)V

    .line 100
    .line 101
    .line 102
    goto :goto_6

    .line 103
    :cond_6
    new-instance v9, Landroid/graphics/Point;

    .line 104
    .line 105
    invoke-static {v11, v14}, Lw7/w;->e(II)I

    .line 106
    .line 107
    .line 108
    move-result v11

    .line 109
    invoke-direct {v9, v11, v10}, Landroid/graphics/Point;-><init>(II)V

    .line 110
    .line 111
    .line 112
    move-object v10, v9

    .line 113
    :goto_6
    iget v9, v12, Lt7/o;->u:I

    .line 114
    .line 115
    mul-int v11, v9, v14

    .line 116
    .line 117
    iget v12, v10, Landroid/graphics/Point;->x:I

    .line 118
    .line 119
    int-to-float v12, v12

    .line 120
    const v13, 0x3f7ae148    # 0.98f

    .line 121
    .line 122
    .line 123
    mul-float/2addr v12, v13

    .line 124
    float-to-int v12, v12

    .line 125
    if-lt v9, v12, :cond_7

    .line 126
    .line 127
    iget v9, v10, Landroid/graphics/Point;->y:I

    .line 128
    .line 129
    int-to-float v9, v9

    .line 130
    mul-float/2addr v9, v13

    .line 131
    float-to-int v9, v9

    .line 132
    if-lt v14, v9, :cond_7

    .line 133
    .line 134
    if-ge v11, v8, :cond_7

    .line 135
    .line 136
    move v8, v11

    .line 137
    :cond_7
    add-int/lit8 v5, v5, 0x1

    .line 138
    .line 139
    const v9, 0x7fffffff

    .line 140
    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_8
    move v9, v8

    .line 144
    goto :goto_8

    .line 145
    :cond_9
    :goto_7
    const v9, 0x7fffffff

    .line 146
    .line 147
    .line 148
    :goto_8
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 149
    .line 150
    .line 151
    move-result-object v10

    .line 152
    const/4 v3, 0x0

    .line 153
    :goto_9
    iget v0, v2, Lt7/q0;->a:I

    .line 154
    .line 155
    if-ge v3, v0, :cond_e

    .line 156
    .line 157
    iget-object v0, v2, Lt7/q0;->d:[Lt7/o;

    .line 158
    .line 159
    aget-object v0, v0, v3

    .line 160
    .line 161
    iget v1, v0, Lt7/o;->u:I

    .line 162
    .line 163
    const/4 v5, -0x1

    .line 164
    if-eq v1, v5, :cond_b

    .line 165
    .line 166
    iget v0, v0, Lt7/o;->v:I

    .line 167
    .line 168
    if-ne v0, v5, :cond_a

    .line 169
    .line 170
    goto :goto_b

    .line 171
    :cond_a
    mul-int/2addr v1, v0

    .line 172
    :goto_a
    const v11, 0x7fffffff

    .line 173
    .line 174
    .line 175
    goto :goto_c

    .line 176
    :cond_b
    :goto_b
    move v1, v5

    .line 177
    goto :goto_a

    .line 178
    :goto_c
    if-eq v9, v11, :cond_d

    .line 179
    .line 180
    if-eq v1, v5, :cond_c

    .line 181
    .line 182
    if-gt v1, v9, :cond_c

    .line 183
    .line 184
    goto :goto_d

    .line 185
    :cond_c
    const/4 v8, 0x0

    .line 186
    goto :goto_e

    .line 187
    :cond_d
    :goto_d
    const/4 v8, 0x1

    .line 188
    :goto_e
    new-instance v0, Lj8/n;

    .line 189
    .line 190
    aget v5, p3, v3

    .line 191
    .line 192
    move/from16 v1, p1

    .line 193
    .line 194
    invoke-direct/range {v0 .. v8}, Lj8/n;-><init>(ILt7/q0;ILj8/i;ILjava/lang/String;IZ)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v10, v0}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    add-int/lit8 v3, v3, 0x1

    .line 201
    .line 202
    move-object/from16 v2, p2

    .line 203
    .line 204
    goto :goto_9

    .line 205
    :cond_e
    invoke-virtual {v10}, Lhr/e0;->i()Lhr/x0;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    return-object v0
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lgs/s;

    .line 4
    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lgs/s;

    .line 8
    .line 9
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lgs/s;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lgs/s;

    .line 16
    .line 17
    new-instance v3, Las/d;

    .line 18
    .line 19
    const-class v4, Lsr/f;

    .line 20
    .line 21
    invoke-virtual {p1, v4}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    check-cast v4, Lsr/f;

    .line 26
    .line 27
    const-class v5, Let/e;

    .line 28
    .line 29
    invoke-virtual {p1, v5}, Lin/z1;->f(Ljava/lang/Class;)Lgt/b;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    invoke-virtual {p1, v0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    move-object v6, v0

    .line 38
    check-cast v6, Ljava/util/concurrent/Executor;

    .line 39
    .line 40
    invoke-virtual {p1, v1}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    move-object v7, v0

    .line 45
    check-cast v7, Ljava/util/concurrent/Executor;

    .line 46
    .line 47
    invoke-virtual {p1, v2}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    move-object v8, v0

    .line 52
    check-cast v8, Ljava/util/concurrent/Executor;

    .line 53
    .line 54
    invoke-virtual {p1, p0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    move-object v9, p0

    .line 59
    check-cast v9, Ljava/util/concurrent/ScheduledExecutorService;

    .line 60
    .line 61
    invoke-direct/range {v3 .. v9}, Las/d;-><init>(Lsr/f;Lgt/b;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;Ljava/util/concurrent/ScheduledExecutorService;)V

    .line 62
    .line 63
    .line 64
    return-object v3
.end method

.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lu/g1;

    .line 4
    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/util/List;

    .line 8
    .line 9
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lt1/j0;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lw/m;

    .line 16
    .line 17
    const-string v3, "openCaptureSession[session="

    .line 18
    .line 19
    iget-object v4, v0, Lu/g1;->a:Ljava/lang/Object;

    .line 20
    .line 21
    monitor-enter v4

    .line 22
    :try_start_0
    iget-object v5, v0, Lu/g1;->a:Ljava/lang/Object;

    .line 23
    .line 24
    monitor-enter v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 25
    :try_start_1
    iget-object v6, v0, Lu/g1;->a:Ljava/lang/Object;

    .line 26
    .line 27
    monitor-enter v6
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 28
    :try_start_2
    iget-object v7, v0, Lu/g1;->j:Ljava/util/List;

    .line 29
    .line 30
    if-eqz v7, :cond_1

    .line 31
    .line 32
    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v7

    .line 36
    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v8

    .line 40
    if-eqz v8, :cond_0

    .line 41
    .line 42
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v8

    .line 46
    check-cast v8, Lh0/t0;

    .line 47
    .line 48
    invoke-virtual {v8}, Lh0/t0;->b()V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    const/4 v7, 0x0

    .line 53
    iput-object v7, v0, Lu/g1;->j:Ljava/util/List;

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :cond_1
    :goto_1
    monitor-exit v6
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 60
    :try_start_3
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 61
    .line 62
    .line 63
    move-result v6
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 64
    const/4 v7, 0x0

    .line 65
    const/4 v8, 0x1

    .line 66
    if-nez v6, :cond_4

    .line 67
    .line 68
    move v6, v7

    .line 69
    :cond_2
    :try_start_4
    invoke-interface {v1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v9

    .line 73
    check-cast v9, Lh0/t0;

    .line 74
    .line 75
    invoke-virtual {v9}, Lh0/t0;->d()V

    .line 76
    .line 77
    .line 78
    add-int/lit8 v6, v6, 0x1

    .line 79
    .line 80
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 81
    .line 82
    .line 83
    move-result v9
    :try_end_4
    .catch Lh0/s0; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 84
    if-lt v6, v9, :cond_2

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :catch_0
    move-exception p0

    .line 88
    sub-int/2addr v6, v8

    .line 89
    :goto_2
    if-ltz v6, :cond_3

    .line 90
    .line 91
    :try_start_5
    invoke-interface {v1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    check-cast p1, Lh0/t0;

    .line 96
    .line 97
    invoke-virtual {p1}, Lh0/t0;->b()V

    .line 98
    .line 99
    .line 100
    add-int/lit8 v6, v6, -0x1

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_3
    throw p0

    .line 104
    :cond_4
    :goto_3
    iput-object v1, v0, Lu/g1;->j:Ljava/util/List;

    .line 105
    .line 106
    monitor-exit v5
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 107
    :try_start_6
    iget-object v1, v0, Lu/g1;->h:Ly4/h;

    .line 108
    .line 109
    if-nez v1, :cond_5

    .line 110
    .line 111
    move v7, v8

    .line 112
    :cond_5
    const-string v1, "The openCaptureSessionCompleter can only set once!"

    .line 113
    .line 114
    invoke-static {v1, v7}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 115
    .line 116
    .line 117
    iput-object p1, v0, Lu/g1;->h:Ly4/h;

    .line 118
    .line 119
    iget-object p1, v2, Lt1/j0;->e:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast p1, Lv/c;

    .line 122
    .line 123
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    iget-object p0, p0, Lw/m;->a:Lw/l;

    .line 127
    .line 128
    iget-object p0, p0, Lw/l;->a:Landroid/hardware/camera2/params/SessionConfiguration;

    .line 129
    .line 130
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 131
    .line 132
    .line 133
    :try_start_7
    iget-object p1, p1, Lh/w;->b:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast p1, Landroid/hardware/camera2/CameraDevice;

    .line 136
    .line 137
    invoke-virtual {p1, p0}, Landroid/hardware/camera2/CameraDevice;->createCaptureSession(Landroid/hardware/camera2/params/SessionConfiguration;)V
    :try_end_7
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_7 .. :try_end_7} :catch_1
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 138
    .line 139
    .line 140
    :try_start_8
    new-instance p0, Ljava/lang/StringBuilder;

    .line 141
    .line 142
    invoke-direct {p0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    const-string p1, "]"

    .line 149
    .line 150
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    monitor-exit v4

    .line 158
    return-object p0

    .line 159
    :catchall_1
    move-exception p0

    .line 160
    goto :goto_6

    .line 161
    :catch_1
    move-exception p0

    .line 162
    new-instance p1, Lv/a;

    .line 163
    .line 164
    invoke-direct {p1, p0}, Lv/a;-><init>(Landroid/hardware/camera2/CameraAccessException;)V

    .line 165
    .line 166
    .line 167
    throw p1
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 168
    :catchall_2
    move-exception p0

    .line 169
    goto :goto_5

    .line 170
    :goto_4
    :try_start_9
    monitor-exit v6
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 171
    :try_start_a
    throw p0

    .line 172
    :goto_5
    monitor-exit v5
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 173
    :try_start_b
    throw p0

    .line 174
    :goto_6
    monitor-exit v4
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_1

    .line 175
    throw p0
.end method

.method public ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;

    .line 4
    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;

    .line 8
    .line 9
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

    .line 16
    .line 17
    invoke-static {v0, v1, v2, p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->a(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
