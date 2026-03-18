.class public final Lt3/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/j;


# instance fields
.field public final d:Lv3/h0;

.field public e:Ll2/x;

.field public f:Lt3/q1;

.field public g:I

.field public h:I

.field public final i:Landroidx/collection/q0;

.field public final j:Landroidx/collection/q0;

.field public final k:Lt3/h0;

.field public final l:Lt3/e0;

.field public final m:Landroidx/collection/q0;

.field public final n:Landroidx/collection/e1;

.field public final o:Landroidx/collection/q0;

.field public final p:Ln2/b;

.field public q:I

.field public r:I

.field public final s:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lv3/h0;Lt3/q1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt3/m0;->d:Lv3/h0;

    .line 5
    .line 6
    iput-object p2, p0, Lt3/m0;->f:Lt3/q1;

    .line 7
    .line 8
    sget-object p1, Landroidx/collection/y0;->a:[J

    .line 9
    .line 10
    new-instance p1, Landroidx/collection/q0;

    .line 11
    .line 12
    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 16
    .line 17
    new-instance p1, Landroidx/collection/q0;

    .line 18
    .line 19
    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Lt3/m0;->j:Landroidx/collection/q0;

    .line 23
    .line 24
    new-instance p1, Lt3/h0;

    .line 25
    .line 26
    invoke-direct {p1, p0}, Lt3/h0;-><init>(Lt3/m0;)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lt3/m0;->k:Lt3/h0;

    .line 30
    .line 31
    new-instance p1, Lt3/e0;

    .line 32
    .line 33
    invoke-direct {p1, p0}, Lt3/e0;-><init>(Lt3/m0;)V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lt3/m0;->l:Lt3/e0;

    .line 37
    .line 38
    new-instance p1, Landroidx/collection/q0;

    .line 39
    .line 40
    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 41
    .line 42
    .line 43
    iput-object p1, p0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 44
    .line 45
    new-instance p1, Landroidx/collection/e1;

    .line 46
    .line 47
    invoke-direct {p1}, Landroidx/collection/e1;-><init>()V

    .line 48
    .line 49
    .line 50
    iput-object p1, p0, Lt3/m0;->n:Landroidx/collection/e1;

    .line 51
    .line 52
    new-instance p1, Landroidx/collection/q0;

    .line 53
    .line 54
    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 55
    .line 56
    .line 57
    iput-object p1, p0, Lt3/m0;->o:Landroidx/collection/q0;

    .line 58
    .line 59
    new-instance p1, Ln2/b;

    .line 60
    .line 61
    const/16 p2, 0x10

    .line 62
    .line 63
    new-array p2, p2, [Ljava/lang/Object;

    .line 64
    .line 65
    invoke-direct {p1, p2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iput-object p1, p0, Lt3/m0;->p:Ln2/b;

    .line 69
    .line 70
    const-string p1, "Asking for intrinsic measurements of SubcomposeLayout layouts is not supported. This includes components that are built on top of SubcomposeLayout, such as lazy lists, BoxWithConstraints, TabRow, etc. To mitigate this:\n- if intrinsic measurements are used to achieve \'match parent\' sizing, consider replacing the parent of the component with a custom layout which controls the order in which children are measured, making intrinsic measurement not needed\n- adding a size modifier to the component, in order to fast return the queried intrinsic measurement."

    .line 71
    .line 72
    iput-object p1, p0, Lt3/m0;->s:Ljava/lang/String;

    .line 73
    .line 74
    return-void
.end method

.method public static b(Lt3/f0;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lt3/f0;->f:Ll2/m1;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    iget-object v1, v0, Ll2/m1;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 6
    .line 7
    sget-object v2, Ll2/n1;->e:Ll2/n1;

    .line 8
    .line 9
    invoke-virtual {v1, v2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, v0, Ll2/m1;->j:Ljp/uf;

    .line 13
    .line 14
    iget-object v2, v1, Ljp/uf;->d:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Landroidx/collection/r0;

    .line 17
    .line 18
    invoke-virtual {v2}, Landroidx/collection/r0;->h()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    const/4 v3, 0x0

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    iget-object v2, v1, Ljp/uf;->d:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v2, Landroidx/collection/r0;

    .line 28
    .line 29
    sget-object v4, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 30
    .line 31
    new-instance v4, Landroidx/collection/r0;

    .line 32
    .line 33
    invoke-direct {v4}, Landroidx/collection/r0;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object v4, v1, Ljp/uf;->d:Ljava/lang/Object;

    .line 37
    .line 38
    iget-object v4, v1, Ljp/uf;->c:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v4, Ln2/b;

    .line 41
    .line 42
    invoke-virtual {v4}, Ln2/b;->i()V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    move-object v2, v3

    .line 47
    :goto_0
    invoke-virtual {v1}, Ljp/uf;->b()V

    .line 48
    .line 49
    .line 50
    iget-object v0, v0, Ll2/m1;->a:Ll2/a0;

    .line 51
    .line 52
    iput-object v3, v0, Ll2/a0;->t:Ll2/m1;

    .line 53
    .line 54
    if-eqz v2, :cond_1

    .line 55
    .line 56
    iget-object v1, v0, Ll2/a0;->x:Ljp/uf;

    .line 57
    .line 58
    iput-object v2, v1, Ljp/uf;->j:Ljava/lang/Object;

    .line 59
    .line 60
    const/4 v1, 0x2

    .line 61
    iput v1, v0, Ll2/a0;->z:I

    .line 62
    .line 63
    :cond_1
    iput-object v3, p0, Lt3/f0;->f:Ll2/m1;

    .line 64
    .line 65
    iget-object v0, p0, Lt3/f0;->c:Ll2/a0;

    .line 66
    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    invoke-virtual {v0}, Ll2/a0;->dispose()V

    .line 70
    .line 71
    .line 72
    :cond_2
    iput-object v3, p0, Lt3/f0;->c:Ll2/a0;

    .line 73
    .line 74
    :cond_3
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Lt3/m0;->g(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final c(I)V
    .locals 13

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lt3/m0;->q:I

    .line 3
    .line 4
    iget-object v1, p0, Lt3/m0;->d:Lv3/h0;

    .line 5
    .line 6
    invoke-virtual {v1}, Lv3/h0;->p()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Landroidx/collection/j0;

    .line 12
    .line 13
    iget-object v3, v2, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v3, Ln2/b;

    .line 16
    .line 17
    iget v3, v3, Ln2/b;->f:I

    .line 18
    .line 19
    iget v4, p0, Lt3/m0;->r:I

    .line 20
    .line 21
    sub-int/2addr v3, v4

    .line 22
    const/4 v4, 0x1

    .line 23
    sub-int/2addr v3, v4

    .line 24
    if-gt p1, v3, :cond_7

    .line 25
    .line 26
    iget-object v5, p0, Lt3/m0;->n:Landroidx/collection/e1;

    .line 27
    .line 28
    invoke-virtual {v5}, Landroidx/collection/e1;->clear()V

    .line 29
    .line 30
    .line 31
    if-gt p1, v3, :cond_0

    .line 32
    .line 33
    move v5, p1

    .line 34
    :goto_0
    invoke-virtual {v2, v5}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v6

    .line 38
    check-cast v6, Lv3/h0;

    .line 39
    .line 40
    iget-object v7, p0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 41
    .line 42
    invoke-virtual {v7, v6}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v6

    .line 46
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    check-cast v6, Lt3/f0;

    .line 50
    .line 51
    iget-object v6, v6, Lt3/f0;->a:Ljava/lang/Object;

    .line 52
    .line 53
    iget-object v7, p0, Lt3/m0;->n:Landroidx/collection/e1;

    .line 54
    .line 55
    iget-object v7, v7, Landroidx/collection/e1;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v7, Landroidx/collection/m0;

    .line 58
    .line 59
    invoke-virtual {v7, v6}, Landroidx/collection/m0;->a(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    if-eq v5, v3, :cond_0

    .line 63
    .line 64
    add-int/lit8 v5, v5, 0x1

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_0
    iget-object v2, p0, Lt3/m0;->f:Lt3/q1;

    .line 68
    .line 69
    iget-object v5, p0, Lt3/m0;->n:Landroidx/collection/e1;

    .line 70
    .line 71
    invoke-interface {v2, v5}, Lt3/q1;->r(Landroidx/collection/e1;)V

    .line 72
    .line 73
    .line 74
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    if-eqz v2, :cond_1

    .line 79
    .line 80
    invoke-virtual {v2}, Lv2/f;->e()Lay0/k;

    .line 81
    .line 82
    .line 83
    move-result-object v5

    .line 84
    goto :goto_1

    .line 85
    :cond_1
    const/4 v5, 0x0

    .line 86
    :goto_1
    invoke-static {v2}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 87
    .line 88
    .line 89
    move-result-object v6

    .line 90
    move v7, v0

    .line 91
    :goto_2
    if-lt v3, p1, :cond_6

    .line 92
    .line 93
    :try_start_0
    move-object v8, v1

    .line 94
    check-cast v8, Landroidx/collection/j0;

    .line 95
    .line 96
    invoke-virtual {v8, v3}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v8

    .line 100
    check-cast v8, Lv3/h0;

    .line 101
    .line 102
    iget-object v9, p0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 103
    .line 104
    invoke-virtual {v9, v8}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v9

    .line 108
    invoke-static {v9}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    check-cast v9, Lt3/f0;

    .line 112
    .line 113
    iget-object v10, v9, Lt3/f0;->a:Ljava/lang/Object;

    .line 114
    .line 115
    iget-object v11, p0, Lt3/m0;->n:Landroidx/collection/e1;

    .line 116
    .line 117
    iget-object v11, v11, Landroidx/collection/e1;->e:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v11, Landroidx/collection/m0;

    .line 120
    .line 121
    invoke-virtual {v11, v10}, Landroidx/collection/m0;->c(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v11

    .line 125
    if-eqz v11, :cond_3

    .line 126
    .line 127
    iget v11, p0, Lt3/m0;->q:I

    .line 128
    .line 129
    add-int/2addr v11, v4

    .line 130
    iput v11, p0, Lt3/m0;->q:I

    .line 131
    .line 132
    iget-object v11, v9, Lt3/f0;->g:Ll2/j1;

    .line 133
    .line 134
    invoke-virtual {v11}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v11

    .line 138
    check-cast v11, Ljava/lang/Boolean;

    .line 139
    .line 140
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 141
    .line 142
    .line 143
    move-result v11

    .line 144
    if-eqz v11, :cond_5

    .line 145
    .line 146
    iget-object v8, v8, Lv3/h0;->I:Lv3/l0;

    .line 147
    .line 148
    iget-object v11, v8, Lv3/l0;->p:Lv3/y0;

    .line 149
    .line 150
    sget-object v12, Lv3/f0;->f:Lv3/f0;

    .line 151
    .line 152
    iput-object v12, v11, Lv3/y0;->o:Lv3/f0;

    .line 153
    .line 154
    iget-object v8, v8, Lv3/l0;->q:Lv3/u0;

    .line 155
    .line 156
    if-eqz v8, :cond_2

    .line 157
    .line 158
    iput-object v12, v8, Lv3/u0;->m:Lv3/f0;

    .line 159
    .line 160
    :cond_2
    invoke-virtual {p0, v9, v0}, Lt3/m0;->h(Lt3/f0;Z)V

    .line 161
    .line 162
    .line 163
    iget-boolean v8, v9, Lt3/f0;->h:Z

    .line 164
    .line 165
    if-eqz v8, :cond_5

    .line 166
    .line 167
    move v7, v4

    .line 168
    goto :goto_3

    .line 169
    :catchall_0
    move-exception p0

    .line 170
    goto :goto_4

    .line 171
    :cond_3
    iget-object v11, p0, Lt3/m0;->d:Lv3/h0;

    .line 172
    .line 173
    iput-boolean v4, v11, Lv3/h0;->s:Z

    .line 174
    .line 175
    iget-object v12, p0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 176
    .line 177
    invoke-virtual {v12, v8}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    iget-object v8, v9, Lt3/f0;->c:Ll2/a0;

    .line 181
    .line 182
    if-eqz v8, :cond_4

    .line 183
    .line 184
    invoke-virtual {v8}, Ll2/a0;->dispose()V

    .line 185
    .line 186
    .line 187
    :cond_4
    iget-object v8, p0, Lt3/m0;->d:Lv3/h0;

    .line 188
    .line 189
    invoke-virtual {v8, v3, v4}, Lv3/h0;->T(II)V

    .line 190
    .line 191
    .line 192
    iput-boolean v0, v11, Lv3/h0;->s:Z

    .line 193
    .line 194
    :cond_5
    :goto_3
    iget-object v8, p0, Lt3/m0;->j:Landroidx/collection/q0;

    .line 195
    .line 196
    invoke-virtual {v8, v10}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 197
    .line 198
    .line 199
    add-int/lit8 v3, v3, -0x1

    .line 200
    .line 201
    goto :goto_2

    .line 202
    :goto_4
    invoke-static {v2, v6, v5}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 203
    .line 204
    .line 205
    throw p0

    .line 206
    :cond_6
    invoke-static {v2, v6, v5}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 207
    .line 208
    .line 209
    goto :goto_5

    .line 210
    :cond_7
    move v7, v0

    .line 211
    :goto_5
    if-eqz v7, :cond_9

    .line 212
    .line 213
    sget-object p1, Lv2/l;->c:Ljava/lang/Object;

    .line 214
    .line 215
    monitor-enter p1

    .line 216
    :try_start_1
    sget-object v1, Lv2/l;->j:Lv2/a;

    .line 217
    .line 218
    iget-object v1, v1, Lv2/b;->h:Landroidx/collection/r0;

    .line 219
    .line 220
    if-eqz v1, :cond_8

    .line 221
    .line 222
    invoke-virtual {v1}, Landroidx/collection/r0;->h()Z

    .line 223
    .line 224
    .line 225
    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 226
    if-ne v1, v4, :cond_8

    .line 227
    .line 228
    move v0, v4

    .line 229
    :cond_8
    monitor-exit p1

    .line 230
    if-eqz v0, :cond_9

    .line 231
    .line 232
    invoke-static {}, Lv2/l;->a()V

    .line 233
    .line 234
    .line 235
    goto :goto_6

    .line 236
    :catchall_1
    move-exception p0

    .line 237
    monitor-exit p1

    .line 238
    throw p0

    .line 239
    :cond_9
    :goto_6
    invoke-virtual {p0}, Lt3/m0;->d()V

    .line 240
    .line 241
    .line 242
    return-void
.end method

.method public final d()V
    .locals 4

    .line 1
    iget-object v0, p0, Lt3/m0;->d:Lv3/h0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lv3/h0;->p()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroidx/collection/j0;

    .line 8
    .line 9
    iget-object v0, v0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Ln2/b;

    .line 12
    .line 13
    iget v0, v0, Ln2/b;->f:I

    .line 14
    .line 15
    iget-object v1, p0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 16
    .line 17
    iget v2, v1, Landroidx/collection/q0;->e:I

    .line 18
    .line 19
    if-ne v2, v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v3, "Inconsistency between the count of nodes tracked by the state ("

    .line 25
    .line 26
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget v1, v1, Landroidx/collection/q0;->e:I

    .line 30
    .line 31
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v1, ") and the children count on the SubcomposeLayout ("

    .line 35
    .line 36
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, "). Are you trying to use the state of the disposed SubcomposeLayout?"

    .line 43
    .line 44
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-static {v1}, Ls3/a;->a(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :goto_0
    iget v1, p0, Lt3/m0;->q:I

    .line 55
    .line 56
    sub-int v1, v0, v1

    .line 57
    .line 58
    iget v2, p0, Lt3/m0;->r:I

    .line 59
    .line 60
    sub-int/2addr v1, v2

    .line 61
    if-ltz v1, :cond_1

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_1
    const-string v1, "Incorrect state. Total children "

    .line 65
    .line 66
    const-string v2, ". Reusable children "

    .line 67
    .line 68
    invoke-static {v1, v0, v2}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    iget v1, p0, Lt3/m0;->q:I

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v1, ". Precomposed children "

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    iget v1, p0, Lt3/m0;->r:I

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    :goto_1
    iget-object v0, p0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 95
    .line 96
    iget v1, v0, Landroidx/collection/q0;->e:I

    .line 97
    .line 98
    iget v2, p0, Lt3/m0;->r:I

    .line 99
    .line 100
    if-ne v1, v2, :cond_2

    .line 101
    .line 102
    return-void

    .line 103
    :cond_2
    new-instance v1, Ljava/lang/StringBuilder;

    .line 104
    .line 105
    const-string v2, "Incorrect state. Precomposed children "

    .line 106
    .line 107
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    iget p0, p0, Lt3/m0;->r:I

    .line 111
    .line 112
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const-string p0, ". Map size "

    .line 116
    .line 117
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    iget p0, v0, Landroidx/collection/q0;->e:I

    .line 121
    .line 122
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    invoke-static {p0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    return-void
.end method

.method public final e()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lt3/m0;->g(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final f()V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    iget-object v2, v0, Lt3/m0;->d:Lv3/h0;

    .line 5
    .line 6
    iput-boolean v1, v2, Lv3/h0;->s:Z

    .line 7
    .line 8
    iget-object v1, v0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 9
    .line 10
    iget-object v3, v1, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 11
    .line 12
    iget-object v4, v1, Landroidx/collection/q0;->a:[J

    .line 13
    .line 14
    array-length v5, v4

    .line 15
    add-int/lit8 v5, v5, -0x2

    .line 16
    .line 17
    const/4 v6, 0x0

    .line 18
    if-ltz v5, :cond_3

    .line 19
    .line 20
    move v7, v6

    .line 21
    :goto_0
    aget-wide v8, v4, v7

    .line 22
    .line 23
    not-long v10, v8

    .line 24
    const/4 v12, 0x7

    .line 25
    shl-long/2addr v10, v12

    .line 26
    and-long/2addr v10, v8

    .line 27
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    and-long/2addr v10, v12

    .line 33
    cmp-long v10, v10, v12

    .line 34
    .line 35
    if-eqz v10, :cond_2

    .line 36
    .line 37
    sub-int v10, v7, v5

    .line 38
    .line 39
    not-int v10, v10

    .line 40
    ushr-int/lit8 v10, v10, 0x1f

    .line 41
    .line 42
    const/16 v11, 0x8

    .line 43
    .line 44
    rsub-int/lit8 v10, v10, 0x8

    .line 45
    .line 46
    move v12, v6

    .line 47
    :goto_1
    if-ge v12, v10, :cond_1

    .line 48
    .line 49
    const-wide/16 v13, 0xff

    .line 50
    .line 51
    and-long/2addr v13, v8

    .line 52
    const-wide/16 v15, 0x80

    .line 53
    .line 54
    cmp-long v13, v13, v15

    .line 55
    .line 56
    if-gez v13, :cond_0

    .line 57
    .line 58
    shl-int/lit8 v13, v7, 0x3

    .line 59
    .line 60
    add-int/2addr v13, v12

    .line 61
    aget-object v13, v3, v13

    .line 62
    .line 63
    check-cast v13, Lt3/f0;

    .line 64
    .line 65
    iget-object v13, v13, Lt3/f0;->c:Ll2/a0;

    .line 66
    .line 67
    if-eqz v13, :cond_0

    .line 68
    .line 69
    invoke-virtual {v13}, Ll2/a0;->dispose()V

    .line 70
    .line 71
    .line 72
    :cond_0
    shr-long/2addr v8, v11

    .line 73
    add-int/lit8 v12, v12, 0x1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    if-ne v10, v11, :cond_3

    .line 77
    .line 78
    :cond_2
    if-eq v7, v5, :cond_3

    .line 79
    .line 80
    add-int/lit8 v7, v7, 0x1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_3
    invoke-virtual {v2}, Lv3/h0;->S()V

    .line 84
    .line 85
    .line 86
    iput-boolean v6, v2, Lv3/h0;->s:Z

    .line 87
    .line 88
    invoke-virtual {v1}, Landroidx/collection/q0;->a()V

    .line 89
    .line 90
    .line 91
    iget-object v1, v0, Lt3/m0;->j:Landroidx/collection/q0;

    .line 92
    .line 93
    invoke-virtual {v1}, Landroidx/collection/q0;->a()V

    .line 94
    .line 95
    .line 96
    iput v6, v0, Lt3/m0;->r:I

    .line 97
    .line 98
    iput v6, v0, Lt3/m0;->q:I

    .line 99
    .line 100
    iget-object v1, v0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 101
    .line 102
    invoke-virtual {v1}, Landroidx/collection/q0;->a()V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Lt3/m0;->d()V

    .line 106
    .line 107
    .line 108
    return-void
.end method

.method public final g(Z)V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lt3/m0;->r:I

    .line 3
    .line 4
    iget-object v1, p0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 5
    .line 6
    invoke-virtual {v1}, Landroidx/collection/q0;->a()V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lt3/m0;->d:Lv3/h0;

    .line 10
    .line 11
    invoke-virtual {v1}, Lv3/h0;->p()Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Landroidx/collection/j0;

    .line 17
    .line 18
    iget-object v2, v2, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v2, Ln2/b;

    .line 21
    .line 22
    iget v2, v2, Ln2/b;->f:I

    .line 23
    .line 24
    iget v3, p0, Lt3/m0;->q:I

    .line 25
    .line 26
    if-eq v3, v2, :cond_4

    .line 27
    .line 28
    iput v2, p0, Lt3/m0;->q:I

    .line 29
    .line 30
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    if-eqz v3, :cond_0

    .line 35
    .line 36
    invoke-virtual {v3}, Lv2/f;->e()Lay0/k;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v4, 0x0

    .line 42
    :goto_0
    invoke-static {v3}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    :goto_1
    if-ge v0, v2, :cond_3

    .line 47
    .line 48
    :try_start_0
    move-object v6, v1

    .line 49
    check-cast v6, Landroidx/collection/j0;

    .line 50
    .line 51
    invoke-virtual {v6, v0}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v6

    .line 55
    check-cast v6, Lv3/h0;

    .line 56
    .line 57
    iget-object v7, p0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 58
    .line 59
    invoke-virtual {v7, v6}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v7

    .line 63
    check-cast v7, Lt3/f0;

    .line 64
    .line 65
    if-eqz v7, :cond_2

    .line 66
    .line 67
    iget-object v8, v7, Lt3/f0;->g:Ll2/j1;

    .line 68
    .line 69
    invoke-virtual {v8}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v8

    .line 73
    check-cast v8, Ljava/lang/Boolean;

    .line 74
    .line 75
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 76
    .line 77
    .line 78
    move-result v8

    .line 79
    if-eqz v8, :cond_2

    .line 80
    .line 81
    iget-object v6, v6, Lv3/h0;->I:Lv3/l0;

    .line 82
    .line 83
    iget-object v8, v6, Lv3/l0;->p:Lv3/y0;

    .line 84
    .line 85
    sget-object v9, Lv3/f0;->f:Lv3/f0;

    .line 86
    .line 87
    iput-object v9, v8, Lv3/y0;->o:Lv3/f0;

    .line 88
    .line 89
    iget-object v6, v6, Lv3/l0;->q:Lv3/u0;

    .line 90
    .line 91
    if-eqz v6, :cond_1

    .line 92
    .line 93
    iput-object v9, v6, Lv3/u0;->m:Lv3/f0;

    .line 94
    .line 95
    :cond_1
    invoke-virtual {p0, v7, p1}, Lt3/m0;->h(Lt3/f0;Z)V

    .line 96
    .line 97
    .line 98
    sget-object v6, Lt3/k1;->a:Lt3/x0;

    .line 99
    .line 100
    iput-object v6, v7, Lt3/f0;->a:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :catchall_0
    move-exception p0

    .line 104
    goto :goto_3

    .line 105
    :cond_2
    :goto_2
    add-int/lit8 v0, v0, 0x1

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :goto_3
    invoke-static {v3, v5, v4}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_3
    invoke-static {v3, v5, v4}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 113
    .line 114
    .line 115
    iget-object p1, p0, Lt3/m0;->j:Landroidx/collection/q0;

    .line 116
    .line 117
    invoke-virtual {p1}, Landroidx/collection/q0;->a()V

    .line 118
    .line 119
    .line 120
    :cond_4
    invoke-virtual {p0}, Lt3/m0;->d()V

    .line 121
    .line 122
    .line 123
    return-void
.end method

.method public final h(Lt3/f0;Z)V
    .locals 2

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    iget-boolean v0, p1, Lt3/f0;->h:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p1, Lt3/f0;->g:Ll2/j1;

    .line 8
    .line 9
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 16
    .line 17
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p1, Lt3/f0;->g:Ll2/j1;

    .line 22
    .line 23
    :goto_0
    iget-object v0, p1, Lt3/f0;->f:Ll2/m1;

    .line 24
    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    invoke-static {p1}, Lt3/m0;->b(Lt3/f0;)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    if-eqz p2, :cond_2

    .line 32
    .line 33
    iget-object p0, p1, Lt3/f0;->c:Ll2/a0;

    .line 34
    .line 35
    if-eqz p0, :cond_5

    .line 36
    .line 37
    invoke-virtual {p0}, Ll2/a0;->l()V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_2
    iget-object p0, p0, Lt3/m0;->d:Lv3/h0;

    .line 42
    .line 43
    invoke-static {p0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lw3/t;

    .line 48
    .line 49
    invoke-virtual {p0}, Lw3/t;->getOutOfFrameExecutor()Lv3/m1;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    if-eqz p0, :cond_4

    .line 54
    .line 55
    new-instance p2, La7/j;

    .line 56
    .line 57
    const/16 v0, 0x13

    .line 58
    .line 59
    invoke-direct {p2, p1, v0}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    check-cast p0, Lw3/t;

    .line 63
    .line 64
    invoke-virtual {p0}, Landroid/view/View;->getHandler()Landroid/os/Handler;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-eqz p0, :cond_3

    .line 69
    .line 70
    new-instance p1, Lm8/o;

    .line 71
    .line 72
    const/16 v0, 0x16

    .line 73
    .line 74
    invoke-direct {p1, p2, v0}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0, p1}, Landroid/os/Handler;->postAtFrontOfQueue(Ljava/lang/Runnable;)Z

    .line 78
    .line 79
    .line 80
    return-void

    .line 81
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 82
    .line 83
    const-string p1, "schedule is called when outOfFrameExecutor is not available (view is detached)"

    .line 84
    .line 85
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_4
    iget-boolean p0, p1, Lt3/f0;->h:Z

    .line 90
    .line 91
    if-nez p0, :cond_5

    .line 92
    .line 93
    iget-object p0, p1, Lt3/f0;->c:Ll2/a0;

    .line 94
    .line 95
    if-eqz p0, :cond_5

    .line 96
    .line 97
    invoke-virtual {p0}, Ll2/a0;->l()V

    .line 98
    .line 99
    .line 100
    :cond_5
    return-void
.end method

.method public final i(Lv3/h0;Ljava/lang/Object;ZLay0/n;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    new-instance v1, Lt3/f0;

    .line 11
    .line 12
    sget-object v3, Lt3/i;->a:Lt2/b;

    .line 13
    .line 14
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object p2, v1, Lt3/f0;->a:Ljava/lang/Object;

    .line 18
    .line 19
    iput-object v3, v1, Lt3/f0;->b:Lay0/n;

    .line 20
    .line 21
    iput-object v2, v1, Lt3/f0;->c:Ll2/a0;

    .line 22
    .line 23
    sget-object p2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 24
    .line 25
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    iput-object p2, v1, Lt3/f0;->g:Ll2/j1;

    .line 30
    .line 31
    invoke-virtual {v0, p1, v1}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    :cond_0
    check-cast v1, Lt3/f0;

    .line 35
    .line 36
    iget-object p2, v1, Lt3/f0;->b:Lay0/n;

    .line 37
    .line 38
    const/4 v0, 0x0

    .line 39
    const/4 v3, 0x1

    .line 40
    if-eq p2, p4, :cond_1

    .line 41
    .line 42
    move p2, v3

    .line 43
    goto :goto_0

    .line 44
    :cond_1
    move p2, v0

    .line 45
    :goto_0
    iget-object v4, v1, Lt3/f0;->f:Ll2/m1;

    .line 46
    .line 47
    if-eqz v4, :cond_6

    .line 48
    .line 49
    if-eqz p2, :cond_2

    .line 50
    .line 51
    invoke-static {v1}, Lt3/m0;->b(Lt3/f0;)V

    .line 52
    .line 53
    .line 54
    goto :goto_4

    .line 55
    :cond_2
    if-eqz p3, :cond_3

    .line 56
    .line 57
    goto :goto_7

    .line 58
    :cond_3
    iget-object v4, v1, Lt3/f0;->f:Ll2/m1;

    .line 59
    .line 60
    if-eqz v4, :cond_6

    .line 61
    .line 62
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    if-eqz v5, :cond_4

    .line 67
    .line 68
    invoke-virtual {v5}, Lv2/f;->e()Lay0/k;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    goto :goto_1

    .line 73
    :cond_4
    move-object v6, v2

    .line 74
    :goto_1
    invoke-static {v5}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 75
    .line 76
    .line 77
    move-result-object v7

    .line 78
    :try_start_0
    iget-object v8, p0, Lt3/m0;->d:Lv3/h0;

    .line 79
    .line 80
    iput-boolean v3, v8, Lv3/h0;->s:Z

    .line 81
    .line 82
    :goto_2
    invoke-virtual {v4}, Ll2/m1;->c()Z

    .line 83
    .line 84
    .line 85
    move-result v9

    .line 86
    if-nez v9, :cond_5

    .line 87
    .line 88
    new-instance v9, Lt0/c;

    .line 89
    .line 90
    invoke-direct {v9, v3}, Lt0/c;-><init>(I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v4, v9}, Ll2/m1;->f(Lt0/c;)Z

    .line 94
    .line 95
    .line 96
    goto :goto_2

    .line 97
    :catchall_0
    move-exception p0

    .line 98
    goto :goto_3

    .line 99
    :cond_5
    invoke-virtual {v4}, Ll2/m1;->a()V

    .line 100
    .line 101
    .line 102
    iput-object v2, v1, Lt3/f0;->f:Ll2/m1;

    .line 103
    .line 104
    iput-boolean v0, v8, Lv3/h0;->s:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 105
    .line 106
    invoke-static {v5, v7, v6}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 107
    .line 108
    .line 109
    goto :goto_4

    .line 110
    :goto_3
    invoke-static {v5, v7, v6}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 111
    .line 112
    .line 113
    throw p0

    .line 114
    :cond_6
    :goto_4
    iget-object v4, v1, Lt3/f0;->c:Ll2/a0;

    .line 115
    .line 116
    if-eqz v4, :cond_8

    .line 117
    .line 118
    iget-object v5, v4, Ll2/a0;->g:Ljava/lang/Object;

    .line 119
    .line 120
    monitor-enter v5

    .line 121
    :try_start_1
    iget-object v4, v4, Ll2/a0;->q:Landroidx/collection/q0;

    .line 122
    .line 123
    iget v4, v4, Landroidx/collection/q0;->e:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 124
    .line 125
    if-lez v4, :cond_7

    .line 126
    .line 127
    move v4, v3

    .line 128
    goto :goto_5

    .line 129
    :cond_7
    move v4, v0

    .line 130
    :goto_5
    monitor-exit v5

    .line 131
    goto :goto_6

    .line 132
    :catchall_1
    move-exception p0

    .line 133
    monitor-exit v5

    .line 134
    throw p0

    .line 135
    :cond_8
    move v4, v3

    .line 136
    :goto_6
    if-nez p2, :cond_a

    .line 137
    .line 138
    if-nez v4, :cond_a

    .line 139
    .line 140
    iget-boolean p2, v1, Lt3/f0;->d:Z

    .line 141
    .line 142
    if-eqz p2, :cond_9

    .line 143
    .line 144
    goto :goto_8

    .line 145
    :cond_9
    :goto_7
    return-void

    .line 146
    :cond_a
    :goto_8
    iput-object p4, v1, Lt3/f0;->b:Lay0/n;

    .line 147
    .line 148
    iget-object p2, v1, Lt3/f0;->f:Ll2/m1;

    .line 149
    .line 150
    if-nez p2, :cond_b

    .line 151
    .line 152
    goto :goto_9

    .line 153
    :cond_b
    const-string p2, "new subcompose call while paused composition is still active"

    .line 154
    .line 155
    invoke-static {p2}, Ls3/a;->a(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    :goto_9
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 159
    .line 160
    .line 161
    move-result-object p2

    .line 162
    if-eqz p2, :cond_c

    .line 163
    .line 164
    invoke-virtual {p2}, Lv2/f;->e()Lay0/k;

    .line 165
    .line 166
    .line 167
    move-result-object v2

    .line 168
    :cond_c
    invoke-static {p2}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 169
    .line 170
    .line 171
    move-result-object p4

    .line 172
    :try_start_2
    iget-object v4, p0, Lt3/m0;->d:Lv3/h0;

    .line 173
    .line 174
    iput-boolean v3, v4, Lv3/h0;->s:Z

    .line 175
    .line 176
    iget-object v5, v1, Lt3/f0;->c:Ll2/a0;

    .line 177
    .line 178
    iget-object v6, p0, Lt3/m0;->e:Ll2/x;

    .line 179
    .line 180
    if-eqz v6, :cond_15

    .line 181
    .line 182
    if-eqz v5, :cond_e

    .line 183
    .line 184
    iget v7, v5, Ll2/a0;->z:I

    .line 185
    .line 186
    const/4 v8, 0x3

    .line 187
    if-ne v7, v8, :cond_d

    .line 188
    .line 189
    move v7, v3

    .line 190
    goto :goto_a

    .line 191
    :cond_d
    move v7, v0

    .line 192
    :goto_a
    if-eqz v7, :cond_10

    .line 193
    .line 194
    goto :goto_b

    .line 195
    :catchall_2
    move-exception p0

    .line 196
    goto/16 :goto_10

    .line 197
    .line 198
    :cond_e
    :goto_b
    if-eqz p3, :cond_f

    .line 199
    .line 200
    sget-object v5, Lw3/t2;->a:Landroid/view/ViewGroup$LayoutParams;

    .line 201
    .line 202
    new-instance v5, Lv3/d2;

    .line 203
    .line 204
    invoke-direct {v5, p1}, Leb/j0;-><init>(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    new-instance p1, Ll2/a0;

    .line 208
    .line 209
    invoke-direct {p1, v6, v5}, Ll2/a0;-><init>(Ll2/x;Leb/j0;)V

    .line 210
    .line 211
    .line 212
    :goto_c
    move-object v5, p1

    .line 213
    goto :goto_d

    .line 214
    :cond_f
    sget-object v5, Lw3/t2;->a:Landroid/view/ViewGroup$LayoutParams;

    .line 215
    .line 216
    new-instance v5, Lv3/d2;

    .line 217
    .line 218
    invoke-direct {v5, p1}, Leb/j0;-><init>(Ljava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    new-instance p1, Ll2/a0;

    .line 222
    .line 223
    invoke-direct {p1, v6, v5}, Ll2/a0;-><init>(Ll2/x;Leb/j0;)V

    .line 224
    .line 225
    .line 226
    goto :goto_c

    .line 227
    :cond_10
    :goto_d
    iput-object v5, v1, Lt3/f0;->c:Ll2/a0;

    .line 228
    .line 229
    iget-object p1, v1, Lt3/f0;->b:Lay0/n;

    .line 230
    .line 231
    iget-object p0, p0, Lt3/m0;->d:Lv3/h0;

    .line 232
    .line 233
    invoke-static {p0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    check-cast p0, Lw3/t;

    .line 238
    .line 239
    invoke-virtual {p0}, Lw3/t;->getOutOfFrameExecutor()Lv3/m1;

    .line 240
    .line 241
    .line 242
    move-result-object p0

    .line 243
    if-eqz p0, :cond_11

    .line 244
    .line 245
    iput-boolean v0, v1, Lt3/f0;->h:Z

    .line 246
    .line 247
    goto :goto_e

    .line 248
    :cond_11
    iput-boolean v3, v1, Lt3/f0;->h:Z

    .line 249
    .line 250
    new-instance p0, Lkn/i0;

    .line 251
    .line 252
    invoke-direct {p0, v3, v1, p1}, Lkn/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    new-instance p1, Lt2/b;

    .line 256
    .line 257
    const v6, 0x5ad8c84e

    .line 258
    .line 259
    .line 260
    invoke-direct {p1, p0, v3, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 261
    .line 262
    .line 263
    :goto_e
    if-eqz p3, :cond_13

    .line 264
    .line 265
    iget-boolean p0, v1, Lt3/f0;->e:Z

    .line 266
    .line 267
    if-eqz p0, :cond_12

    .line 268
    .line 269
    invoke-virtual {v5}, Ll2/a0;->i()Z

    .line 270
    .line 271
    .line 272
    invoke-virtual {v5}, Ll2/a0;->p()V

    .line 273
    .line 274
    .line 275
    invoke-virtual {v5, v3, p1}, Ll2/a0;->k(ZLay0/n;)Ll2/m1;

    .line 276
    .line 277
    .line 278
    move-result-object p0

    .line 279
    iput-object p0, v1, Lt3/f0;->f:Ll2/m1;

    .line 280
    .line 281
    goto :goto_f

    .line 282
    :cond_12
    invoke-virtual {v5}, Ll2/a0;->i()Z

    .line 283
    .line 284
    .line 285
    move-result p0

    .line 286
    invoke-virtual {v5, p0, p1}, Ll2/a0;->k(ZLay0/n;)Ll2/m1;

    .line 287
    .line 288
    .line 289
    move-result-object p0

    .line 290
    iput-object p0, v1, Lt3/f0;->f:Ll2/m1;

    .line 291
    .line 292
    goto :goto_f

    .line 293
    :cond_13
    iget-boolean p0, v1, Lt3/f0;->e:Z

    .line 294
    .line 295
    if-eqz p0, :cond_14

    .line 296
    .line 297
    invoke-virtual {v5}, Ll2/a0;->i()Z

    .line 298
    .line 299
    .line 300
    invoke-virtual {v5}, Ll2/a0;->p()V

    .line 301
    .line 302
    .line 303
    iget-object p0, v5, Ll2/a0;->y:Ll2/t;

    .line 304
    .line 305
    const/16 p3, 0x64

    .line 306
    .line 307
    iput p3, p0, Ll2/t;->z:I

    .line 308
    .line 309
    iput-boolean v3, p0, Ll2/t;->y:Z

    .line 310
    .line 311
    iput-object p1, v5, Ll2/a0;->A:Lay0/n;

    .line 312
    .line 313
    iget-object p3, v5, Ll2/a0;->d:Ll2/x;

    .line 314
    .line 315
    invoke-virtual {p3, v5, p1}, Ll2/x;->a(Ll2/a0;Lay0/n;)V

    .line 316
    .line 317
    .line 318
    invoke-virtual {p0}, Ll2/t;->t()V

    .line 319
    .line 320
    .line 321
    goto :goto_f

    .line 322
    :cond_14
    invoke-virtual {v5, p1}, Ll2/a0;->A(Lay0/n;)V

    .line 323
    .line 324
    .line 325
    :goto_f
    iput-boolean v0, v1, Lt3/f0;->e:Z

    .line 326
    .line 327
    iput-boolean v0, v4, Lv3/h0;->s:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 328
    .line 329
    invoke-static {p2, p4, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 330
    .line 331
    .line 332
    iput-boolean v0, v1, Lt3/f0;->d:Z

    .line 333
    .line 334
    return-void

    .line 335
    :cond_15
    :try_start_3
    const-string p0, "parent composition reference not set"

    .line 336
    .line 337
    invoke-static {p0}, Ls3/a;->c(Ljava/lang/String;)Ljava/lang/Void;

    .line 338
    .line 339
    .line 340
    new-instance p0, La8/r0;

    .line 341
    .line 342
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 343
    .line 344
    .line 345
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 346
    :goto_10
    invoke-static {p2, p4, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 347
    .line 348
    .line 349
    throw p0
.end method

.method public final j(Ljava/lang/Object;)Lv3/h0;
    .locals 11

    .line 1
    iget v0, p0, Lt3/m0;->q:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_5

    .line 6
    .line 7
    :cond_0
    iget-object v0, p0, Lt3/m0;->d:Lv3/h0;

    .line 8
    .line 9
    invoke-virtual {v0}, Lv3/h0;->p()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Landroidx/collection/j0;

    .line 14
    .line 15
    iget-object v2, v1, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v2, Ln2/b;

    .line 18
    .line 19
    iget v2, v2, Ln2/b;->f:I

    .line 20
    .line 21
    iget v3, p0, Lt3/m0;->r:I

    .line 22
    .line 23
    sub-int/2addr v2, v3

    .line 24
    iget v3, p0, Lt3/m0;->q:I

    .line 25
    .line 26
    sub-int v3, v2, v3

    .line 27
    .line 28
    const/4 v4, 0x1

    .line 29
    sub-int/2addr v2, v4

    .line 30
    move v5, v2

    .line 31
    :goto_0
    iget-object v6, p0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 32
    .line 33
    const/4 v7, -0x1

    .line 34
    if-lt v5, v3, :cond_2

    .line 35
    .line 36
    invoke-virtual {v1, v5}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v8

    .line 40
    check-cast v8, Lv3/h0;

    .line 41
    .line 42
    invoke-virtual {v6, v8}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v8

    .line 46
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    check-cast v8, Lt3/f0;

    .line 50
    .line 51
    iget-object v8, v8, Lt3/f0;->a:Ljava/lang/Object;

    .line 52
    .line 53
    invoke-static {v8, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v8

    .line 57
    if-eqz v8, :cond_1

    .line 58
    .line 59
    move v8, v5

    .line 60
    goto :goto_1

    .line 61
    :cond_1
    add-int/lit8 v5, v5, -0x1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_2
    move v8, v7

    .line 65
    :goto_1
    if-ne v8, v7, :cond_6

    .line 66
    .line 67
    :goto_2
    if-lt v2, v3, :cond_5

    .line 68
    .line 69
    invoke-virtual {v1, v2}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    check-cast v5, Lv3/h0;

    .line 74
    .line 75
    invoke-virtual {v6, v5}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v5

    .line 79
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    check-cast v5, Lt3/f0;

    .line 83
    .line 84
    iget-object v9, v5, Lt3/f0;->a:Ljava/lang/Object;

    .line 85
    .line 86
    sget-object v10, Lt3/k1;->a:Lt3/x0;

    .line 87
    .line 88
    if-eq v9, v10, :cond_4

    .line 89
    .line 90
    iget-object v10, p0, Lt3/m0;->f:Lt3/q1;

    .line 91
    .line 92
    invoke-interface {v10, p1, v9}, Lt3/q1;->s(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v9

    .line 96
    if-eqz v9, :cond_3

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_3
    add-int/lit8 v2, v2, -0x1

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_4
    :goto_3
    iput-object p1, v5, Lt3/f0;->a:Ljava/lang/Object;

    .line 103
    .line 104
    move v5, v2

    .line 105
    move v8, v5

    .line 106
    goto :goto_4

    .line 107
    :cond_5
    move v5, v2

    .line 108
    :cond_6
    :goto_4
    if-ne v8, v7, :cond_7

    .line 109
    .line 110
    :goto_5
    const/4 p0, 0x0

    .line 111
    return-object p0

    .line 112
    :cond_7
    if-eq v5, v3, :cond_8

    .line 113
    .line 114
    iput-boolean v4, v0, Lv3/h0;->s:Z

    .line 115
    .line 116
    invoke-virtual {v0, v5, v3, v4}, Lv3/h0;->M(III)V

    .line 117
    .line 118
    .line 119
    const/4 p1, 0x0

    .line 120
    iput-boolean p1, v0, Lv3/h0;->s:Z

    .line 121
    .line 122
    :cond_8
    iget p1, p0, Lt3/m0;->q:I

    .line 123
    .line 124
    add-int/2addr p1, v7

    .line 125
    iput p1, p0, Lt3/m0;->q:I

    .line 126
    .line 127
    invoke-virtual {v1, v3}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    check-cast p0, Lv3/h0;

    .line 132
    .line 133
    invoke-virtual {v6, p0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    check-cast p1, Lt3/f0;

    .line 141
    .line 142
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 143
    .line 144
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    iput-object v0, p1, Lt3/f0;->g:Ll2/j1;

    .line 149
    .line 150
    iput-boolean v4, p1, Lt3/f0;->e:Z

    .line 151
    .line 152
    iput-boolean v4, p1, Lt3/f0;->d:Z

    .line 153
    .line 154
    return-object p0
.end method
