.class public final Lb0/k1;
.super Lb0/z1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final w:Lb0/i1;

.field public static final x:Lj0/c;


# instance fields
.field public p:Lb0/j1;

.field public q:Ljava/util/concurrent/Executor;

.field public r:Lh0/v1;

.field public s:Lb0/u1;

.field public t:Lp0/k;

.field public u:Lb0/x1;

.field public v:Lh0/w1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lb0/i1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lb0/k1;->w:Lb0/i1;

    .line 7
    .line 8
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Lb0/k1;->x:Lj0/c;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final A(Landroid/graphics/Rect;)V
    .locals 3

    .line 1
    iput-object p1, p0, Lb0/z1;->j:Landroid/graphics/Rect;

    .line 2
    .line 3
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iget-object v0, p0, Lb0/k1;->t:Lp0/k;

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lb0/z1;->m(Lh0/b0;)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-virtual {p0, p1, v1}, Lb0/z1;->h(Lh0/b0;Z)I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    iget-object p0, p0, Lb0/z1;->g:Lh0/o2;

    .line 22
    .line 23
    check-cast p0, Lh0/a1;

    .line 24
    .line 25
    sget-object v1, Lh0/a1;->H0:Lh0/g;

    .line 26
    .line 27
    const/4 v2, -0x1

    .line 28
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-interface {p0, v1, v2}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    new-instance v1, Lp0/i;

    .line 43
    .line 44
    invoke-direct {v1, v0, p1, p0}, Lp0/i;-><init>(Lp0/k;II)V

    .line 45
    .line 46
    .line 47
    invoke-static {v1}, Llp/k1;->d(Ljava/lang/Runnable;)V

    .line 48
    .line 49
    .line 50
    :cond_0
    return-void
.end method

.method public final D()V
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/k1;->v:Lh0/w1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Lh0/w1;->b()V

    .line 7
    .line 8
    .line 9
    iput-object v1, p0, Lb0/k1;->v:Lh0/w1;

    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lb0/k1;->s:Lb0/u1;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0}, Lh0/t0;->a()V

    .line 16
    .line 17
    .line 18
    iput-object v1, p0, Lb0/k1;->s:Lb0/u1;

    .line 19
    .line 20
    :cond_1
    iget-object v0, p0, Lb0/k1;->t:Lp0/k;

    .line 21
    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    invoke-virtual {v0}, Lp0/k;->b()V

    .line 25
    .line 26
    .line 27
    iput-object v1, p0, Lb0/k1;->t:Lp0/k;

    .line 28
    .line 29
    :cond_2
    iget-object v0, p0, Lb0/k1;->u:Lb0/x1;

    .line 30
    .line 31
    if-eqz v0, :cond_3

    .line 32
    .line 33
    iget-object v2, v0, Lb0/x1;->a:Ljava/lang/Object;

    .line 34
    .line 35
    monitor-enter v2

    .line 36
    :try_start_0
    iput-object v1, v0, Lb0/x1;->m:Lb0/w1;

    .line 37
    .line 38
    iput-object v1, v0, Lb0/x1;->n:Ljava/util/concurrent/Executor;

    .line 39
    .line 40
    monitor-exit v2

    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception p0

    .line 43
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    throw p0

    .line 45
    :cond_3
    :goto_0
    iput-object v1, p0, Lb0/k1;->u:Lb0/x1;

    .line 46
    .line 47
    return-void
.end method

.method public final E(Lb0/j1;)V
    .locals 1

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    iput-object v0, p0, Lb0/k1;->p:Lb0/j1;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    iput p1, p0, Lb0/z1;->c:I

    .line 11
    .line 12
    invoke-virtual {p0}, Lb0/z1;->q()V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    iput-object p1, p0, Lb0/k1;->p:Lb0/j1;

    .line 17
    .line 18
    sget-object p1, Lb0/k1;->x:Lj0/c;

    .line 19
    .line 20
    iput-object p1, p0, Lb0/k1;->q:Ljava/util/concurrent/Executor;

    .line 21
    .line 22
    iget-object p1, p0, Lb0/z1;->h:Lh0/k;

    .line 23
    .line 24
    if-eqz p1, :cond_1

    .line 25
    .line 26
    iget-object v0, p1, Lh0/k;->a:Landroid/util/Size;

    .line 27
    .line 28
    :cond_1
    if-eqz v0, :cond_2

    .line 29
    .line 30
    iget-object v0, p0, Lb0/z1;->g:Lh0/o2;

    .line 31
    .line 32
    check-cast v0, Lh0/o1;

    .line 33
    .line 34
    invoke-virtual {p0, v0, p1}, Lb0/k1;->F(Lh0/o1;Lh0/k;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0}, Lb0/z1;->p()V

    .line 38
    .line 39
    .line 40
    :cond_2
    invoke-virtual {p0}, Lb0/z1;->o()V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public final F(Lh0/o1;Lh0/k;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v4, p2

    .line 4
    .line 5
    const/4 v1, -0x1

    .line 6
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 7
    .line 8
    .line 9
    move-result-object v11

    .line 10
    invoke-static {}, Llp/k1;->a()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Lb0/z1;->c()Lh0/b0;

    .line 14
    .line 15
    .line 16
    move-result-object v12

    .line 17
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Lb0/k1;->D()V

    .line 21
    .line 22
    .line 23
    iget-object v1, v0, Lb0/k1;->t:Lp0/k;

    .line 24
    .line 25
    const/4 v13, 0x0

    .line 26
    const/4 v14, 0x1

    .line 27
    if-nez v1, :cond_0

    .line 28
    .line 29
    move v1, v14

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move v1, v13

    .line 32
    :goto_0
    const/4 v2, 0x0

    .line 33
    invoke-static {v2, v1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 34
    .line 35
    .line 36
    new-instance v1, Lp0/k;

    .line 37
    .line 38
    iget-object v5, v0, Lb0/z1;->k:Landroid/graphics/Matrix;

    .line 39
    .line 40
    invoke-interface {v12}, Lh0/b0;->p()Z

    .line 41
    .line 42
    .line 43
    move-result v6

    .line 44
    iget-object v3, v4, Lh0/k;->a:Landroid/util/Size;

    .line 45
    .line 46
    iget-object v7, v0, Lb0/z1;->j:Landroid/graphics/Rect;

    .line 47
    .line 48
    if-eqz v7, :cond_1

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    if-eqz v3, :cond_2

    .line 52
    .line 53
    new-instance v2, Landroid/graphics/Rect;

    .line 54
    .line 55
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 56
    .line 57
    .line 58
    move-result v7

    .line 59
    invoke-virtual {v3}, Landroid/util/Size;->getHeight()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    invoke-direct {v2, v13, v13, v7, v3}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 64
    .line 65
    .line 66
    :cond_2
    move-object v7, v2

    .line 67
    :goto_1
    invoke-static {v7}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0, v12}, Lb0/z1;->m(Lh0/b0;)Z

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    invoke-virtual {v0, v12, v2}, Lb0/z1;->h(Lh0/b0;Z)I

    .line 75
    .line 76
    .line 77
    move-result v8

    .line 78
    iget-object v2, v0, Lb0/z1;->g:Lh0/o2;

    .line 79
    .line 80
    check-cast v2, Lh0/a1;

    .line 81
    .line 82
    sget-object v15, Lh0/a1;->H0:Lh0/g;

    .line 83
    .line 84
    invoke-interface {v2, v15, v11}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    check-cast v2, Ljava/lang/Integer;

    .line 89
    .line 90
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 91
    .line 92
    .line 93
    move-result v9

    .line 94
    invoke-interface {v12}, Lh0/b0;->p()Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-eqz v2, :cond_3

    .line 99
    .line 100
    invoke-virtual {v0, v12}, Lb0/z1;->m(Lh0/b0;)Z

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    if-eqz v2, :cond_3

    .line 105
    .line 106
    move v10, v14

    .line 107
    goto :goto_2

    .line 108
    :cond_3
    move v10, v13

    .line 109
    :goto_2
    const/4 v2, 0x1

    .line 110
    const/16 v3, 0x22

    .line 111
    .line 112
    invoke-direct/range {v1 .. v10}, Lp0/k;-><init>(IILh0/k;Landroid/graphics/Matrix;ZLandroid/graphics/Rect;IIZ)V

    .line 113
    .line 114
    .line 115
    iput-object v1, v0, Lb0/k1;->t:Lp0/k;

    .line 116
    .line 117
    new-instance v2, La0/d;

    .line 118
    .line 119
    const/16 v3, 0xa

    .line 120
    .line 121
    invoke-direct {v2, v0, v3}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 122
    .line 123
    .line 124
    invoke-static {}, Llp/k1;->a()V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v1}, Lp0/k;->a()V

    .line 128
    .line 129
    .line 130
    iget-object v1, v1, Lp0/k;->m:Ljava/util/HashSet;

    .line 131
    .line 132
    invoke-virtual {v1, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    iget-object v1, v0, Lb0/k1;->t:Lp0/k;

    .line 136
    .line 137
    invoke-virtual {v1, v12, v14}, Lp0/k;->c(Lh0/b0;Z)Lb0/x1;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    iput-object v1, v0, Lb0/k1;->u:Lb0/x1;

    .line 142
    .line 143
    iget-object v1, v1, Lb0/x1;->k:Lb0/u1;

    .line 144
    .line 145
    iput-object v1, v0, Lb0/k1;->s:Lb0/u1;

    .line 146
    .line 147
    iget-object v1, v0, Lb0/k1;->p:Lb0/j1;

    .line 148
    .line 149
    if-eqz v1, :cond_5

    .line 150
    .line 151
    invoke-virtual {v0}, Lb0/z1;->c()Lh0/b0;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    iget-object v2, v0, Lb0/k1;->t:Lp0/k;

    .line 156
    .line 157
    if-eqz v1, :cond_4

    .line 158
    .line 159
    if-eqz v2, :cond_4

    .line 160
    .line 161
    invoke-virtual {v0, v1}, Lb0/z1;->m(Lh0/b0;)Z

    .line 162
    .line 163
    .line 164
    move-result v3

    .line 165
    invoke-virtual {v0, v1, v3}, Lb0/z1;->h(Lh0/b0;Z)I

    .line 166
    .line 167
    .line 168
    move-result v1

    .line 169
    iget-object v3, v0, Lb0/z1;->g:Lh0/o2;

    .line 170
    .line 171
    check-cast v3, Lh0/a1;

    .line 172
    .line 173
    invoke-interface {v3, v15, v11}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    check-cast v3, Ljava/lang/Integer;

    .line 178
    .line 179
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 180
    .line 181
    .line 182
    move-result v3

    .line 183
    new-instance v5, Lp0/i;

    .line 184
    .line 185
    invoke-direct {v5, v2, v1, v3}, Lp0/i;-><init>(Lp0/k;II)V

    .line 186
    .line 187
    .line 188
    invoke-static {v5}, Llp/k1;->d(Ljava/lang/Runnable;)V

    .line 189
    .line 190
    .line 191
    :cond_4
    iget-object v1, v0, Lb0/k1;->p:Lb0/j1;

    .line 192
    .line 193
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 194
    .line 195
    .line 196
    iget-object v2, v0, Lb0/k1;->u:Lb0/x1;

    .line 197
    .line 198
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 199
    .line 200
    .line 201
    iget-object v3, v0, Lb0/k1;->q:Ljava/util/concurrent/Executor;

    .line 202
    .line 203
    new-instance v5, La8/z;

    .line 204
    .line 205
    const/16 v6, 0x8

    .line 206
    .line 207
    invoke-direct {v5, v6, v1, v2}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    invoke-interface {v3, v5}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 211
    .line 212
    .line 213
    :cond_5
    iget-object v1, v4, Lh0/k;->a:Landroid/util/Size;

    .line 214
    .line 215
    move-object/from16 v2, p1

    .line 216
    .line 217
    invoke-static {v2, v1}, Lh0/v1;->d(Lh0/o2;Landroid/util/Size;)Lh0/v1;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    iget-object v3, v1, Lh0/u1;->b:Lb0/n1;

    .line 222
    .line 223
    iget v5, v4, Lh0/k;->d:I

    .line 224
    .line 225
    iput v5, v1, Lh0/u1;->h:I

    .line 226
    .line 227
    invoke-virtual {v0, v1, v4}, Lb0/z1;->a(Lh0/v1;Lh0/k;)V

    .line 228
    .line 229
    .line 230
    invoke-interface {v2}, Lh0/o2;->v()I

    .line 231
    .line 232
    .line 233
    move-result v2

    .line 234
    if-eqz v2, :cond_6

    .line 235
    .line 236
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 237
    .line 238
    .line 239
    if-eqz v2, :cond_6

    .line 240
    .line 241
    sget-object v5, Lh0/o2;->a1:Lh0/g;

    .line 242
    .line 243
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    iget-object v6, v3, Lb0/n1;->g:Ljava/lang/Object;

    .line 248
    .line 249
    check-cast v6, Lh0/j1;

    .line 250
    .line 251
    invoke-virtual {v6, v5, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 252
    .line 253
    .line 254
    :cond_6
    iget-object v2, v4, Lh0/k;->f:Lh0/q0;

    .line 255
    .line 256
    if-eqz v2, :cond_7

    .line 257
    .line 258
    invoke-virtual {v3, v2}, Lb0/n1;->i(Lh0/q0;)V

    .line 259
    .line 260
    .line 261
    :cond_7
    iget-object v2, v0, Lb0/k1;->p:Lb0/j1;

    .line 262
    .line 263
    if-eqz v2, :cond_8

    .line 264
    .line 265
    iget-object v2, v0, Lb0/k1;->s:Lb0/u1;

    .line 266
    .line 267
    iget-object v3, v4, Lh0/k;->c:Lb0/y;

    .line 268
    .line 269
    iget-object v4, v0, Lb0/z1;->g:Lh0/o2;

    .line 270
    .line 271
    check-cast v4, Lh0/a1;

    .line 272
    .line 273
    sget-object v5, Lh0/a1;->I0:Lh0/g;

    .line 274
    .line 275
    invoke-interface {v4, v5, v11}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v4

    .line 279
    check-cast v4, Ljava/lang/Integer;

    .line 280
    .line 281
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 282
    .line 283
    .line 284
    move-result v4

    .line 285
    invoke-virtual {v1, v2, v3, v4}, Lh0/v1;->b(Lh0/t0;Lb0/y;I)V

    .line 286
    .line 287
    .line 288
    :cond_8
    iget-object v2, v0, Lb0/k1;->v:Lh0/w1;

    .line 289
    .line 290
    if-eqz v2, :cond_9

    .line 291
    .line 292
    invoke-virtual {v2}, Lh0/w1;->b()V

    .line 293
    .line 294
    .line 295
    :cond_9
    new-instance v2, Lh0/w1;

    .line 296
    .line 297
    new-instance v3, Lb0/q0;

    .line 298
    .line 299
    const/4 v4, 0x1

    .line 300
    invoke-direct {v3, v0, v4}, Lb0/q0;-><init>(Ljava/lang/Object;I)V

    .line 301
    .line 302
    .line 303
    invoke-direct {v2, v3}, Lh0/w1;-><init>(Lh0/x1;)V

    .line 304
    .line 305
    .line 306
    iput-object v2, v0, Lb0/k1;->v:Lh0/w1;

    .line 307
    .line 308
    iput-object v2, v1, Lh0/u1;->f:Lh0/w1;

    .line 309
    .line 310
    iput-object v1, v0, Lb0/k1;->r:Lh0/v1;

    .line 311
    .line 312
    invoke-virtual {v1}, Lh0/v1;->c()Lh0/z1;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v1

    .line 320
    new-instance v2, Ljava/util/ArrayList;

    .line 321
    .line 322
    invoke-direct {v2, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 323
    .line 324
    .line 325
    aget-object v1, v1, v13

    .line 326
    .line 327
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 331
    .line 332
    .line 333
    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    invoke-virtual {v0, v1}, Lb0/z1;->C(Ljava/util/List;)V

    .line 338
    .line 339
    .line 340
    return-void
.end method

.method public final f(ZLh0/r2;)Lh0/o2;
    .locals 3

    .line 1
    sget-object v0, Lb0/k1;->w:Lb0/i1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object v0, Lb0/i1;->a:Lh0/o1;

    .line 7
    .line 8
    invoke-interface {v0}, Lh0/o2;->J()Lh0/q2;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-interface {p2, v1, v2}, Lh0/r2;->a(Lh0/q2;I)Lh0/q0;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    invoke-static {p2, v0}, Lh0/q0;->w(Lh0/q0;Lh0/q0;)Lh0/n1;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    :cond_0
    if-nez p2, :cond_1

    .line 24
    .line 25
    const/4 p0, 0x0

    .line 26
    return-object p0

    .line 27
    :cond_1
    invoke-virtual {p0, p2}, Lb0/k1;->l(Lh0/q0;)Lh0/n2;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lb0/h1;

    .line 32
    .line 33
    new-instance p1, Lh0/o1;

    .line 34
    .line 35
    iget-object p0, p0, Lb0/h1;->b:Lh0/j1;

    .line 36
    .line 37
    invoke-static {p0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-direct {p1, p0}, Lh0/o1;-><init>(Lh0/n1;)V

    .line 42
    .line 43
    .line 44
    return-object p1
.end method

.method public final k()Ljava/util/Set;
    .locals 1

    .line 1
    new-instance p0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p0, v0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final l(Lh0/q0;)Lh0/n2;
    .locals 0

    .line 1
    new-instance p0, Lb0/h1;

    .line 2
    .line 3
    invoke-static {p1}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-direct {p0, p1}, Lb0/h1;-><init>(Lh0/j1;)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public final t(Lh0/z;Lh0/n2;)Lh0/o2;
    .locals 1

    .line 1
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object p1, Lh0/z0;->C0:Lh0/g;

    .line 6
    .line 7
    const/16 v0, 0x22

    .line 8
    .line 9
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast p0, Lh0/j1;

    .line 14
    .line 15
    invoke-virtual {p0, p1, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    invoke-interface {p2}, Lh0/n2;->b()Lh0/o2;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lb0/z1;->g()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "Preview:"

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final w(Lh0/q0;)Lh0/k;
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/k1;->r:Lh0/v1;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lh0/v1;->a(Lh0/q0;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb0/k1;->r:Lh0/v1;

    .line 7
    .line 8
    invoke-virtual {v0}, Lh0/v1;->c()Lh0/z1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    new-instance v1, Ljava/util/ArrayList;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 20
    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    aget-object v0, v0, v2

    .line 24
    .line 25
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p0, v0}, Lb0/z1;->C(Ljava/util/List;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lb0/z1;->h:Lh0/k;

    .line 39
    .line 40
    invoke-virtual {p0}, Lh0/k;->b()Lss/b;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    iput-object p1, p0, Lss/b;->j:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-virtual {p0}, Lss/b;->c()Lh0/k;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method

.method public final x(Lh0/k;Lh0/k;)Lh0/k;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onSuggestedStreamSpecUpdated: primaryStreamSpec = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string v1, ", secondaryStreamSpec "

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    const-string v0, "Preview"

    .line 24
    .line 25
    invoke-static {v0, p2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object p2, p0, Lb0/z1;->g:Lh0/o2;

    .line 29
    .line 30
    check-cast p2, Lh0/o1;

    .line 31
    .line 32
    invoke-virtual {p0, p2, p1}, Lb0/k1;->F(Lh0/o1;Lh0/k;)V

    .line 33
    .line 34
    .line 35
    return-object p1
.end method

.method public final y()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lb0/k1;->D()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
