.class public final Laa/l0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ll2/t2;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ll2/t2;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p8, p0, Laa/l0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Laa/l0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Laa/l0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Laa/l0;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Laa/l0;->h:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p5, p0, Laa/l0;->i:Ll2/t2;

    .line 12
    .line 13
    iput-object p6, p0, Laa/l0;->j:Ljava/lang/Object;

    .line 14
    .line 15
    const/4 p1, 0x2

    .line 16
    invoke-direct {p0, p1, p7}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 10

    .line 1
    iget p1, p0, Laa/l0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Laa/l0;

    .line 7
    .line 8
    iget-object p1, p0, Laa/l0;->e:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lse/f;

    .line 12
    .line 13
    iget-object p1, p0, Laa/l0;->f:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v2, p1

    .line 16
    check-cast v2, Lay0/a;

    .line 17
    .line 18
    iget-object p1, p0, Laa/l0;->g:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v3, p1

    .line 21
    check-cast v3, Lay0/k;

    .line 22
    .line 23
    iget-object p1, p0, Laa/l0;->h:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v4, p1

    .line 26
    check-cast v4, Ll2/b1;

    .line 27
    .line 28
    iget-object p1, p0, Laa/l0;->i:Ll2/t2;

    .line 29
    .line 30
    move-object v5, p1

    .line 31
    check-cast v5, Ll2/b1;

    .line 32
    .line 33
    iget-object p0, p0, Laa/l0;->j:Ljava/lang/Object;

    .line 34
    .line 35
    move-object v6, p0

    .line 36
    check-cast v6, Ll2/b1;

    .line 37
    .line 38
    const/4 v8, 0x1

    .line 39
    move-object v7, p2

    .line 40
    invoke-direct/range {v0 .. v8}, Laa/l0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ll2/t2;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    return-object v0

    .line 44
    :pswitch_0
    move-object v7, p2

    .line 45
    new-instance v1, Laa/l0;

    .line 46
    .line 47
    iget-object p1, p0, Laa/l0;->e:Ljava/lang/Object;

    .line 48
    .line 49
    move-object v2, p1

    .line 50
    check-cast v2, Lc1/w1;

    .line 51
    .line 52
    iget-object p1, p0, Laa/l0;->f:Ljava/lang/Object;

    .line 53
    .line 54
    move-object v3, p1

    .line 55
    check-cast v3, Lz9/y;

    .line 56
    .line 57
    iget-object p1, p0, Laa/l0;->g:Ljava/lang/Object;

    .line 58
    .line 59
    move-object v4, p1

    .line 60
    check-cast v4, Lz9/k;

    .line 61
    .line 62
    iget-object p1, p0, Laa/l0;->h:Ljava/lang/Object;

    .line 63
    .line 64
    move-object v5, p1

    .line 65
    check-cast v5, Landroidx/collection/g0;

    .line 66
    .line 67
    iget-object p1, p0, Laa/l0;->j:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p1, Laa/i;

    .line 70
    .line 71
    const/4 v9, 0x0

    .line 72
    iget-object v6, p0, Laa/l0;->i:Ll2/t2;

    .line 73
    .line 74
    move-object v8, v7

    .line 75
    move-object v7, p1

    .line 76
    invoke-direct/range {v1 .. v9}, Laa/l0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ll2/t2;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 77
    .line 78
    .line 79
    return-object v1

    .line 80
    nop

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Laa/l0;->d:I

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
    invoke-virtual {p0, p1, p2}, Laa/l0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Laa/l0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Laa/l0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Laa/l0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Laa/l0;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Laa/l0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    return-object p1

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Laa/l0;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Laa/l0;->j:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v4, v0, Laa/l0;->i:Ll2/t2;

    .line 10
    .line 11
    iget-object v5, v0, Laa/l0;->h:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v6, v0, Laa/l0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object v7, v0, Laa/l0;->f:Ljava/lang/Object;

    .line 16
    .line 17
    iget-object v0, v0, Laa/l0;->g:Ljava/lang/Object;

    .line 18
    .line 19
    packed-switch v1, :pswitch_data_0

    .line 20
    .line 21
    .line 22
    check-cast v0, Lay0/k;

    .line 23
    .line 24
    check-cast v7, Lay0/a;

    .line 25
    .line 26
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 27
    .line 28
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    check-cast v6, Lse/f;

    .line 32
    .line 33
    iget-boolean v1, v6, Lse/f;->a:Z

    .line 34
    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    check-cast v5, Ll2/b1;

    .line 38
    .line 39
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Lay0/a;

    .line 44
    .line 45
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    invoke-interface {v7}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    sget-object v1, Lpe/b;->e:Lpe/b;

    .line 52
    .line 53
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_0
    iget-boolean v1, v6, Lse/f;->b:Z

    .line 58
    .line 59
    if-eqz v1, :cond_1

    .line 60
    .line 61
    check-cast v4, Ll2/b1;

    .line 62
    .line 63
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    check-cast v1, Lay0/a;

    .line 68
    .line 69
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    invoke-interface {v7}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    sget-object v1, Lpe/b;->f:Lpe/b;

    .line 76
    .line 77
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_1
    iget-boolean v1, v6, Lse/f;->c:Z

    .line 82
    .line 83
    if-eqz v1, :cond_2

    .line 84
    .line 85
    check-cast v3, Ll2/b1;

    .line 86
    .line 87
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    check-cast v1, Lay0/a;

    .line 92
    .line 93
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    invoke-interface {v7}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    sget-object v1, Lpe/b;->g:Lpe/b;

    .line 100
    .line 101
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    :cond_2
    :goto_0
    return-object v2

    .line 105
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 106
    .line 107
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    check-cast v6, Lc1/w1;

    .line 111
    .line 112
    iget-object v1, v6, Lc1/w1;->a:Lap0/o;

    .line 113
    .line 114
    invoke-virtual {v1}, Lap0/o;->D()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    iget-object v6, v6, Lc1/w1;->d:Ll2/j1;

    .line 119
    .line 120
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v8

    .line 124
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    if-eqz v1, :cond_9

    .line 129
    .line 130
    check-cast v7, Lz9/y;

    .line 131
    .line 132
    iget-object v1, v7, Lz9/y;->b:Lca/g;

    .line 133
    .line 134
    iget-object v1, v1, Lca/g;->f:Lmx0/l;

    .line 135
    .line 136
    invoke-virtual {v1}, Lmx0/l;->n()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    check-cast v1, Lz9/k;

    .line 141
    .line 142
    if-eqz v1, :cond_3

    .line 143
    .line 144
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    check-cast v0, Lz9/k;

    .line 149
    .line 150
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    if-eqz v0, :cond_9

    .line 155
    .line 156
    :cond_3
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    check-cast v0, Ljava/util/List;

    .line 161
    .line 162
    check-cast v0, Ljava/lang/Iterable;

    .line 163
    .line 164
    check-cast v3, Laa/i;

    .line 165
    .line 166
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    if-eqz v1, :cond_4

    .line 175
    .line 176
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    check-cast v1, Lz9/k;

    .line 181
    .line 182
    invoke-virtual {v3}, Lz9/j0;->b()Lz9/m;

    .line 183
    .line 184
    .line 185
    move-result-object v4

    .line 186
    invoke-virtual {v4, v1}, Lz9/m;->c(Lz9/k;)V

    .line 187
    .line 188
    .line 189
    goto :goto_1

    .line 190
    :cond_4
    check-cast v5, Landroidx/collection/g0;

    .line 191
    .line 192
    iget-object v0, v5, Landroidx/collection/g0;->a:[J

    .line 193
    .line 194
    array-length v1, v0

    .line 195
    add-int/lit8 v1, v1, -0x2

    .line 196
    .line 197
    if-ltz v1, :cond_9

    .line 198
    .line 199
    const/4 v4, 0x0

    .line 200
    :goto_2
    aget-wide v7, v0, v4

    .line 201
    .line 202
    not-long v9, v7

    .line 203
    const/4 v11, 0x7

    .line 204
    shl-long/2addr v9, v11

    .line 205
    and-long/2addr v9, v7

    .line 206
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 207
    .line 208
    .line 209
    .line 210
    .line 211
    and-long/2addr v9, v12

    .line 212
    cmp-long v9, v9, v12

    .line 213
    .line 214
    if-eqz v9, :cond_8

    .line 215
    .line 216
    sub-int v9, v4, v1

    .line 217
    .line 218
    not-int v9, v9

    .line 219
    ushr-int/lit8 v9, v9, 0x1f

    .line 220
    .line 221
    const/16 v10, 0x8

    .line 222
    .line 223
    rsub-int/lit8 v9, v9, 0x8

    .line 224
    .line 225
    const/4 v12, 0x0

    .line 226
    :goto_3
    if-ge v12, v9, :cond_7

    .line 227
    .line 228
    const-wide/16 v13, 0xff

    .line 229
    .line 230
    and-long v15, v7, v13

    .line 231
    .line 232
    const-wide/16 v17, 0x80

    .line 233
    .line 234
    cmp-long v15, v15, v17

    .line 235
    .line 236
    if-gez v15, :cond_5

    .line 237
    .line 238
    shl-int/lit8 v15, v4, 0x3

    .line 239
    .line 240
    add-int/2addr v15, v12

    .line 241
    iget-object v3, v5, Landroidx/collection/g0;->b:[Ljava/lang/Object;

    .line 242
    .line 243
    aget-object v3, v3, v15

    .line 244
    .line 245
    move/from16 p1, v11

    .line 246
    .line 247
    iget-object v11, v5, Landroidx/collection/g0;->c:[F

    .line 248
    .line 249
    aget v11, v11, v15

    .line 250
    .line 251
    check-cast v3, Ljava/lang/String;

    .line 252
    .line 253
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v11

    .line 257
    check-cast v11, Lz9/k;

    .line 258
    .line 259
    iget-object v11, v11, Lz9/k;->i:Ljava/lang/String;

    .line 260
    .line 261
    invoke-static {v3, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v3

    .line 265
    if-nez v3, :cond_6

    .line 266
    .line 267
    iget v3, v5, Landroidx/collection/g0;->e:I

    .line 268
    .line 269
    add-int/lit8 v3, v3, -0x1

    .line 270
    .line 271
    iput v3, v5, Landroidx/collection/g0;->e:I

    .line 272
    .line 273
    iget-object v3, v5, Landroidx/collection/g0;->a:[J

    .line 274
    .line 275
    iget v11, v5, Landroidx/collection/g0;->d:I

    .line 276
    .line 277
    shr-int/lit8 v16, v15, 0x3

    .line 278
    .line 279
    and-int/lit8 v17, v15, 0x7

    .line 280
    .line 281
    shl-int/lit8 v17, v17, 0x3

    .line 282
    .line 283
    aget-wide v18, v3, v16

    .line 284
    .line 285
    shl-long v13, v13, v17

    .line 286
    .line 287
    not-long v13, v13

    .line 288
    and-long v13, v18, v13

    .line 289
    .line 290
    const-wide/16 v18, 0xfe

    .line 291
    .line 292
    shl-long v17, v18, v17

    .line 293
    .line 294
    or-long v13, v13, v17

    .line 295
    .line 296
    aput-wide v13, v3, v16

    .line 297
    .line 298
    add-int/lit8 v16, v15, -0x7

    .line 299
    .line 300
    and-int v16, v16, v11

    .line 301
    .line 302
    and-int/lit8 v11, v11, 0x7

    .line 303
    .line 304
    add-int v16, v16, v11

    .line 305
    .line 306
    shr-int/lit8 v11, v16, 0x3

    .line 307
    .line 308
    aput-wide v13, v3, v11

    .line 309
    .line 310
    iget-object v3, v5, Landroidx/collection/g0;->b:[Ljava/lang/Object;

    .line 311
    .line 312
    const/4 v11, 0x0

    .line 313
    aput-object v11, v3, v15

    .line 314
    .line 315
    goto :goto_4

    .line 316
    :cond_5
    move/from16 p1, v11

    .line 317
    .line 318
    :cond_6
    :goto_4
    shr-long/2addr v7, v10

    .line 319
    add-int/lit8 v12, v12, 0x1

    .line 320
    .line 321
    move/from16 v11, p1

    .line 322
    .line 323
    goto :goto_3

    .line 324
    :cond_7
    if-ne v9, v10, :cond_9

    .line 325
    .line 326
    :cond_8
    if-eq v4, v1, :cond_9

    .line 327
    .line 328
    add-int/lit8 v4, v4, 0x1

    .line 329
    .line 330
    goto/16 :goto_2

    .line 331
    .line 332
    :cond_9
    return-object v2

    .line 333
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
