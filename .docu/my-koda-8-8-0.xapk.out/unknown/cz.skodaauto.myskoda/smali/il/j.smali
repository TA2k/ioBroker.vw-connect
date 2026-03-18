.class public final Lil/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ltl/b;

.field public final b:Llx0/q;

.field public final c:Lpv/g;

.field public final d:Lil/c;

.field public final e:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ltl/b;Llx0/q;Llx0/q;Llx0/q;Lil/c;Lxl/d;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p7

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    move-object/from16 v3, p2

    .line 11
    .line 12
    iput-object v3, v0, Lil/j;->a:Ltl/b;

    .line 13
    .line 14
    move-object/from16 v3, p3

    .line 15
    .line 16
    iput-object v3, v0, Lil/j;->b:Llx0/q;

    .line 17
    .line 18
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    sget-object v4, Lvy0/p0;->a:Lcz0/e;

    .line 23
    .line 24
    sget-object v4, Laz0/m;->a:Lwy0/c;

    .line 25
    .line 26
    iget-object v4, v4, Lwy0/c;->h:Lwy0/c;

    .line 27
    .line 28
    invoke-static {v3, v4}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    new-instance v4, Lil/i;

    .line 33
    .line 34
    invoke-direct {v4, v0}, Lil/i;-><init>(Lil/j;)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v3, v4}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    invoke-static {v3}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 42
    .line 43
    .line 44
    new-instance v3, Lxl/f;

    .line 45
    .line 46
    iget-boolean v4, v2, Lxl/d;->b:Z

    .line 47
    .line 48
    invoke-direct {v3, v0, v1, v4}, Lxl/f;-><init>(Lil/j;Landroid/content/Context;Z)V

    .line 49
    .line 50
    .line 51
    new-instance v4, Lpv/g;

    .line 52
    .line 53
    const/4 v5, 0x7

    .line 54
    invoke-direct {v4, v5, v0, v3}, Lpv/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iput-object v4, v0, Lil/j;->c:Lpv/g;

    .line 58
    .line 59
    new-instance v5, Lil/b;

    .line 60
    .line 61
    move-object/from16 v6, p6

    .line 62
    .line 63
    invoke-direct {v5, v6}, Lil/b;-><init>(Lil/c;)V

    .line 64
    .line 65
    .line 66
    new-instance v6, Lql/a;

    .line 67
    .line 68
    const/4 v7, 0x2

    .line 69
    invoke-direct {v6, v7}, Lql/a;-><init>(I)V

    .line 70
    .line 71
    .line 72
    const-class v8, Ld01/a0;

    .line 73
    .line 74
    invoke-virtual {v5, v6, v8}, Lil/b;->d(Lql/a;Ljava/lang/Class;)V

    .line 75
    .line 76
    .line 77
    new-instance v6, Lql/a;

    .line 78
    .line 79
    const/4 v8, 0x5

    .line 80
    invoke-direct {v6, v8}, Lql/a;-><init>(I)V

    .line 81
    .line 82
    .line 83
    const-class v9, Ljava/lang/String;

    .line 84
    .line 85
    invoke-virtual {v5, v6, v9}, Lil/b;->d(Lql/a;Ljava/lang/Class;)V

    .line 86
    .line 87
    .line 88
    new-instance v6, Lql/a;

    .line 89
    .line 90
    const/4 v9, 0x1

    .line 91
    invoke-direct {v6, v9}, Lql/a;-><init>(I)V

    .line 92
    .line 93
    .line 94
    const-class v10, Landroid/net/Uri;

    .line 95
    .line 96
    invoke-virtual {v5, v6, v10}, Lil/b;->d(Lql/a;Ljava/lang/Class;)V

    .line 97
    .line 98
    .line 99
    new-instance v6, Lql/a;

    .line 100
    .line 101
    const/4 v11, 0x4

    .line 102
    invoke-direct {v6, v11}, Lql/a;-><init>(I)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v5, v6, v10}, Lil/b;->d(Lql/a;Ljava/lang/Class;)V

    .line 106
    .line 107
    .line 108
    new-instance v6, Lql/a;

    .line 109
    .line 110
    const/4 v12, 0x3

    .line 111
    invoke-direct {v6, v12}, Lql/a;-><init>(I)V

    .line 112
    .line 113
    .line 114
    const-class v13, Ljava/lang/Integer;

    .line 115
    .line 116
    invoke-virtual {v5, v6, v13}, Lil/b;->d(Lql/a;Ljava/lang/Class;)V

    .line 117
    .line 118
    .line 119
    new-instance v6, Lql/a;

    .line 120
    .line 121
    const/4 v13, 0x0

    .line 122
    invoke-direct {v6, v13}, Lql/a;-><init>(I)V

    .line 123
    .line 124
    .line 125
    const-class v14, [B

    .line 126
    .line 127
    invoke-virtual {v5, v6, v14}, Lil/b;->d(Lql/a;Ljava/lang/Class;)V

    .line 128
    .line 129
    .line 130
    new-instance v6, Lpl/c;

    .line 131
    .line 132
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 133
    .line 134
    .line 135
    new-instance v14, Llx0/l;

    .line 136
    .line 137
    invoke-direct {v14, v6, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    iget-object v6, v5, Lil/b;->c:Ljava/util/ArrayList;

    .line 141
    .line 142
    invoke-virtual {v6, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    new-instance v14, Lpl/a;

    .line 146
    .line 147
    iget-boolean v15, v2, Lxl/d;->a:Z

    .line 148
    .line 149
    invoke-direct {v14, v15}, Lpl/a;-><init>(Z)V

    .line 150
    .line 151
    .line 152
    new-instance v15, Llx0/l;

    .line 153
    .line 154
    const-class v7, Ljava/io/File;

    .line 155
    .line 156
    invoke-direct {v15, v14, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v6, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    new-instance v14, Lnl/i;

    .line 163
    .line 164
    iget-boolean v15, v2, Lxl/d;->c:Z

    .line 165
    .line 166
    move-object/from16 v9, p4

    .line 167
    .line 168
    move-object/from16 v11, p5

    .line 169
    .line 170
    invoke-direct {v14, v11, v9, v15}, Lnl/i;-><init>(Llx0/q;Llx0/q;Z)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v5, v14, v10}, Lil/b;->c(Lnl/f;Ljava/lang/Class;)V

    .line 174
    .line 175
    .line 176
    new-instance v9, Lnl/a;

    .line 177
    .line 178
    invoke-direct {v9, v8}, Lnl/a;-><init>(I)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v5, v9, v7}, Lil/b;->c(Lnl/f;Ljava/lang/Class;)V

    .line 182
    .line 183
    .line 184
    new-instance v7, Lnl/a;

    .line 185
    .line 186
    invoke-direct {v7, v13}, Lnl/a;-><init>(I)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v5, v7, v10}, Lil/b;->c(Lnl/f;Ljava/lang/Class;)V

    .line 190
    .line 191
    .line 192
    new-instance v7, Lnl/a;

    .line 193
    .line 194
    invoke-direct {v7, v12}, Lnl/a;-><init>(I)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v5, v7, v10}, Lil/b;->c(Lnl/f;Ljava/lang/Class;)V

    .line 198
    .line 199
    .line 200
    new-instance v7, Lnl/a;

    .line 201
    .line 202
    const/4 v8, 0x6

    .line 203
    invoke-direct {v7, v8}, Lnl/a;-><init>(I)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v5, v7, v10}, Lil/b;->c(Lnl/f;Ljava/lang/Class;)V

    .line 207
    .line 208
    .line 209
    new-instance v7, Lnl/a;

    .line 210
    .line 211
    const/4 v8, 0x4

    .line 212
    invoke-direct {v7, v8}, Lnl/a;-><init>(I)V

    .line 213
    .line 214
    .line 215
    const-class v8, Landroid/graphics/drawable/Drawable;

    .line 216
    .line 217
    invoke-virtual {v5, v7, v8}, Lil/b;->c(Lnl/f;Ljava/lang/Class;)V

    .line 218
    .line 219
    .line 220
    new-instance v7, Lnl/a;

    .line 221
    .line 222
    const/4 v8, 0x1

    .line 223
    invoke-direct {v7, v8}, Lnl/a;-><init>(I)V

    .line 224
    .line 225
    .line 226
    const-class v8, Landroid/graphics/Bitmap;

    .line 227
    .line 228
    invoke-virtual {v5, v7, v8}, Lil/b;->c(Lnl/f;Ljava/lang/Class;)V

    .line 229
    .line 230
    .line 231
    new-instance v7, Lnl/a;

    .line 232
    .line 233
    const/4 v8, 0x2

    .line 234
    invoke-direct {v7, v8}, Lnl/a;-><init>(I)V

    .line 235
    .line 236
    .line 237
    const-class v8, Ljava/nio/ByteBuffer;

    .line 238
    .line 239
    invoke-virtual {v5, v7, v8}, Lil/b;->c(Lnl/f;Ljava/lang/Class;)V

    .line 240
    .line 241
    .line 242
    new-instance v7, Lkl/b;

    .line 243
    .line 244
    iget v8, v2, Lxl/d;->d:I

    .line 245
    .line 246
    iget-object v2, v2, Lxl/d;->e:Lkl/h;

    .line 247
    .line 248
    invoke-direct {v7, v8, v2}, Lkl/b;-><init>(ILkl/h;)V

    .line 249
    .line 250
    .line 251
    iget-object v2, v5, Lil/b;->e:Ljava/util/ArrayList;

    .line 252
    .line 253
    invoke-virtual {v2, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    new-instance v7, Lil/c;

    .line 257
    .line 258
    iget-object v8, v5, Lil/b;->a:Ljava/util/ArrayList;

    .line 259
    .line 260
    invoke-static {v8}, Llp/ze;->b(Ljava/util/ArrayList;)Ljava/util/List;

    .line 261
    .line 262
    .line 263
    move-result-object v8

    .line 264
    iget-object v9, v5, Lil/b;->b:Ljava/util/ArrayList;

    .line 265
    .line 266
    invoke-static {v9}, Llp/ze;->b(Ljava/util/ArrayList;)Ljava/util/List;

    .line 267
    .line 268
    .line 269
    move-result-object v9

    .line 270
    invoke-static {v6}, Llp/ze;->b(Ljava/util/ArrayList;)Ljava/util/List;

    .line 271
    .line 272
    .line 273
    move-result-object v6

    .line 274
    iget-object v5, v5, Lil/b;->d:Ljava/util/ArrayList;

    .line 275
    .line 276
    invoke-static {v5}, Llp/ze;->b(Ljava/util/ArrayList;)Ljava/util/List;

    .line 277
    .line 278
    .line 279
    move-result-object v5

    .line 280
    invoke-static {v2}, Llp/ze;->b(Ljava/util/ArrayList;)Ljava/util/List;

    .line 281
    .line 282
    .line 283
    move-result-object v2

    .line 284
    move-object/from16 p7, v2

    .line 285
    .line 286
    move-object/from16 p6, v5

    .line 287
    .line 288
    move-object/from16 p5, v6

    .line 289
    .line 290
    move-object/from16 p2, v7

    .line 291
    .line 292
    move-object/from16 p3, v8

    .line 293
    .line 294
    move-object/from16 p4, v9

    .line 295
    .line 296
    invoke-direct/range {p2 .. p7}, Lil/c;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 297
    .line 298
    .line 299
    move-object/from16 v2, p2

    .line 300
    .line 301
    move-object/from16 v5, p3

    .line 302
    .line 303
    iput-object v2, v0, Lil/j;->d:Lil/c;

    .line 304
    .line 305
    move-object v8, v5

    .line 306
    check-cast v8, Ljava/util/Collection;

    .line 307
    .line 308
    new-instance v2, Lol/f;

    .line 309
    .line 310
    invoke-direct {v2, v0, v4}, Lol/f;-><init>(Lil/j;Lpv/g;)V

    .line 311
    .line 312
    .line 313
    invoke-static {v8, v2}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 314
    .line 315
    .line 316
    move-result-object v2

    .line 317
    iput-object v2, v0, Lil/j;->e:Ljava/util/ArrayList;

    .line 318
    .line 319
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 320
    .line 321
    invoke-direct {v0, v13}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 322
    .line 323
    .line 324
    invoke-virtual {v1, v3}, Landroid/content/Context;->registerComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    .line 325
    .line 326
    .line 327
    return-void
.end method

.method public static final a(Lil/j;Ltl/h;ILrx0/c;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p3

    .line 4
    .line 5
    instance-of v2, v0, Lil/h;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v0

    .line 10
    check-cast v2, Lil/h;

    .line 11
    .line 12
    iget v3, v2, Lil/h;->k:I

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
    iput v3, v2, Lil/h;->k:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lil/h;

    .line 25
    .line 26
    invoke-direct {v2, v1, v0}, Lil/h;-><init>(Lil/j;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v0, v2, Lil/h;->i:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lil/h;->k:I

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    const/4 v6, 0x2

    .line 37
    const/4 v7, 0x1

    .line 38
    const/4 v8, 0x0

    .line 39
    if-eqz v4, :cond_4

    .line 40
    .line 41
    if-eq v4, v7, :cond_3

    .line 42
    .line 43
    if-eq v4, v6, :cond_2

    .line 44
    .line 45
    if-ne v4, v5, :cond_1

    .line 46
    .line 47
    iget-object v1, v2, Lil/h;->g:Lil/d;

    .line 48
    .line 49
    iget-object v3, v2, Lil/h;->f:Ltl/h;

    .line 50
    .line 51
    iget-object v4, v2, Lil/h;->e:Lmm/k;

    .line 52
    .line 53
    iget-object v2, v2, Lil/h;->d:Lil/j;

    .line 54
    .line 55
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 56
    .line 57
    .line 58
    move-object v14, v2

    .line 59
    goto/16 :goto_7

    .line 60
    .line 61
    :catchall_0
    move-exception v0

    .line 62
    move-object v11, v1

    .line 63
    move-object v1, v2

    .line 64
    goto/16 :goto_d

    .line 65
    .line 66
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 69
    .line 70
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw v0

    .line 74
    :cond_2
    iget-object v1, v2, Lil/h;->h:Landroid/graphics/Bitmap;

    .line 75
    .line 76
    iget-object v4, v2, Lil/h;->g:Lil/d;

    .line 77
    .line 78
    iget-object v6, v2, Lil/h;->f:Ltl/h;

    .line 79
    .line 80
    iget-object v7, v2, Lil/h;->e:Lmm/k;

    .line 81
    .line 82
    iget-object v9, v2, Lil/h;->d:Lil/j;

    .line 83
    .line 84
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 85
    .line 86
    .line 87
    move-object/from16 v17, v1

    .line 88
    .line 89
    move-object/from16 v16, v4

    .line 90
    .line 91
    move-object v13, v6

    .line 92
    move-object v14, v9

    .line 93
    :goto_1
    move-object v4, v7

    .line 94
    goto/16 :goto_5

    .line 95
    .line 96
    :catchall_1
    move-exception v0

    .line 97
    move-object v11, v4

    .line 98
    move-object v3, v6

    .line 99
    :goto_2
    move-object v4, v7

    .line 100
    move-object v1, v9

    .line 101
    goto/16 :goto_d

    .line 102
    .line 103
    :cond_3
    iget-object v1, v2, Lil/h;->g:Lil/d;

    .line 104
    .line 105
    iget-object v4, v2, Lil/h;->f:Ltl/h;

    .line 106
    .line 107
    iget-object v7, v2, Lil/h;->e:Lmm/k;

    .line 108
    .line 109
    iget-object v9, v2, Lil/h;->d:Lil/j;

    .line 110
    .line 111
    :try_start_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 112
    .line 113
    .line 114
    move-object v11, v1

    .line 115
    move-object v1, v9

    .line 116
    goto :goto_3

    .line 117
    :catchall_2
    move-exception v0

    .line 118
    move-object v11, v1

    .line 119
    move-object v3, v4

    .line 120
    goto :goto_2

    .line 121
    :cond_4
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    iget-object v0, v1, Lil/j;->c:Lpv/g;

    .line 125
    .line 126
    invoke-interface {v2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    invoke-static {v4}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 131
    .line 132
    .line 133
    move-result-object v4

    .line 134
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    move-object/from16 v0, p1

    .line 138
    .line 139
    iget-object v9, v0, Ltl/h;->u:Landroidx/lifecycle/r;

    .line 140
    .line 141
    new-instance v10, Lmm/k;

    .line 142
    .line 143
    invoke-direct {v10, v9, v4, v7}, Lmm/k;-><init>(Landroidx/lifecycle/r;Lvy0/i1;I)V

    .line 144
    .line 145
    .line 146
    invoke-static {v0}, Ltl/h;->a(Ltl/h;)Ltl/g;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    iget-object v4, v1, Lil/j;->a:Ltl/b;

    .line 151
    .line 152
    iput-object v4, v0, Ltl/g;->b:Ltl/b;

    .line 153
    .line 154
    iput-object v8, v0, Ltl/g;->q:Lul/f;

    .line 155
    .line 156
    invoke-virtual {v0}, Ltl/g;->a()Ltl/h;

    .line 157
    .line 158
    .line 159
    move-result-object v4

    .line 160
    sget-object v11, Lil/d;->a:Lil/d;

    .line 161
    .line 162
    :try_start_3
    iget-object v0, v4, Ltl/h;->b:Ljava/lang/Object;

    .line 163
    .line 164
    sget-object v12, Ltl/j;->a:Ltl/j;

    .line 165
    .line 166
    if-eq v0, v12, :cond_e

    .line 167
    .line 168
    invoke-virtual {v9, v10}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 169
    .line 170
    .line 171
    if-nez p2, :cond_5

    .line 172
    .line 173
    iget-object v0, v4, Ltl/h;->u:Landroidx/lifecycle/r;

    .line 174
    .line 175
    iput-object v1, v2, Lil/h;->d:Lil/j;

    .line 176
    .line 177
    iput-object v10, v2, Lil/h;->e:Lmm/k;

    .line 178
    .line 179
    iput-object v4, v2, Lil/h;->f:Ltl/h;

    .line 180
    .line 181
    iput-object v11, v2, Lil/h;->g:Lil/d;

    .line 182
    .line 183
    iput v7, v2, Lil/h;->k:I

    .line 184
    .line 185
    invoke-static {v0, v2}, Llp/bf;->g(Landroidx/lifecycle/r;Lrx0/c;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 189
    if-ne v0, v3, :cond_5

    .line 190
    .line 191
    goto/16 :goto_6

    .line 192
    .line 193
    :catchall_3
    move-exception v0

    .line 194
    move-object v3, v4

    .line 195
    move-object v4, v10

    .line 196
    goto/16 :goto_d

    .line 197
    .line 198
    :cond_5
    move-object v7, v10

    .line 199
    :goto_3
    :try_start_4
    iget-object v0, v1, Lil/j;->b:Llx0/q;

    .line 200
    .line 201
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    check-cast v0, Lrl/c;

    .line 206
    .line 207
    if-eqz v0, :cond_6

    .line 208
    .line 209
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 210
    .line 211
    .line 212
    goto :goto_4

    .line 213
    :catchall_4
    move-exception v0

    .line 214
    move-object v3, v4

    .line 215
    move-object v4, v7

    .line 216
    goto/16 :goto_d

    .line 217
    .line 218
    :cond_6
    :goto_4
    iget-object v0, v4, Ltl/h;->z:Ltl/b;

    .line 219
    .line 220
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 221
    .line 222
    .line 223
    sget-object v0, Lxl/b;->a:Ltl/b;

    .line 224
    .line 225
    iget-object v0, v4, Ltl/h;->c:Lvl/a;

    .line 226
    .line 227
    if-eqz v0, :cond_7

    .line 228
    .line 229
    invoke-interface {v0, v8}, Lvl/a;->b(Landroid/graphics/drawable/Drawable;)V

    .line 230
    .line 231
    .line 232
    :cond_7
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 233
    .line 234
    .line 235
    iget-object v0, v4, Ltl/h;->v:Lul/h;

    .line 236
    .line 237
    iput-object v1, v2, Lil/h;->d:Lil/j;

    .line 238
    .line 239
    iput-object v7, v2, Lil/h;->e:Lmm/k;

    .line 240
    .line 241
    iput-object v4, v2, Lil/h;->f:Ltl/h;

    .line 242
    .line 243
    iput-object v11, v2, Lil/h;->g:Lil/d;

    .line 244
    .line 245
    iput-object v8, v2, Lil/h;->h:Landroid/graphics/Bitmap;

    .line 246
    .line 247
    iput v6, v2, Lil/h;->k:I

    .line 248
    .line 249
    invoke-interface {v0, v2}, Lul/h;->d(Lil/h;)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 253
    if-ne v0, v3, :cond_8

    .line 254
    .line 255
    goto :goto_6

    .line 256
    :cond_8
    move-object v14, v1

    .line 257
    move-object v13, v4

    .line 258
    move-object/from16 v17, v8

    .line 259
    .line 260
    move-object/from16 v16, v11

    .line 261
    .line 262
    goto/16 :goto_1

    .line 263
    .line 264
    :goto_5
    :try_start_5
    move-object v15, v0

    .line 265
    check-cast v15, Lul/g;

    .line 266
    .line 267
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 268
    .line 269
    .line 270
    iget-object v0, v13, Ltl/h;->q:Lvy0/x;

    .line 271
    .line 272
    new-instance v12, Laa/i0;

    .line 273
    .line 274
    const/16 v18, 0x0

    .line 275
    .line 276
    const/16 v19, 0xa

    .line 277
    .line 278
    invoke-direct/range {v12 .. v19}, Laa/i0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_7

    .line 279
    .line 280
    .line 281
    move-object/from16 v1, v16

    .line 282
    .line 283
    :try_start_6
    iput-object v14, v2, Lil/h;->d:Lil/j;

    .line 284
    .line 285
    iput-object v4, v2, Lil/h;->e:Lmm/k;

    .line 286
    .line 287
    iput-object v13, v2, Lil/h;->f:Ltl/h;

    .line 288
    .line 289
    iput-object v1, v2, Lil/h;->g:Lil/d;

    .line 290
    .line 291
    iput-object v8, v2, Lil/h;->h:Landroid/graphics/Bitmap;

    .line 292
    .line 293
    iput v5, v2, Lil/h;->k:I

    .line 294
    .line 295
    invoke-static {v0, v12, v2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 299
    if-ne v0, v3, :cond_9

    .line 300
    .line 301
    :goto_6
    return-object v3

    .line 302
    :cond_9
    move-object v3, v13

    .line 303
    :goto_7
    :try_start_7
    check-cast v0, Ltl/i;

    .line 304
    .line 305
    instance-of v2, v0, Ltl/n;

    .line 306
    .line 307
    if-eqz v2, :cond_c

    .line 308
    .line 309
    move-object v2, v0

    .line 310
    check-cast v2, Ltl/n;

    .line 311
    .line 312
    iget-object v5, v3, Ltl/h;->c:Lvl/a;

    .line 313
    .line 314
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 315
    .line 316
    .line 317
    iget-object v6, v2, Ltl/n;->b:Ltl/h;

    .line 318
    .line 319
    instance-of v7, v5, Ljl/i;

    .line 320
    .line 321
    if-nez v7, :cond_a

    .line 322
    .line 323
    goto :goto_8

    .line 324
    :cond_a
    iget-object v7, v6, Ltl/h;->g:Lwl/e;

    .line 325
    .line 326
    check-cast v5, Ljl/i;

    .line 327
    .line 328
    invoke-interface {v7, v5, v2}, Lwl/e;->a(Ljl/i;Ltl/i;)Lwl/f;

    .line 329
    .line 330
    .line 331
    move-result-object v2

    .line 332
    instance-of v5, v2, Lwl/d;

    .line 333
    .line 334
    if-eqz v5, :cond_b

    .line 335
    .line 336
    goto :goto_8

    .line 337
    :cond_b
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 338
    .line 339
    .line 340
    invoke-interface {v2}, Lwl/f;->a()V

    .line 341
    .line 342
    .line 343
    :goto_8
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 344
    .line 345
    .line 346
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 347
    .line 348
    .line 349
    goto :goto_b

    .line 350
    :goto_9
    move-object v11, v1

    .line 351
    :goto_a
    move-object v1, v14

    .line 352
    goto :goto_d

    .line 353
    :catchall_5
    move-exception v0

    .line 354
    goto :goto_9

    .line 355
    :cond_c
    instance-of v2, v0, Ltl/d;

    .line 356
    .line 357
    if-eqz v2, :cond_d

    .line 358
    .line 359
    move-object v2, v0

    .line 360
    check-cast v2, Ltl/d;

    .line 361
    .line 362
    iget-object v5, v3, Ltl/h;->c:Lvl/a;

    .line 363
    .line 364
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 365
    .line 366
    .line 367
    invoke-static {v2, v5, v1}, Lil/j;->b(Ltl/d;Lvl/a;Lil/d;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    .line 368
    .line 369
    .line 370
    :cond_d
    :goto_b
    iget-object v1, v4, Lmm/k;->e:Landroidx/lifecycle/r;

    .line 371
    .line 372
    invoke-virtual {v1, v4}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 373
    .line 374
    .line 375
    return-object v0

    .line 376
    :catchall_6
    move-exception v0

    .line 377
    :goto_c
    move-object v11, v1

    .line 378
    move-object v3, v13

    .line 379
    goto :goto_a

    .line 380
    :catchall_7
    move-exception v0

    .line 381
    move-object/from16 v1, v16

    .line 382
    .line 383
    goto :goto_c

    .line 384
    :cond_e
    :try_start_8
    new-instance v0, Ltl/k;

    .line 385
    .line 386
    const-string v2, "The request\'s data is null."

    .line 387
    .line 388
    invoke-direct {v0, v2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 389
    .line 390
    .line 391
    throw v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 392
    :goto_d
    :try_start_9
    instance-of v2, v0, Ljava/util/concurrent/CancellationException;

    .line 393
    .line 394
    if-nez v2, :cond_f

    .line 395
    .line 396
    iget-object v1, v1, Lil/j;->c:Lpv/g;

    .line 397
    .line 398
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 399
    .line 400
    .line 401
    invoke-static {v3, v0}, Lpv/g;->b(Ltl/h;Ljava/lang/Throwable;)Ltl/d;

    .line 402
    .line 403
    .line 404
    move-result-object v0

    .line 405
    iget-object v1, v3, Ltl/h;->c:Lvl/a;

    .line 406
    .line 407
    invoke-static {v0, v1, v11}, Lil/j;->b(Ltl/d;Lvl/a;Lil/d;)V

    .line 408
    .line 409
    .line 410
    goto :goto_b

    .line 411
    :catchall_8
    move-exception v0

    .line 412
    goto :goto_e

    .line 413
    :cond_f
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 414
    .line 415
    .line 416
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 417
    .line 418
    .line 419
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 420
    .line 421
    .line 422
    throw v0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_8

    .line 423
    :goto_e
    iget-object v1, v4, Lmm/k;->e:Landroidx/lifecycle/r;

    .line 424
    .line 425
    invoke-virtual {v1, v4}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 426
    .line 427
    .line 428
    throw v0
.end method

.method public static b(Ltl/d;Lvl/a;Lil/d;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltl/d;->b:Ltl/h;

    .line 2
    .line 3
    instance-of v1, p1, Ljl/i;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-object v1, v0, Ltl/h;->g:Lwl/e;

    .line 9
    .line 10
    check-cast p1, Ljl/i;

    .line 11
    .line 12
    invoke-interface {v1, p1, p0}, Lwl/e;->a(Ljl/i;Ltl/i;)Lwl/f;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    instance-of p1, p0, Lwl/d;

    .line 17
    .line 18
    if-eqz p1, :cond_1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    invoke-interface {p0}, Lwl/f;->a()V

    .line 25
    .line 26
    .line 27
    :goto_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    return-void
.end method
