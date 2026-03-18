.class public abstract Lev/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/List;Lm6/j;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lm6/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lm6/f;

    .line 7
    .line 8
    iget v1, v0, Lm6/f;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lm6/f;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/f;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lm6/f;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/f;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object p0, v0, Lm6/f;->e:Ljava/util/Iterator;

    .line 40
    .line 41
    iget-object p1, v0, Lm6/f;->d:Ljava/io/Serializable;

    .line 42
    .line 43
    check-cast p1, Lkotlin/jvm/internal/f0;

    .line 44
    .line 45
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 46
    .line 47
    .line 48
    goto :goto_2

    .line 49
    :catchall_0
    move-exception p2

    .line 50
    goto :goto_3

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    iget-object p0, v0, Lm6/f;->d:Ljava/io/Serializable;

    .line 60
    .line 61
    check-cast p0, Ljava/util/List;

    .line 62
    .line 63
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    new-instance p2, Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 73
    .line 74
    .line 75
    new-instance v2, La7/k0;

    .line 76
    .line 77
    const/4 v5, 0x0

    .line 78
    invoke-direct {v2, p0, p2, v5}, La7/k0;-><init>(Ljava/util/List;Ljava/util/ArrayList;Lkotlin/coroutines/Continuation;)V

    .line 79
    .line 80
    .line 81
    iput-object p2, v0, Lm6/f;->d:Ljava/io/Serializable;

    .line 82
    .line 83
    iput v4, v0, Lm6/f;->g:I

    .line 84
    .line 85
    invoke-virtual {p1, v2, v0}, Lm6/j;->a(La7/k0;Lrx0/c;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    if-ne p0, v1, :cond_4

    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_4
    move-object p0, p2

    .line 93
    :goto_1
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 94
    .line 95
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 96
    .line 97
    .line 98
    check-cast p0, Ljava/lang/Iterable;

    .line 99
    .line 100
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    :cond_5
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    if-eqz p2, :cond_7

    .line 109
    .line 110
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    check-cast p2, Lay0/k;

    .line 115
    .line 116
    :try_start_1
    iput-object p1, v0, Lm6/f;->d:Ljava/io/Serializable;

    .line 117
    .line 118
    iput-object p0, v0, Lm6/f;->e:Ljava/util/Iterator;

    .line 119
    .line 120
    iput v3, v0, Lm6/f;->g:I

    .line 121
    .line 122
    invoke-interface {p2, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 126
    if-ne p2, v1, :cond_5

    .line 127
    .line 128
    goto :goto_4

    .line 129
    :goto_3
    iget-object v2, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 130
    .line 131
    if-nez v2, :cond_6

    .line 132
    .line 133
    iput-object p2, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_6
    check-cast v2, Ljava/lang/Throwable;

    .line 137
    .line 138
    invoke-static {v2, p2}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_7
    iget-object p0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast p0, Ljava/lang/Throwable;

    .line 145
    .line 146
    if-nez p0, :cond_8

    .line 147
    .line 148
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    :goto_4
    return-object v1

    .line 151
    :cond_8
    throw p0
.end method

.method public static final b(La7/e2;Landroid/widget/RemoteViews;Ly6/q;La7/d1;)V
    .locals 22

    .line 1
    move-object/from16 v10, p0

    .line 2
    .line 3
    iget-object v4, v10, La7/e2;->a:Landroid/content/Context;

    .line 4
    .line 5
    new-instance v2, Lkotlin/jvm/internal/f0;

    .line 6
    .line 7
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    new-instance v3, Lkotlin/jvm/internal/f0;

    .line 11
    .line 12
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    new-instance v7, Lkotlin/jvm/internal/f0;

    .line 16
    .line 17
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    new-instance v9, Lkotlin/jvm/internal/f0;

    .line 21
    .line 22
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    new-instance v8, Lkotlin/jvm/internal/f0;

    .line 26
    .line 27
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sget-object v0, Ly6/u;->d:Ly6/u;

    .line 31
    .line 32
    iput-object v0, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 33
    .line 34
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 35
    .line 36
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 37
    .line 38
    .line 39
    new-instance v12, Lkotlin/jvm/internal/f0;

    .line 40
    .line 41
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 42
    .line 43
    .line 44
    new-instance v11, Lkotlin/jvm/internal/f0;

    .line 45
    .line 46
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 47
    .line 48
    .line 49
    new-instance v13, Lkotlin/jvm/internal/f0;

    .line 50
    .line 51
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 52
    .line 53
    .line 54
    new-instance v0, La7/u;

    .line 55
    .line 56
    move-object/from16 v5, p1

    .line 57
    .line 58
    move-object/from16 v6, p3

    .line 59
    .line 60
    invoke-direct/range {v0 .. v13}, La7/u;-><init>(Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Landroid/content/Context;Landroid/widget/RemoteViews;La7/d1;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;La7/e2;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;)V

    .line 61
    .line 62
    .line 63
    move-object/from16 v21, v5

    .line 64
    .line 65
    move-object v5, v0

    .line 66
    move-object v0, v1

    .line 67
    move-object/from16 v1, v21

    .line 68
    .line 69
    sget-object v14, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    move-object/from16 v15, p2

    .line 72
    .line 73
    invoke-interface {v15, v14, v5}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    iget-object v2, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v2, Lf7/t;

    .line 79
    .line 80
    iget-object v3, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v3, Lf7/n;

    .line 83
    .line 84
    sget-object v5, La7/j1;->a:Ljava/lang/Object;

    .line 85
    .line 86
    iget v5, v6, La7/d1;->b:I

    .line 87
    .line 88
    iget v14, v6, La7/d1;->a:I

    .line 89
    .line 90
    const/16 v16, 0x0

    .line 91
    .line 92
    const/4 v15, -0x1

    .line 93
    if-ne v5, v15, :cond_2

    .line 94
    .line 95
    if-eqz v2, :cond_0

    .line 96
    .line 97
    invoke-static {v1, v2, v14}, Lev/a;->d(Landroid/widget/RemoteViews;Lf7/t;I)V

    .line 98
    .line 99
    .line 100
    :cond_0
    if-eqz v3, :cond_1

    .line 101
    .line 102
    invoke-static {v1, v3, v14}, Lev/a;->c(Landroid/widget/RemoteViews;Lf7/n;I)V

    .line 103
    .line 104
    .line 105
    :cond_1
    :goto_0
    move-object/from16 v18, v4

    .line 106
    .line 107
    move-object/from16 v19, v8

    .line 108
    .line 109
    move-object/from16 v17, v12

    .line 110
    .line 111
    move-object/from16 v20, v13

    .line 112
    .line 113
    goto/16 :goto_11

    .line 114
    .line 115
    :cond_2
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 116
    .line 117
    const/16 v15, 0x1f

    .line 118
    .line 119
    if-ge v5, v15, :cond_25

    .line 120
    .line 121
    if-eqz v2, :cond_3

    .line 122
    .line 123
    iget-object v2, v2, Lf7/t;->a:Lk7/g;

    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_3
    const/4 v2, 0x0

    .line 127
    :goto_1
    if-eqz v3, :cond_4

    .line 128
    .line 129
    iget-object v3, v3, Lf7/n;->a:Lk7/g;

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_4
    const/4 v3, 0x0

    .line 133
    :goto_2
    invoke-static {v2}, Lev/a;->f(Lk7/g;)Z

    .line 134
    .line 135
    .line 136
    move-result v5

    .line 137
    if-nez v5, :cond_5

    .line 138
    .line 139
    invoke-static {v3}, Lev/a;->f(Lk7/g;)Z

    .line 140
    .line 141
    .line 142
    move-result v5

    .line 143
    if-nez v5, :cond_5

    .line 144
    .line 145
    goto :goto_0

    .line 146
    :cond_5
    instance-of v5, v2, Lk7/e;

    .line 147
    .line 148
    if-nez v5, :cond_7

    .line 149
    .line 150
    instance-of v5, v2, Lk7/d;

    .line 151
    .line 152
    if-eqz v5, :cond_6

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_6
    move/from16 v5, v16

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_7
    :goto_3
    const/4 v5, 0x1

    .line 159
    :goto_4
    instance-of v15, v3, Lk7/e;

    .line 160
    .line 161
    if-nez v15, :cond_9

    .line 162
    .line 163
    instance-of v15, v3, Lk7/d;

    .line 164
    .line 165
    if-eqz v15, :cond_8

    .line 166
    .line 167
    goto :goto_5

    .line 168
    :cond_8
    move/from16 v15, v16

    .line 169
    .line 170
    goto :goto_6

    .line 171
    :cond_9
    :goto_5
    const/4 v15, 0x1

    .line 172
    :goto_6
    if-eqz v5, :cond_a

    .line 173
    .line 174
    if-eqz v15, :cond_a

    .line 175
    .line 176
    const v5, 0x7f0d051e

    .line 177
    .line 178
    .line 179
    goto :goto_7

    .line 180
    :cond_a
    if-eqz v5, :cond_b

    .line 181
    .line 182
    const v5, 0x7f0d051f

    .line 183
    .line 184
    .line 185
    goto :goto_7

    .line 186
    :cond_b
    if-eqz v15, :cond_c

    .line 187
    .line 188
    const v5, 0x7f0d0520

    .line 189
    .line 190
    .line 191
    goto :goto_7

    .line 192
    :cond_c
    const v5, 0x7f0d0521

    .line 193
    .line 194
    .line 195
    :goto_7
    const v15, 0x7f0a0299

    .line 196
    .line 197
    .line 198
    move-object/from16 v18, v4

    .line 199
    .line 200
    const/4 v4, 0x0

    .line 201
    invoke-static {v1, v10, v15, v5, v4}, Lj0/g;->a(Landroid/widget/RemoteViews;La7/e2;IILjava/lang/Integer;)I

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    instance-of v5, v2, Lk7/c;

    .line 206
    .line 207
    sget-object v15, Lk7/f;->a:Lk7/f;

    .line 208
    .line 209
    move/from16 v17, v5

    .line 210
    .line 211
    sget-object v5, Lk7/e;->a:Lk7/e;

    .line 212
    .line 213
    move-object/from16 v19, v8

    .line 214
    .line 215
    sget-object v8, Lk7/d;->a:Lk7/d;

    .line 216
    .line 217
    if-eqz v17, :cond_d

    .line 218
    .line 219
    check-cast v2, Lk7/c;

    .line 220
    .line 221
    iget v2, v2, Lk7/c;->a:F

    .line 222
    .line 223
    invoke-virtual/range {v18 .. v18}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 224
    .line 225
    .line 226
    move-result-object v17

    .line 227
    move-object/from16 v20, v13

    .line 228
    .line 229
    invoke-virtual/range {v17 .. v17}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 230
    .line 231
    .line 232
    move-result-object v13

    .line 233
    move-object/from16 v17, v12

    .line 234
    .line 235
    const/4 v12, 0x1

    .line 236
    invoke-static {v12, v2, v13}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 237
    .line 238
    .line 239
    move-result v2

    .line 240
    float-to-int v2, v2

    .line 241
    const-string v12, "setWidth"

    .line 242
    .line 243
    invoke-virtual {v1, v4, v12, v2}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 244
    .line 245
    .line 246
    goto :goto_c

    .line 247
    :cond_d
    move-object/from16 v17, v12

    .line 248
    .line 249
    move-object/from16 v20, v13

    .line 250
    .line 251
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result v12

    .line 255
    if-eqz v12, :cond_e

    .line 256
    .line 257
    const/4 v12, 0x1

    .line 258
    goto :goto_8

    .line 259
    :cond_e
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    move-result v12

    .line 263
    :goto_8
    if-eqz v12, :cond_f

    .line 264
    .line 265
    const/4 v12, 0x1

    .line 266
    goto :goto_9

    .line 267
    :cond_f
    invoke-static {v2, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 268
    .line 269
    .line 270
    move-result v12

    .line 271
    :goto_9
    if-eqz v12, :cond_10

    .line 272
    .line 273
    :goto_a
    const/4 v2, 0x1

    .line 274
    goto :goto_b

    .line 275
    :cond_10
    if-nez v2, :cond_11

    .line 276
    .line 277
    goto :goto_a

    .line 278
    :cond_11
    move/from16 v2, v16

    .line 279
    .line 280
    :goto_b
    if-eqz v2, :cond_24

    .line 281
    .line 282
    :goto_c
    instance-of v2, v3, Lk7/c;

    .line 283
    .line 284
    if-eqz v2, :cond_12

    .line 285
    .line 286
    check-cast v3, Lk7/c;

    .line 287
    .line 288
    iget v2, v3, Lk7/c;->a:F

    .line 289
    .line 290
    invoke-virtual/range {v18 .. v18}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 291
    .line 292
    .line 293
    move-result-object v3

    .line 294
    invoke-virtual {v3}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 295
    .line 296
    .line 297
    move-result-object v3

    .line 298
    const/4 v12, 0x1

    .line 299
    invoke-static {v12, v2, v3}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 300
    .line 301
    .line 302
    move-result v2

    .line 303
    float-to-int v2, v2

    .line 304
    const-string v3, "setHeight"

    .line 305
    .line 306
    invoke-virtual {v1, v4, v3, v2}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 307
    .line 308
    .line 309
    goto :goto_11

    .line 310
    :cond_12
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 311
    .line 312
    .line 313
    move-result v2

    .line 314
    if-eqz v2, :cond_13

    .line 315
    .line 316
    const/4 v2, 0x1

    .line 317
    goto :goto_d

    .line 318
    :cond_13
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 319
    .line 320
    .line 321
    move-result v2

    .line 322
    :goto_d
    if-eqz v2, :cond_14

    .line 323
    .line 324
    const/4 v2, 0x1

    .line 325
    goto :goto_e

    .line 326
    :cond_14
    invoke-static {v3, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    move-result v2

    .line 330
    :goto_e
    if-eqz v2, :cond_15

    .line 331
    .line 332
    :goto_f
    const/4 v2, 0x1

    .line 333
    goto :goto_10

    .line 334
    :cond_15
    if-nez v3, :cond_16

    .line 335
    .line 336
    goto :goto_f

    .line 337
    :cond_16
    move/from16 v2, v16

    .line 338
    .line 339
    :goto_10
    if-eqz v2, :cond_23

    .line 340
    .line 341
    :goto_11
    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 342
    .line 343
    check-cast v0, Lz6/b;

    .line 344
    .line 345
    const-string v2, "GlanceAppWidget"

    .line 346
    .line 347
    if-eqz v0, :cond_19

    .line 348
    .line 349
    iget-object v3, v0, Lz6/b;->a:Lz6/a;

    .line 350
    .line 351
    iget-object v0, v10, La7/e2;->m:Ljava/lang/Integer;

    .line 352
    .line 353
    if-eqz v0, :cond_17

    .line 354
    .line 355
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 356
    .line 357
    .line 358
    move-result v0

    .line 359
    goto :goto_12

    .line 360
    :cond_17
    move v0, v14

    .line 361
    :goto_12
    :try_start_0
    iget-boolean v4, v10, La7/e2;->f:Z

    .line 362
    .line 363
    if-eqz v4, :cond_18

    .line 364
    .line 365
    sget-object v4, Lb7/b;->g:Lb7/b;

    .line 366
    .line 367
    invoke-static {v3, v10, v0, v4}, Lb7/e;->b(Lz6/a;La7/e2;ILay0/k;)Landroid/content/Intent;

    .line 368
    .line 369
    .line 370
    move-result-object v4

    .line 371
    invoke-virtual {v1, v0, v4}, Landroid/widget/RemoteViews;->setOnClickFillInIntent(ILandroid/content/Intent;)V

    .line 372
    .line 373
    .line 374
    goto :goto_14

    .line 375
    :catchall_0
    move-exception v0

    .line 376
    goto :goto_13

    .line 377
    :cond_18
    sget-object v4, Lb7/b;->h:Lb7/b;

    .line 378
    .line 379
    invoke-static {v3, v10, v0, v4}, Lb7/e;->c(Lz6/a;La7/e2;ILay0/k;)Landroid/app/PendingIntent;

    .line 380
    .line 381
    .line 382
    move-result-object v4

    .line 383
    invoke-virtual {v1, v0, v4}, Landroid/widget/RemoteViews;->setOnClickPendingIntent(ILandroid/app/PendingIntent;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 384
    .line 385
    .line 386
    goto :goto_14

    .line 387
    :goto_13
    new-instance v4, Ljava/lang/StringBuilder;

    .line 388
    .line 389
    const-string v5, "Unrecognized Action: "

    .line 390
    .line 391
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 392
    .line 393
    .line 394
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 395
    .line 396
    .line 397
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 398
    .line 399
    .line 400
    move-result-object v3

    .line 401
    invoke-static {v2, v3, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 402
    .line 403
    .line 404
    :cond_19
    :goto_14
    iget-object v0, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 405
    .line 406
    check-cast v0, Lk7/g;

    .line 407
    .line 408
    if-eqz v0, :cond_1b

    .line 409
    .line 410
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 411
    .line 412
    const/16 v15, 0x1f

    .line 413
    .line 414
    if-lt v3, v15, :cond_1a

    .line 415
    .line 416
    sget-object v2, La7/t;->a:La7/t;

    .line 417
    .line 418
    invoke-virtual {v2, v1, v14, v0}, La7/t;->a(Landroid/widget/RemoteViews;ILk7/g;)V

    .line 419
    .line 420
    .line 421
    goto :goto_15

    .line 422
    :cond_1a
    const-string v0, "Cannot set the rounded corner of views before Api 31."

    .line 423
    .line 424
    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 425
    .line 426
    .line 427
    :cond_1b
    :goto_15
    iget-object v0, v7, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 428
    .line 429
    check-cast v0, Lf7/p;

    .line 430
    .line 431
    if-eqz v0, :cond_1e

    .line 432
    .line 433
    invoke-virtual/range {v18 .. v18}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 434
    .line 435
    .line 436
    move-result-object v2

    .line 437
    iget-object v3, v0, Lf7/p;->a:Lf7/o;

    .line 438
    .line 439
    iget v4, v3, Lf7/o;->a:F

    .line 440
    .line 441
    iget-object v3, v3, Lf7/o;->b:Ljava/util/List;

    .line 442
    .line 443
    invoke-static {v3, v2}, Lkp/n7;->a(Ljava/util/List;Landroid/content/res/Resources;)F

    .line 444
    .line 445
    .line 446
    move-result v3

    .line 447
    add-float/2addr v3, v4

    .line 448
    iget-object v4, v0, Lf7/p;->b:Lf7/o;

    .line 449
    .line 450
    iget v5, v4, Lf7/o;->a:F

    .line 451
    .line 452
    iget-object v4, v4, Lf7/o;->b:Ljava/util/List;

    .line 453
    .line 454
    invoke-static {v4, v2}, Lkp/n7;->a(Ljava/util/List;Landroid/content/res/Resources;)F

    .line 455
    .line 456
    .line 457
    move-result v4

    .line 458
    add-float/2addr v4, v5

    .line 459
    iget-object v5, v0, Lf7/p;->c:Lf7/o;

    .line 460
    .line 461
    iget v7, v5, Lf7/o;->a:F

    .line 462
    .line 463
    iget-object v5, v5, Lf7/o;->b:Ljava/util/List;

    .line 464
    .line 465
    invoke-static {v5, v2}, Lkp/n7;->a(Ljava/util/List;Landroid/content/res/Resources;)F

    .line 466
    .line 467
    .line 468
    move-result v5

    .line 469
    add-float/2addr v5, v7

    .line 470
    iget-object v7, v0, Lf7/p;->d:Lf7/o;

    .line 471
    .line 472
    iget v8, v7, Lf7/o;->a:F

    .line 473
    .line 474
    iget-object v7, v7, Lf7/o;->b:Ljava/util/List;

    .line 475
    .line 476
    invoke-static {v7, v2}, Lkp/n7;->a(Ljava/util/List;Landroid/content/res/Resources;)F

    .line 477
    .line 478
    .line 479
    move-result v7

    .line 480
    add-float/2addr v7, v8

    .line 481
    iget-object v8, v0, Lf7/p;->e:Lf7/o;

    .line 482
    .line 483
    iget v9, v8, Lf7/o;->a:F

    .line 484
    .line 485
    iget-object v8, v8, Lf7/o;->b:Ljava/util/List;

    .line 486
    .line 487
    invoke-static {v8, v2}, Lkp/n7;->a(Ljava/util/List;Landroid/content/res/Resources;)F

    .line 488
    .line 489
    .line 490
    move-result v8

    .line 491
    add-float/2addr v8, v9

    .line 492
    iget-object v0, v0, Lf7/p;->f:Lf7/o;

    .line 493
    .line 494
    iget v9, v0, Lf7/o;->a:F

    .line 495
    .line 496
    iget-object v0, v0, Lf7/o;->b:Ljava/util/List;

    .line 497
    .line 498
    invoke-static {v0, v2}, Lkp/n7;->a(Ljava/util/List;Landroid/content/res/Resources;)F

    .line 499
    .line 500
    .line 501
    move-result v0

    .line 502
    add-float/2addr v0, v9

    .line 503
    iget-boolean v2, v10, La7/e2;->c:Z

    .line 504
    .line 505
    if-eqz v2, :cond_1c

    .line 506
    .line 507
    move v9, v8

    .line 508
    goto :goto_16

    .line 509
    :cond_1c
    move v9, v4

    .line 510
    :goto_16
    add-float/2addr v3, v9

    .line 511
    if-eqz v2, :cond_1d

    .line 512
    .line 513
    goto :goto_17

    .line 514
    :cond_1d
    move v4, v8

    .line 515
    :goto_17
    add-float/2addr v7, v4

    .line 516
    invoke-virtual/range {v18 .. v18}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 517
    .line 518
    .line 519
    move-result-object v2

    .line 520
    invoke-virtual {v2}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 521
    .line 522
    .line 523
    move-result-object v2

    .line 524
    iget v4, v6, La7/d1;->a:I

    .line 525
    .line 526
    const/4 v12, 0x1

    .line 527
    invoke-static {v12, v3, v2}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 528
    .line 529
    .line 530
    move-result v3

    .line 531
    float-to-int v3, v3

    .line 532
    invoke-static {v12, v5, v2}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 533
    .line 534
    .line 535
    move-result v5

    .line 536
    float-to-int v5, v5

    .line 537
    invoke-static {v12, v7, v2}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 538
    .line 539
    .line 540
    move-result v6

    .line 541
    float-to-int v6, v6

    .line 542
    invoke-static {v12, v0, v2}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 543
    .line 544
    .line 545
    move-result v0

    .line 546
    float-to-int v0, v0

    .line 547
    move v2, v4

    .line 548
    move v4, v5

    .line 549
    move v5, v6

    .line 550
    move v6, v0

    .line 551
    invoke-virtual/range {v1 .. v6}, Landroid/widget/RemoteViews;->setViewPadding(IIIII)V

    .line 552
    .line 553
    .line 554
    :cond_1e
    iget-object v0, v11, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 555
    .line 556
    if-nez v0, :cond_22

    .line 557
    .line 558
    move-object/from16 v12, v17

    .line 559
    .line 560
    iget-object v0, v12, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 561
    .line 562
    check-cast v0, La7/e0;

    .line 563
    .line 564
    move-object/from16 v13, v20

    .line 565
    .line 566
    iget-object v0, v13, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 567
    .line 568
    check-cast v0, Lg7/a;

    .line 569
    .line 570
    move-object/from16 v8, v19

    .line 571
    .line 572
    iget-object v0, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 573
    .line 574
    check-cast v0, Ly6/u;

    .line 575
    .line 576
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 577
    .line 578
    .line 579
    move-result v0

    .line 580
    if-eqz v0, :cond_1f

    .line 581
    .line 582
    const/4 v12, 0x1

    .line 583
    if-eq v0, v12, :cond_21

    .line 584
    .line 585
    const/4 v2, 0x2

    .line 586
    if-ne v0, v2, :cond_20

    .line 587
    .line 588
    const/16 v16, 0x8

    .line 589
    .line 590
    :cond_1f
    :goto_18
    move/from16 v0, v16

    .line 591
    .line 592
    goto :goto_19

    .line 593
    :cond_20
    new-instance v0, La8/r0;

    .line 594
    .line 595
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 596
    .line 597
    .line 598
    throw v0

    .line 599
    :cond_21
    const/16 v16, 0x4

    .line 600
    .line 601
    goto :goto_18

    .line 602
    :goto_19
    invoke-virtual {v1, v14, v0}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 603
    .line 604
    .line 605
    return-void

    .line 606
    :cond_22
    new-instance v0, Ljava/lang/ClassCastException;

    .line 607
    .line 608
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 609
    .line 610
    .line 611
    throw v0

    .line 612
    :cond_23
    new-instance v0, La8/r0;

    .line 613
    .line 614
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 615
    .line 616
    .line 617
    throw v0

    .line 618
    :cond_24
    new-instance v0, La8/r0;

    .line 619
    .line 620
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 621
    .line 622
    .line 623
    throw v0

    .line 624
    :cond_25
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 625
    .line 626
    const-string v1, "There is currently no valid use case where a complex view is used on Android S"

    .line 627
    .line 628
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 629
    .line 630
    .line 631
    throw v0
.end method

.method public static final c(Landroid/widget/RemoteViews;Lf7/n;I)V
    .locals 7

    .line 1
    iget-object p1, p1, Lf7/n;->a:Lk7/g;

    .line 2
    .line 3
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 4
    .line 5
    const/16 v1, 0x1f

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    const/4 v3, 0x1

    .line 9
    const/4 v4, 0x0

    .line 10
    sget-object v5, Lk7/d;->a:Lk7/d;

    .line 11
    .line 12
    sget-object v6, Lk7/f;->a:Lk7/f;

    .line 13
    .line 14
    if-ge v0, v1, :cond_1

    .line 15
    .line 16
    const/4 p0, 0x3

    .line 17
    new-array p0, p0, [Lk7/g;

    .line 18
    .line 19
    aput-object v6, p0, v4

    .line 20
    .line 21
    sget-object p2, Lk7/e;->a:Lk7/e;

    .line 22
    .line 23
    aput-object p2, p0, v3

    .line 24
    .line 25
    aput-object v5, p0, v2

    .line 26
    .line 27
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    sget-object p2, La7/j1;->a:Ljava/lang/Object;

    .line 32
    .line 33
    invoke-interface {p0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-eqz p0, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 41
    .line 42
    new-instance p2, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string v0, "Using a height of "

    .line 45
    .line 46
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string p1, " requires a complex layout before API 31"

    .line 53
    .line 54
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_1
    const/16 v1, 0x21

    .line 66
    .line 67
    if-ge v0, v1, :cond_2

    .line 68
    .line 69
    new-array v0, v2, [Lk7/g;

    .line 70
    .line 71
    aput-object v6, v0, v4

    .line 72
    .line 73
    aput-object v5, v0, v3

    .line 74
    .line 75
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-interface {v0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    if-eqz v0, :cond_2

    .line 84
    .line 85
    :goto_0
    return-void

    .line 86
    :cond_2
    sget-object v0, La7/t;->a:La7/t;

    .line 87
    .line 88
    invoke-virtual {v0, p0, p2, p1}, La7/t;->b(Landroid/widget/RemoteViews;ILk7/g;)V

    .line 89
    .line 90
    .line 91
    return-void
.end method

.method public static final d(Landroid/widget/RemoteViews;Lf7/t;I)V
    .locals 7

    .line 1
    iget-object p1, p1, Lf7/t;->a:Lk7/g;

    .line 2
    .line 3
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 4
    .line 5
    const/16 v1, 0x1f

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    const/4 v3, 0x1

    .line 9
    const/4 v4, 0x0

    .line 10
    sget-object v5, Lk7/d;->a:Lk7/d;

    .line 11
    .line 12
    sget-object v6, Lk7/f;->a:Lk7/f;

    .line 13
    .line 14
    if-ge v0, v1, :cond_1

    .line 15
    .line 16
    const/4 p0, 0x3

    .line 17
    new-array p0, p0, [Lk7/g;

    .line 18
    .line 19
    aput-object v6, p0, v4

    .line 20
    .line 21
    sget-object p2, Lk7/e;->a:Lk7/e;

    .line 22
    .line 23
    aput-object p2, p0, v3

    .line 24
    .line 25
    aput-object v5, p0, v2

    .line 26
    .line 27
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    sget-object p2, La7/j1;->a:Ljava/lang/Object;

    .line 32
    .line 33
    invoke-interface {p0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-eqz p0, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 41
    .line 42
    new-instance p2, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string v0, "Using a width of "

    .line 45
    .line 46
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string p1, " requires a complex layout before API 31"

    .line 53
    .line 54
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_1
    const/16 v1, 0x21

    .line 66
    .line 67
    if-ge v0, v1, :cond_2

    .line 68
    .line 69
    new-array v0, v2, [Lk7/g;

    .line 70
    .line 71
    aput-object v6, v0, v4

    .line 72
    .line 73
    aput-object v5, v0, v3

    .line 74
    .line 75
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-interface {v0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    if-eqz v0, :cond_2

    .line 84
    .line 85
    :goto_0
    return-void

    .line 86
    :cond_2
    sget-object v0, La7/t;->a:La7/t;

    .line 87
    .line 88
    invoke-virtual {v0, p0, p2, p1}, La7/t;->c(Landroid/widget/RemoteViews;ILk7/g;)V

    .line 89
    .line 90
    .line 91
    return-void
.end method

.method public static final e(Lv3/m;)Lw1/c;
    .locals 13

    .line 1
    new-instance v2, Lv1/a;

    .line 2
    .line 3
    invoke-direct {v2}, Lv1/a;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ly21/d;

    .line 7
    .line 8
    const/4 v6, 0x0

    .line 9
    const/16 v7, 0xc

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    const-class v3, Lv1/a;

    .line 13
    .line 14
    const-string v4, "addFilter"

    .line 15
    .line 16
    const-string v5, "addFilter$foundation_release(Lkotlin/jvm/functions/Function1;)V"

    .line 17
    .line 18
    invoke-direct/range {v0 .. v7}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 19
    .line 20
    .line 21
    new-instance v1, Lyp0/d;

    .line 22
    .line 23
    const/4 v3, 0x4

    .line 24
    invoke-direct {v1, v2, v3}, Lyp0/d;-><init>(Ljava/lang/Object;I)V

    .line 25
    .line 26
    .line 27
    new-instance v3, Lyp0/d;

    .line 28
    .line 29
    const/4 v4, 0x5

    .line 30
    invoke-direct {v3, v4, v1, v0}, Lyp0/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    sget-object v0, Lz1/c;->a:Lz1/c;

    .line 34
    .line 35
    invoke-static {p0, v0, v3}, Lv3/f;->A(Lv3/m;Ljava/lang/Object;Lay0/k;)V

    .line 36
    .line 37
    .line 38
    new-instance p0, Landroidx/collection/l0;

    .line 39
    .line 40
    invoke-direct {p0}, Landroidx/collection/l0;-><init>()V

    .line 41
    .line 42
    .line 43
    iget-object v0, v2, Lv1/a;->a:Landroidx/collection/l0;

    .line 44
    .line 45
    iget-object v1, v0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 46
    .line 47
    iget v0, v0, Landroidx/collection/l0;->b:I

    .line 48
    .line 49
    const/4 v3, 0x0

    .line 50
    const/4 v4, 0x1

    .line 51
    const/4 v5, 0x0

    .line 52
    move v6, v3

    .line 53
    move v7, v4

    .line 54
    move-object v8, v5

    .line 55
    :goto_0
    sget-object v9, Lw1/f;->b:Lw1/f;

    .line 56
    .line 57
    if-ge v6, v0, :cond_6

    .line 58
    .line 59
    aget-object v10, v1, v6

    .line 60
    .line 61
    check-cast v10, Lw1/b;

    .line 62
    .line 63
    if-eqz v7, :cond_0

    .line 64
    .line 65
    if-eq v10, v9, :cond_5

    .line 66
    .line 67
    :cond_0
    if-ne v10, v9, :cond_1

    .line 68
    .line 69
    if-ne v8, v9, :cond_1

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_1
    if-ne v10, v9, :cond_2

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_2
    iget-object v7, v2, Lv1/a;->b:Landroidx/collection/l0;

    .line 76
    .line 77
    iget-object v9, v7, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 78
    .line 79
    iget v7, v7, Landroidx/collection/l0;->b:I

    .line 80
    .line 81
    move v11, v3

    .line 82
    :goto_1
    if-ge v11, v7, :cond_4

    .line 83
    .line 84
    aget-object v12, v9, v11

    .line 85
    .line 86
    check-cast v12, Lay0/k;

    .line 87
    .line 88
    invoke-interface {v12, v10}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v12

    .line 92
    check-cast v12, Ljava/lang/Boolean;

    .line 93
    .line 94
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    .line 95
    .line 96
    .line 97
    move-result v12

    .line 98
    if-nez v12, :cond_3

    .line 99
    .line 100
    :goto_2
    move v7, v3

    .line 101
    goto :goto_4

    .line 102
    :cond_3
    add-int/lit8 v11, v11, 0x1

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_4
    :goto_3
    invoke-virtual {p0, v10}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    move v7, v3

    .line 109
    move-object v8, v10

    .line 110
    :cond_5
    :goto_4
    add-int/lit8 v6, v6, 0x1

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_6
    invoke-virtual {p0}, Landroidx/collection/l0;->g()Z

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-eqz v0, :cond_7

    .line 118
    .line 119
    goto :goto_5

    .line 120
    :cond_7
    iget-object v0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 121
    .line 122
    iget v1, p0, Landroidx/collection/l0;->b:I

    .line 123
    .line 124
    sub-int/2addr v1, v4

    .line 125
    aget-object v5, v0, v1

    .line 126
    .line 127
    :goto_5
    check-cast v5, Lw1/b;

    .line 128
    .line 129
    if-ne v5, v9, :cond_8

    .line 130
    .line 131
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 132
    .line 133
    sub-int/2addr v0, v4

    .line 134
    invoke-virtual {p0, v0}, Landroidx/collection/l0;->j(I)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    :cond_8
    new-instance v0, Lw1/c;

    .line 138
    .line 139
    iget-object v1, p0, Landroidx/collection/l0;->c:Landroidx/collection/j0;

    .line 140
    .line 141
    if-eqz v1, :cond_9

    .line 142
    .line 143
    goto :goto_6

    .line 144
    :cond_9
    new-instance v1, Landroidx/collection/j0;

    .line 145
    .line 146
    const/4 v2, 0x0

    .line 147
    invoke-direct {v1, p0, v2}, Landroidx/collection/j0;-><init>(Ljava/lang/Object;I)V

    .line 148
    .line 149
    .line 150
    iput-object v1, p0, Landroidx/collection/l0;->c:Landroidx/collection/j0;

    .line 151
    .line 152
    :goto_6
    invoke-direct {v0, v1}, Lw1/c;-><init>(Ljava/util/List;)V

    .line 153
    .line 154
    .line 155
    return-object v0
.end method

.method public static final f(Lk7/g;)Z
    .locals 3

    .line 1
    instance-of v0, p0, Lk7/c;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    sget-object v0, Lk7/d;->a:Lk7/d;

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    move v0, v1

    .line 16
    goto :goto_0

    .line 17
    :cond_1
    sget-object v0, Lk7/e;->a:Lk7/e;

    .line 18
    .line 19
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    :goto_0
    if-eqz v0, :cond_2

    .line 24
    .line 25
    move v0, v1

    .line 26
    goto :goto_1

    .line 27
    :cond_2
    sget-object v0, Lk7/f;->a:Lk7/f;

    .line 28
    .line 29
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    :goto_1
    const/4 v2, 0x0

    .line 34
    if-eqz v0, :cond_3

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_3
    if-nez p0, :cond_4

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_4
    move v1, v2

    .line 41
    :goto_2
    if-eqz v1, :cond_5

    .line 42
    .line 43
    return v2

    .line 44
    :cond_5
    new-instance p0, La8/r0;

    .line 45
    .line 46
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 47
    .line 48
    .line 49
    throw p0
.end method
