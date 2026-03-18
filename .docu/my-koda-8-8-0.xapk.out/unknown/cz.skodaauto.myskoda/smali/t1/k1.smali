.class public final Lt1/k1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ll2/j1;

.field public b:Lg4/g;

.field public final c:Lv2/o;


# direct methods
.method public constructor <init>(Lg4/g;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iput-object v1, v0, Lt1/k1;->a:Ll2/j1;

    .line 12
    .line 13
    new-instance v1, Lsb/a;

    .line 14
    .line 15
    const/16 v2, 0x17

    .line 16
    .line 17
    invoke-direct {v1, v2}, Lsb/a;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    new-instance v2, Lg4/d;

    .line 24
    .line 25
    move-object/from16 v3, p1

    .line 26
    .line 27
    invoke-direct {v2, v3}, Lg4/d;-><init>(Lg4/g;)V

    .line 28
    .line 29
    .line 30
    new-instance v3, Ljava/util/ArrayList;

    .line 31
    .line 32
    iget-object v4, v2, Lg4/d;->f:Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 39
    .line 40
    .line 41
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    const/4 v7, 0x0

    .line 46
    :goto_0
    if-ge v7, v5, :cond_1

    .line 47
    .line 48
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v8

    .line 52
    check-cast v8, Lg4/c;

    .line 53
    .line 54
    const/high16 v9, -0x80000000

    .line 55
    .line 56
    invoke-virtual {v8, v9}, Lg4/c;->a(I)Lg4/e;

    .line 57
    .line 58
    .line 59
    move-result-object v8

    .line 60
    invoke-virtual {v1, v8}, Lsb/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v8

    .line 64
    check-cast v8, Ljava/util/List;

    .line 65
    .line 66
    new-instance v9, Ljava/util/ArrayList;

    .line 67
    .line 68
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 69
    .line 70
    .line 71
    move-result v10

    .line 72
    invoke-direct {v9, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 73
    .line 74
    .line 75
    move-object v10, v8

    .line 76
    check-cast v10, Ljava/util/Collection;

    .line 77
    .line 78
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 79
    .line 80
    .line 81
    move-result v10

    .line 82
    const/4 v11, 0x0

    .line 83
    :goto_1
    if-ge v11, v10, :cond_0

    .line 84
    .line 85
    invoke-interface {v8, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v12

    .line 89
    check-cast v12, Lg4/e;

    .line 90
    .line 91
    new-instance v13, Lg4/c;

    .line 92
    .line 93
    iget-object v14, v12, Lg4/e;->a:Ljava/lang/Object;

    .line 94
    .line 95
    iget v15, v12, Lg4/e;->b:I

    .line 96
    .line 97
    iget v6, v12, Lg4/e;->c:I

    .line 98
    .line 99
    iget-object v12, v12, Lg4/e;->d:Ljava/lang/String;

    .line 100
    .line 101
    invoke-direct {v13, v14, v15, v6, v12}, Lg4/c;-><init>(Ljava/lang/Object;IILjava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v9, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    add-int/lit8 v11, v11, 0x1

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_0
    invoke-static {v9, v3}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 111
    .line 112
    .line 113
    add-int/lit8 v7, v7, 0x1

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_1
    invoke-virtual {v4}, Ljava/util/ArrayList;->clear()V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 120
    .line 121
    .line 122
    invoke-virtual {v2}, Lg4/d;->j()Lg4/g;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    iput-object v1, v0, Lt1/k1;->b:Lg4/g;

    .line 127
    .line 128
    new-instance v1, Lv2/o;

    .line 129
    .line 130
    invoke-direct {v1}, Lv2/o;-><init>()V

    .line 131
    .line 132
    .line 133
    iput-object v1, v0, Lt1/k1;->c:Lv2/o;

    .line 134
    .line 135
    return-void
.end method

.method public static c(Lg4/e;Lg4/l0;)Lg4/e;
    .locals 2

    .line 1
    iget-object p1, p1, Lg4/l0;->b:Lg4/o;

    .line 2
    .line 3
    iget v0, p1, Lg4/o;->f:I

    .line 4
    .line 5
    add-int/lit8 v0, v0, -0x1

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-virtual {p1, v0, v1}, Lg4/o;->c(IZ)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget v0, p0, Lg4/e;->b:I

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    if-ge v0, p1, :cond_0

    .line 16
    .line 17
    iget v0, p0, Lg4/e;->c:I

    .line 18
    .line 19
    invoke-static {v0, p1}, Ljava/lang/Math;->min(II)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    const/16 v0, 0xb

    .line 24
    .line 25
    invoke-static {p0, v1, p1, v0}, Lg4/e;->a(Lg4/e;Lg4/b;II)Lg4/e;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_0
    return-object v1
.end method


# virtual methods
.method public final a(Ll2/o;I)V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p1

    .line 6
    .line 7
    check-cast v2, Ll2/t;

    .line 8
    .line 9
    const v3, 0x44d294da

    .line 10
    .line 11
    .line 12
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const/4 v5, 0x2

    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    const/4 v3, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v5

    .line 25
    :goto_0
    or-int/2addr v3, v1

    .line 26
    and-int/lit8 v6, v3, 0x3

    .line 27
    .line 28
    const/4 v8, 0x0

    .line 29
    if-eq v6, v5, :cond_1

    .line 30
    .line 31
    const/4 v6, 0x1

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v6, v8

    .line 34
    :goto_1
    and-int/lit8 v9, v3, 0x1

    .line 35
    .line 36
    invoke-virtual {v2, v9, v6}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    if-eqz v6, :cond_14

    .line 41
    .line 42
    sget-object v6, Lw3/h1;->r:Ll2/u2;

    .line 43
    .line 44
    invoke-virtual {v2, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    check-cast v6, Lw3/r0;

    .line 49
    .line 50
    iget-object v9, v0, Lt1/k1;->b:Lg4/g;

    .line 51
    .line 52
    iget-object v10, v9, Lg4/g;->e:Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {v10}, Ljava/lang/String;->length()I

    .line 55
    .line 56
    .line 57
    move-result v10

    .line 58
    invoke-virtual {v9, v10}, Lg4/g;->a(I)Ljava/util/List;

    .line 59
    .line 60
    .line 61
    move-result-object v9

    .line 62
    move-object v10, v9

    .line 63
    check-cast v10, Ljava/util/Collection;

    .line 64
    .line 65
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 66
    .line 67
    .line 68
    move-result v10

    .line 69
    move v11, v8

    .line 70
    :goto_2
    if-ge v11, v10, :cond_15

    .line 71
    .line 72
    invoke-interface {v9, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v12

    .line 76
    check-cast v12, Lg4/e;

    .line 77
    .line 78
    iget v13, v12, Lg4/e;->b:I

    .line 79
    .line 80
    iget-object v14, v12, Lg4/e;->a:Ljava/lang/Object;

    .line 81
    .line 82
    iget v15, v12, Lg4/e;->c:I

    .line 83
    .line 84
    if-eq v13, v15, :cond_13

    .line 85
    .line 86
    const v13, 0x2b3dee17

    .line 87
    .line 88
    .line 89
    invoke-virtual {v2, v13}, Ll2/t;->Y(I)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v13

    .line 96
    sget-object v15, Ll2/n;->a:Ll2/x0;

    .line 97
    .line 98
    if-ne v13, v15, :cond_2

    .line 99
    .line 100
    invoke-static {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 101
    .line 102
    .line 103
    move-result-object v13

    .line 104
    :cond_2
    check-cast v13, Li1/l;

    .line 105
    .line 106
    const/16 p1, 0x4

    .line 107
    .line 108
    new-instance v4, Lod0/n;

    .line 109
    .line 110
    move/from16 v16, v5

    .line 111
    .line 112
    const/16 v5, 0x19

    .line 113
    .line 114
    invoke-direct {v4, v5, v0, v12}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 118
    .line 119
    invoke-static {v5, v4}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 120
    .line 121
    .line 122
    move-result-object v4

    .line 123
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v5

    .line 127
    if-ne v5, v15, :cond_3

    .line 128
    .line 129
    new-instance v5, Lsb/a;

    .line 130
    .line 131
    const/16 v17, 0x1

    .line 132
    .line 133
    const/16 v7, 0x18

    .line 134
    .line 135
    invoke-direct {v5, v7}, Lsb/a;-><init>(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    goto :goto_3

    .line 142
    :cond_3
    const/16 v17, 0x1

    .line 143
    .line 144
    :goto_3
    check-cast v5, Lay0/k;

    .line 145
    .line 146
    invoke-static {v4, v8, v5}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 147
    .line 148
    .line 149
    move-result-object v4

    .line 150
    new-instance v5, Lt1/m1;

    .line 151
    .line 152
    new-instance v7, La0/h;

    .line 153
    .line 154
    const/16 v8, 0x18

    .line 155
    .line 156
    invoke-direct {v7, v8, v0, v12}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    invoke-direct {v5, v7}, Lt1/m1;-><init>(La0/h;)V

    .line 160
    .line 161
    .line 162
    invoke-interface {v4, v5}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 163
    .line 164
    .line 165
    move-result-object v4

    .line 166
    invoke-static {v4, v13}, Landroidx/compose/foundation/a;->j(Lx2/s;Li1/l;)Lx2/s;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    sget-object v5, Lp3/q;->a:Lp3/p;

    .line 171
    .line 172
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    sget-object v5, Lp3/s;->c:Lp3/a;

    .line 176
    .line 177
    invoke-static {v4, v5}, Lp3/s;->g(Lx2/s;Lp3/a;)Lx2/s;

    .line 178
    .line 179
    .line 180
    move-result-object v4

    .line 181
    invoke-virtual {v2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v5

    .line 185
    invoke-virtual {v2, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v7

    .line 189
    or-int/2addr v5, v7

    .line 190
    invoke-virtual {v2, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v7

    .line 194
    or-int/2addr v5, v7

    .line 195
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v7

    .line 199
    if-nez v5, :cond_4

    .line 200
    .line 201
    if-ne v7, v15, :cond_5

    .line 202
    .line 203
    :cond_4
    new-instance v7, Lo51/c;

    .line 204
    .line 205
    invoke-direct {v7, v0, v12, v6}, Lo51/c;-><init>(Lt1/k1;Lg4/e;Lw3/r0;)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v2, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    :cond_5
    check-cast v7, Lay0/a;

    .line 212
    .line 213
    invoke-static {v4, v13, v7}, Landroidx/compose/foundation/a;->g(Lx2/s;Li1/l;Lay0/a;)Lx2/s;

    .line 214
    .line 215
    .line 216
    move-result-object v4

    .line 217
    const/4 v5, 0x0

    .line 218
    invoke-static {v4, v2, v5}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 219
    .line 220
    .line 221
    check-cast v14, Lg4/n;

    .line 222
    .line 223
    invoke-virtual {v14}, Lg4/n;->b()Lg4/m0;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    if-eqz v4, :cond_6

    .line 228
    .line 229
    iget-object v5, v4, Lg4/m0;->a:Lg4/g0;

    .line 230
    .line 231
    if-nez v5, :cond_7

    .line 232
    .line 233
    iget-object v5, v4, Lg4/m0;->b:Lg4/g0;

    .line 234
    .line 235
    if-nez v5, :cond_7

    .line 236
    .line 237
    iget-object v5, v4, Lg4/m0;->c:Lg4/g0;

    .line 238
    .line 239
    if-nez v5, :cond_7

    .line 240
    .line 241
    iget-object v4, v4, Lg4/m0;->d:Lg4/g0;

    .line 242
    .line 243
    if-nez v4, :cond_7

    .line 244
    .line 245
    :cond_6
    const/4 v5, 0x0

    .line 246
    goto/16 :goto_a

    .line 247
    .line 248
    :cond_7
    const v4, 0x2b4a813f

    .line 249
    .line 250
    .line 251
    invoke-virtual {v2, v4}, Ll2/t;->Y(I)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v4

    .line 258
    if-ne v4, v15, :cond_8

    .line 259
    .line 260
    new-instance v4, Lt1/q0;

    .line 261
    .line 262
    invoke-direct {v4, v13}, Lt1/q0;-><init>(Li1/l;)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v2, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    :cond_8
    check-cast v4, Lt1/q0;

    .line 269
    .line 270
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v5

    .line 274
    const/4 v7, 0x0

    .line 275
    if-ne v5, v15, :cond_9

    .line 276
    .line 277
    new-instance v5, Lrp0/a;

    .line 278
    .line 279
    const/16 v8, 0xb

    .line 280
    .line 281
    invoke-direct {v5, v4, v7, v8}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    :cond_9
    check-cast v5, Lay0/n;

    .line 288
    .line 289
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 290
    .line 291
    invoke-static {v5, v8, v2}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 292
    .line 293
    .line 294
    iget-object v5, v4, Lt1/q0;->b:Ll2/g1;

    .line 295
    .line 296
    iget-object v8, v4, Lt1/q0;->b:Ll2/g1;

    .line 297
    .line 298
    invoke-virtual {v5}, Ll2/g1;->o()I

    .line 299
    .line 300
    .line 301
    move-result v5

    .line 302
    and-int/lit8 v5, v5, 0x2

    .line 303
    .line 304
    if-eqz v5, :cond_a

    .line 305
    .line 306
    move/from16 v5, v17

    .line 307
    .line 308
    goto :goto_4

    .line 309
    :cond_a
    const/4 v5, 0x0

    .line 310
    :goto_4
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 311
    .line 312
    .line 313
    move-result-object v18

    .line 314
    invoke-virtual {v8}, Ll2/g1;->o()I

    .line 315
    .line 316
    .line 317
    move-result v5

    .line 318
    and-int/lit8 v5, v5, 0x1

    .line 319
    .line 320
    if-eqz v5, :cond_b

    .line 321
    .line 322
    move/from16 v5, v17

    .line 323
    .line 324
    goto :goto_5

    .line 325
    :cond_b
    const/4 v5, 0x0

    .line 326
    :goto_5
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 327
    .line 328
    .line 329
    move-result-object v19

    .line 330
    invoke-virtual {v8}, Ll2/g1;->o()I

    .line 331
    .line 332
    .line 333
    move-result v5

    .line 334
    and-int/lit8 v5, v5, 0x4

    .line 335
    .line 336
    if-eqz v5, :cond_c

    .line 337
    .line 338
    move/from16 v5, v17

    .line 339
    .line 340
    goto :goto_6

    .line 341
    :cond_c
    const/4 v5, 0x0

    .line 342
    :goto_6
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 343
    .line 344
    .line 345
    move-result-object v20

    .line 346
    invoke-virtual {v14}, Lg4/n;->b()Lg4/m0;

    .line 347
    .line 348
    .line 349
    move-result-object v5

    .line 350
    if-eqz v5, :cond_d

    .line 351
    .line 352
    iget-object v5, v5, Lg4/m0;->a:Lg4/g0;

    .line 353
    .line 354
    move-object/from16 v21, v5

    .line 355
    .line 356
    goto :goto_7

    .line 357
    :cond_d
    move-object/from16 v21, v7

    .line 358
    .line 359
    :goto_7
    invoke-virtual {v14}, Lg4/n;->b()Lg4/m0;

    .line 360
    .line 361
    .line 362
    move-result-object v5

    .line 363
    if-eqz v5, :cond_e

    .line 364
    .line 365
    iget-object v5, v5, Lg4/m0;->b:Lg4/g0;

    .line 366
    .line 367
    move-object/from16 v22, v5

    .line 368
    .line 369
    goto :goto_8

    .line 370
    :cond_e
    move-object/from16 v22, v7

    .line 371
    .line 372
    :goto_8
    invoke-virtual {v14}, Lg4/n;->b()Lg4/m0;

    .line 373
    .line 374
    .line 375
    move-result-object v5

    .line 376
    if-eqz v5, :cond_f

    .line 377
    .line 378
    iget-object v5, v5, Lg4/m0;->c:Lg4/g0;

    .line 379
    .line 380
    move-object/from16 v23, v5

    .line 381
    .line 382
    goto :goto_9

    .line 383
    :cond_f
    move-object/from16 v23, v7

    .line 384
    .line 385
    :goto_9
    invoke-virtual {v14}, Lg4/n;->b()Lg4/m0;

    .line 386
    .line 387
    .line 388
    move-result-object v5

    .line 389
    if-eqz v5, :cond_10

    .line 390
    .line 391
    iget-object v7, v5, Lg4/m0;->d:Lg4/g0;

    .line 392
    .line 393
    :cond_10
    move-object/from16 v24, v7

    .line 394
    .line 395
    filled-new-array/range {v18 .. v24}, [Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v5

    .line 399
    invoke-virtual {v2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 400
    .line 401
    .line 402
    move-result v7

    .line 403
    invoke-virtual {v2, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 404
    .line 405
    .line 406
    move-result v8

    .line 407
    or-int/2addr v7, v8

    .line 408
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v8

    .line 412
    if-nez v7, :cond_11

    .line 413
    .line 414
    if-ne v8, v15, :cond_12

    .line 415
    .line 416
    :cond_11
    new-instance v8, Lod0/n;

    .line 417
    .line 418
    invoke-direct {v8, v0, v12, v4}, Lod0/n;-><init>(Lt1/k1;Lg4/e;Lt1/q0;)V

    .line 419
    .line 420
    .line 421
    invoke-virtual {v2, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 422
    .line 423
    .line 424
    :cond_12
    check-cast v8, Lay0/k;

    .line 425
    .line 426
    shl-int/lit8 v4, v3, 0x6

    .line 427
    .line 428
    and-int/lit16 v4, v4, 0x380

    .line 429
    .line 430
    invoke-virtual {v0, v5, v8, v2, v4}, Lt1/k1;->b([Ljava/lang/Object;Lay0/k;Ll2/o;I)V

    .line 431
    .line 432
    .line 433
    const/4 v5, 0x0

    .line 434
    invoke-virtual {v2, v5}, Ll2/t;->q(Z)V

    .line 435
    .line 436
    .line 437
    goto :goto_b

    .line 438
    :goto_a
    const v4, 0x2b6975be

    .line 439
    .line 440
    .line 441
    invoke-virtual {v2, v4}, Ll2/t;->Y(I)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {v2, v5}, Ll2/t;->q(Z)V

    .line 445
    .line 446
    .line 447
    :goto_b
    invoke-virtual {v2, v5}, Ll2/t;->q(Z)V

    .line 448
    .line 449
    .line 450
    goto :goto_c

    .line 451
    :cond_13
    move/from16 v16, v5

    .line 452
    .line 453
    move v5, v8

    .line 454
    const/16 p1, 0x4

    .line 455
    .line 456
    const/16 v17, 0x1

    .line 457
    .line 458
    const v4, 0x2b69abfe

    .line 459
    .line 460
    .line 461
    invoke-virtual {v2, v4}, Ll2/t;->Y(I)V

    .line 462
    .line 463
    .line 464
    invoke-virtual {v2, v5}, Ll2/t;->q(Z)V

    .line 465
    .line 466
    .line 467
    :goto_c
    add-int/lit8 v11, v11, 0x1

    .line 468
    .line 469
    move v8, v5

    .line 470
    move/from16 v5, v16

    .line 471
    .line 472
    goto/16 :goto_2

    .line 473
    .line 474
    :cond_14
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 475
    .line 476
    .line 477
    :cond_15
    invoke-virtual {v2}, Ll2/t;->s()Ll2/u1;

    .line 478
    .line 479
    .line 480
    move-result-object v2

    .line 481
    if-eqz v2, :cond_16

    .line 482
    .line 483
    new-instance v3, Llk/c;

    .line 484
    .line 485
    const/16 v4, 0x1b

    .line 486
    .line 487
    invoke-direct {v3, v0, v1, v4}, Llk/c;-><init>(Ljava/lang/Object;II)V

    .line 488
    .line 489
    .line 490
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 491
    .line 492
    :cond_16
    return-void
.end method

.method public final b([Ljava/lang/Object;Lay0/k;Ll2/o;I)V
    .locals 7

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, -0x7c28da43

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x30

    .line 10
    .line 11
    const/16 v1, 0x20

    .line 12
    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    move v0, v1

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/16 v0, 0x10

    .line 24
    .line 25
    :goto_0
    or-int/2addr v0, p4

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move v0, p4

    .line 28
    :goto_1
    and-int/lit16 v2, p4, 0x180

    .line 29
    .line 30
    if-nez v2, :cond_3

    .line 31
    .line 32
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_2

    .line 37
    .line 38
    const/16 v2, 0x100

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    const/16 v2, 0x80

    .line 42
    .line 43
    :goto_2
    or-int/2addr v0, v2

    .line 44
    :cond_3
    array-length v2, p1

    .line 45
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    const v3, -0x155b4ff2

    .line 50
    .line 51
    .line 52
    invoke-virtual {p3, v3, v2}, Ll2/t;->V(ILjava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    array-length v2, p1

    .line 56
    invoke-virtual {p3, v2}, Ll2/t;->e(I)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    const/4 v3, 0x4

    .line 61
    const/4 v4, 0x0

    .line 62
    if-eqz v2, :cond_4

    .line 63
    .line 64
    move v2, v3

    .line 65
    goto :goto_3

    .line 66
    :cond_4
    move v2, v4

    .line 67
    :goto_3
    or-int/2addr v0, v2

    .line 68
    array-length v2, p1

    .line 69
    move v5, v4

    .line 70
    :goto_4
    if-ge v5, v2, :cond_6

    .line 71
    .line 72
    aget-object v6, p1, v5

    .line 73
    .line 74
    invoke-virtual {p3, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    if-eqz v6, :cond_5

    .line 79
    .line 80
    move v6, v3

    .line 81
    goto :goto_5

    .line 82
    :cond_5
    move v6, v4

    .line 83
    :goto_5
    or-int/2addr v0, v6

    .line 84
    add-int/lit8 v5, v5, 0x1

    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_6
    invoke-virtual {p3, v4}, Ll2/t;->q(Z)V

    .line 88
    .line 89
    .line 90
    and-int/lit8 v2, v0, 0xe

    .line 91
    .line 92
    if-nez v2, :cond_7

    .line 93
    .line 94
    or-int/lit8 v0, v0, 0x2

    .line 95
    .line 96
    :cond_7
    and-int/lit16 v2, v0, 0x93

    .line 97
    .line 98
    const/16 v3, 0x92

    .line 99
    .line 100
    const/4 v5, 0x1

    .line 101
    if-eq v2, v3, :cond_8

    .line 102
    .line 103
    move v2, v5

    .line 104
    goto :goto_6

    .line 105
    :cond_8
    move v2, v4

    .line 106
    :goto_6
    and-int/lit8 v3, v0, 0x1

    .line 107
    .line 108
    invoke-virtual {p3, v3, v2}, Ll2/t;->O(IZ)Z

    .line 109
    .line 110
    .line 111
    move-result v2

    .line 112
    if-eqz v2, :cond_c

    .line 113
    .line 114
    new-instance v2, Ld01/x;

    .line 115
    .line 116
    const/4 v3, 0x2

    .line 117
    invoke-direct {v2, v3}, Ld01/x;-><init>(I)V

    .line 118
    .line 119
    .line 120
    iget-object v3, v2, Ld01/x;->b:Ljava/util/ArrayList;

    .line 121
    .line 122
    invoke-virtual {v2, p2}, Ld01/x;->b(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v2, p1}, Ld01/x;->g(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    new-array v2, v2, [Ljava/lang/Object;

    .line 133
    .line 134
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v3

    .line 142
    and-int/lit8 v0, v0, 0x70

    .line 143
    .line 144
    if-ne v0, v1, :cond_9

    .line 145
    .line 146
    move v4, v5

    .line 147
    :cond_9
    or-int v0, v3, v4

    .line 148
    .line 149
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    if-nez v0, :cond_a

    .line 154
    .line 155
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 156
    .line 157
    if-ne v1, v0, :cond_b

    .line 158
    .line 159
    :cond_a
    new-instance v1, Lt1/k;

    .line 160
    .line 161
    const/4 v0, 0x1

    .line 162
    invoke-direct {v1, p0, p2, v0}, Lt1/k;-><init>(Lt1/k1;Lay0/k;I)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {p3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    :cond_b
    check-cast v1, Lay0/k;

    .line 169
    .line 170
    invoke-static {v2, v1, p3}, Ll2/l0;->c([Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    goto :goto_7

    .line 174
    :cond_c
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 175
    .line 176
    .line 177
    :goto_7
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 178
    .line 179
    .line 180
    move-result-object p3

    .line 181
    if-eqz p3, :cond_d

    .line 182
    .line 183
    new-instance v0, Lph/a;

    .line 184
    .line 185
    const/4 v2, 0x6

    .line 186
    move-object v3, p0

    .line 187
    move-object v4, p1

    .line 188
    move-object v5, p2

    .line 189
    move v1, p4

    .line 190
    invoke-direct/range {v0 .. v5}, Lph/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 194
    .line 195
    :cond_d
    return-void
.end method
