.class public abstract Lkp/r9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 11

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x4568e7d0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v1

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_4

    .line 23
    .line 24
    const v2, -0x6040e0aa

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    const-class v3, Lsa0/b;

    .line 45
    .line 46
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 47
    .line 48
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    invoke-static/range {v3 .. v9}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    check-cast v2, Lql0/j;

    .line 67
    .line 68
    invoke-static {v2, p0, v1, v0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 69
    .line 70
    .line 71
    move-object v5, v2

    .line 72
    check-cast v5, Lsa0/b;

    .line 73
    .line 74
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    if-nez v0, :cond_1

    .line 83
    .line 84
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 85
    .line 86
    if-ne v2, v0, :cond_2

    .line 87
    .line 88
    :cond_1
    new-instance v3, Lt90/c;

    .line 89
    .line 90
    const/4 v9, 0x0

    .line 91
    const/4 v10, 0x5

    .line 92
    const/4 v4, 0x0

    .line 93
    const-class v6, Lsa0/b;

    .line 94
    .line 95
    const-string v7, "onClose"

    .line 96
    .line 97
    const-string v8, "onClose()V"

    .line 98
    .line 99
    invoke-direct/range {v3 .. v10}, Lt90/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    move-object v2, v3

    .line 106
    :cond_2
    check-cast v2, Lhy0/g;

    .line 107
    .line 108
    check-cast v2, Lay0/a;

    .line 109
    .line 110
    invoke-static {v2, p0, v1}, Lkp/r9;->b(Lay0/a;Ll2/o;I)V

    .line 111
    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 115
    .line 116
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 117
    .line 118
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw p0

    .line 122
    :cond_4
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 123
    .line 124
    .line 125
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    if-eqz p0, :cond_5

    .line 130
    .line 131
    new-instance v0, Lt10/b;

    .line 132
    .line 133
    const/16 v1, 0x19

    .line 134
    .line 135
    invoke-direct {v0, p1, v1}, Lt10/b;-><init>(II)V

    .line 136
    .line 137
    .line 138
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 139
    .line 140
    :cond_5
    return-void
.end method

.method public static final b(Lay0/a;Ll2/o;I)V
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v9, p1

    .line 4
    .line 5
    check-cast v9, Ll2/t;

    .line 6
    .line 7
    const v2, 0x585149fc

    .line 8
    .line 9
    .line 10
    invoke-virtual {v9, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v12, 0x2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v2, v12

    .line 23
    :goto_0
    or-int v2, p2, v2

    .line 24
    .line 25
    and-int/lit8 v3, v2, 0x3

    .line 26
    .line 27
    const/4 v13, 0x0

    .line 28
    const/4 v14, 0x1

    .line 29
    if-eq v3, v12, :cond_1

    .line 30
    .line 31
    move v3, v14

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v3, v13

    .line 34
    :goto_1
    and-int/2addr v2, v14

    .line 35
    invoke-virtual {v9, v2, v3}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_b

    .line 40
    .line 41
    sget-object v15, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 42
    .line 43
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 44
    .line 45
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 46
    .line 47
    invoke-static {v2, v3, v9, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    iget-wide v5, v9, Ll2/t;->T:J

    .line 52
    .line 53
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    invoke-static {v9, v15}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 62
    .line 63
    .line 64
    move-result-object v7

    .line 65
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 66
    .line 67
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 71
    .line 72
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 73
    .line 74
    .line 75
    iget-boolean v10, v9, Ll2/t;->S:Z

    .line 76
    .line 77
    if-eqz v10, :cond_2

    .line 78
    .line 79
    invoke-virtual {v9, v8}, Ll2/t;->l(Lay0/a;)V

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_2
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 84
    .line 85
    .line 86
    :goto_2
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 87
    .line 88
    invoke-static {v10, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 89
    .line 90
    .line 91
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 92
    .line 93
    invoke-static {v4, v6, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 94
    .line 95
    .line 96
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 97
    .line 98
    iget-boolean v11, v9, Ll2/t;->S:Z

    .line 99
    .line 100
    if-nez v11, :cond_3

    .line 101
    .line 102
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v11

    .line 106
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 107
    .line 108
    .line 109
    move-result-object v14

    .line 110
    invoke-static {v11, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v11

    .line 114
    if-nez v11, :cond_4

    .line 115
    .line 116
    :cond_3
    invoke-static {v5, v9, v5, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 117
    .line 118
    .line 119
    :cond_4
    sget-object v14, Lv3/j;->d:Lv3/h;

    .line 120
    .line 121
    invoke-static {v14, v7, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 122
    .line 123
    .line 124
    new-instance v5, Li91/x2;

    .line 125
    .line 126
    const/4 v7, 0x3

    .line 127
    invoke-direct {v5, v0, v7}, Li91/x2;-><init>(Lay0/a;I)V

    .line 128
    .line 129
    .line 130
    move-object v7, v10

    .line 131
    const/4 v10, 0x0

    .line 132
    const/16 v11, 0x3bf

    .line 133
    .line 134
    move-object/from16 v16, v2

    .line 135
    .line 136
    const/4 v2, 0x0

    .line 137
    move-object/from16 v17, v3

    .line 138
    .line 139
    const/4 v3, 0x0

    .line 140
    move-object/from16 v18, v4

    .line 141
    .line 142
    const/4 v4, 0x0

    .line 143
    move-object/from16 v19, v6

    .line 144
    .line 145
    const/4 v6, 0x0

    .line 146
    move-object/from16 v20, v7

    .line 147
    .line 148
    const/4 v7, 0x0

    .line 149
    move-object/from16 v21, v8

    .line 150
    .line 151
    const/4 v8, 0x0

    .line 152
    move-object/from16 v24, v16

    .line 153
    .line 154
    move-object/from16 v25, v17

    .line 155
    .line 156
    move-object/from16 v28, v18

    .line 157
    .line 158
    move-object/from16 v29, v19

    .line 159
    .line 160
    move-object/from16 v27, v20

    .line 161
    .line 162
    move-object/from16 v26, v21

    .line 163
    .line 164
    invoke-static/range {v2 .. v11}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 165
    .line 166
    .line 167
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    iget v2, v2, Lj91/c;->j:F

    .line 172
    .line 173
    const/4 v3, 0x0

    .line 174
    invoke-static {v15, v2, v3, v12}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    move-object/from16 v3, v24

    .line 179
    .line 180
    move-object/from16 v4, v25

    .line 181
    .line 182
    invoke-static {v3, v4, v9, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    iget-wide v4, v9, Ll2/t;->T:J

    .line 187
    .line 188
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 189
    .line 190
    .line 191
    move-result v4

    .line 192
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 193
    .line 194
    .line 195
    move-result-object v5

    .line 196
    invoke-static {v9, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 201
    .line 202
    .line 203
    iget-boolean v6, v9, Ll2/t;->S:Z

    .line 204
    .line 205
    if-eqz v6, :cond_5

    .line 206
    .line 207
    move-object/from16 v6, v26

    .line 208
    .line 209
    invoke-virtual {v9, v6}, Ll2/t;->l(Lay0/a;)V

    .line 210
    .line 211
    .line 212
    :goto_3
    move-object/from16 v7, v27

    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_5
    move-object/from16 v6, v26

    .line 216
    .line 217
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 218
    .line 219
    .line 220
    goto :goto_3

    .line 221
    :goto_4
    invoke-static {v7, v3, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 222
    .line 223
    .line 224
    move-object/from16 v3, v28

    .line 225
    .line 226
    invoke-static {v3, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 227
    .line 228
    .line 229
    iget-boolean v5, v9, Ll2/t;->S:Z

    .line 230
    .line 231
    if-nez v5, :cond_6

    .line 232
    .line 233
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v5

    .line 237
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 238
    .line 239
    .line 240
    move-result-object v8

    .line 241
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    move-result v5

    .line 245
    if-nez v5, :cond_7

    .line 246
    .line 247
    :cond_6
    move-object/from16 v5, v29

    .line 248
    .line 249
    goto :goto_5

    .line 250
    :cond_7
    move-object/from16 v5, v29

    .line 251
    .line 252
    goto :goto_6

    .line 253
    :goto_5
    invoke-static {v4, v9, v4, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 254
    .line 255
    .line 256
    :goto_6
    invoke-static {v14, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 257
    .line 258
    .line 259
    const-string v2, "vehicle_connection_statuses_title"

    .line 260
    .line 261
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 262
    .line 263
    invoke-static {v4, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    const v8, 0x7f121493

    .line 268
    .line 269
    .line 270
    invoke-static {v9, v8}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object v8

    .line 274
    invoke-static {v9}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 275
    .line 276
    .line 277
    move-result-object v10

    .line 278
    invoke-virtual {v10}, Lj91/f;->i()Lg4/p0;

    .line 279
    .line 280
    .line 281
    move-result-object v10

    .line 282
    const/16 v22, 0x0

    .line 283
    .line 284
    const v23, 0xfff8

    .line 285
    .line 286
    .line 287
    move-object/from16 v29, v5

    .line 288
    .line 289
    move-object/from16 v21, v6

    .line 290
    .line 291
    const-wide/16 v5, 0x0

    .line 292
    .line 293
    move-object v11, v4

    .line 294
    move-object/from16 v20, v7

    .line 295
    .line 296
    move-object v4, v2

    .line 297
    move-object v2, v8

    .line 298
    const-wide/16 v7, 0x0

    .line 299
    .line 300
    move-object/from16 v27, v20

    .line 301
    .line 302
    move-object/from16 v20, v9

    .line 303
    .line 304
    const/4 v9, 0x0

    .line 305
    move-object/from16 v18, v3

    .line 306
    .line 307
    move-object v3, v10

    .line 308
    move-object v12, v11

    .line 309
    const-wide/16 v10, 0x0

    .line 310
    .line 311
    move-object v15, v12

    .line 312
    const/4 v12, 0x0

    .line 313
    move/from16 v16, v13

    .line 314
    .line 315
    const/4 v13, 0x0

    .line 316
    move-object/from16 v17, v14

    .line 317
    .line 318
    move-object/from16 v19, v15

    .line 319
    .line 320
    const-wide/16 v14, 0x0

    .line 321
    .line 322
    move/from16 v24, v16

    .line 323
    .line 324
    const/16 v16, 0x0

    .line 325
    .line 326
    move-object/from16 v25, v17

    .line 327
    .line 328
    const/16 v17, 0x0

    .line 329
    .line 330
    move-object/from16 v28, v18

    .line 331
    .line 332
    const/16 v18, 0x0

    .line 333
    .line 334
    move-object/from16 v26, v19

    .line 335
    .line 336
    const/16 v19, 0x0

    .line 337
    .line 338
    move-object/from16 v30, v21

    .line 339
    .line 340
    const/16 v21, 0x180

    .line 341
    .line 342
    move-object/from16 v33, v25

    .line 343
    .line 344
    move-object/from16 v1, v26

    .line 345
    .line 346
    move-object/from16 v31, v28

    .line 347
    .line 348
    move-object/from16 v32, v29

    .line 349
    .line 350
    move-object/from16 v0, v30

    .line 351
    .line 352
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 353
    .line 354
    .line 355
    move-object/from16 v9, v20

    .line 356
    .line 357
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 358
    .line 359
    .line 360
    move-result-object v2

    .line 361
    iget v2, v2, Lj91/c;->d:F

    .line 362
    .line 363
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 364
    .line 365
    .line 366
    move-result-object v2

    .line 367
    invoke-static {v9, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 368
    .line 369
    .line 370
    sget-object v2, Lx2/c;->n:Lx2/i;

    .line 371
    .line 372
    sget-object v3, Lk1/j;->a:Lk1/c;

    .line 373
    .line 374
    const/16 v4, 0x30

    .line 375
    .line 376
    invoke-static {v3, v2, v9, v4}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 377
    .line 378
    .line 379
    move-result-object v2

    .line 380
    iget-wide v3, v9, Ll2/t;->T:J

    .line 381
    .line 382
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 383
    .line 384
    .line 385
    move-result v3

    .line 386
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 387
    .line 388
    .line 389
    move-result-object v4

    .line 390
    invoke-static {v9, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 391
    .line 392
    .line 393
    move-result-object v5

    .line 394
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 395
    .line 396
    .line 397
    iget-boolean v6, v9, Ll2/t;->S:Z

    .line 398
    .line 399
    if-eqz v6, :cond_8

    .line 400
    .line 401
    invoke-virtual {v9, v0}, Ll2/t;->l(Lay0/a;)V

    .line 402
    .line 403
    .line 404
    :goto_7
    move-object/from16 v7, v27

    .line 405
    .line 406
    goto :goto_8

    .line 407
    :cond_8
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 408
    .line 409
    .line 410
    goto :goto_7

    .line 411
    :goto_8
    invoke-static {v7, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 412
    .line 413
    .line 414
    move-object/from16 v0, v31

    .line 415
    .line 416
    invoke-static {v0, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 417
    .line 418
    .line 419
    iget-boolean v0, v9, Ll2/t;->S:Z

    .line 420
    .line 421
    if-nez v0, :cond_9

    .line 422
    .line 423
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 428
    .line 429
    .line 430
    move-result-object v2

    .line 431
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 432
    .line 433
    .line 434
    move-result v0

    .line 435
    if-nez v0, :cond_a

    .line 436
    .line 437
    :cond_9
    move-object/from16 v0, v32

    .line 438
    .line 439
    goto :goto_a

    .line 440
    :cond_a
    :goto_9
    move-object/from16 v0, v33

    .line 441
    .line 442
    goto :goto_b

    .line 443
    :goto_a
    invoke-static {v3, v9, v3, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 444
    .line 445
    .line 446
    goto :goto_9

    .line 447
    :goto_b
    invoke-static {v0, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 448
    .line 449
    .line 450
    sget-object v0, Lra0/c;->g:Lra0/c;

    .line 451
    .line 452
    invoke-static {v0, v9}, Lkp/t9;->c(Lra0/c;Ll2/o;)Lta0/d;

    .line 453
    .line 454
    .line 455
    move-result-object v2

    .line 456
    check-cast v2, Lta0/c;

    .line 457
    .line 458
    iget-object v2, v2, Lta0/c;->a:Li91/k1;

    .line 459
    .line 460
    invoke-virtual {v2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 461
    .line 462
    .line 463
    move-result-object v3

    .line 464
    new-instance v4, Ljava/lang/StringBuilder;

    .line 465
    .line 466
    const-string v5, "indicator_"

    .line 467
    .line 468
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 469
    .line 470
    .line 471
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 472
    .line 473
    .line 474
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 475
    .line 476
    .line 477
    move-result-object v3

    .line 478
    invoke-static {v1, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 479
    .line 480
    .line 481
    move-result-object v3

    .line 482
    const/4 v4, 0x0

    .line 483
    invoke-static {v2, v3, v9, v4, v4}, Li91/j0;->E(Li91/k1;Lx2/s;Ll2/o;II)V

    .line 484
    .line 485
    .line 486
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 487
    .line 488
    .line 489
    move-result-object v2

    .line 490
    iget v2, v2, Lj91/c;->b:F

    .line 491
    .line 492
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 493
    .line 494
    .line 495
    move-result-object v2

    .line 496
    invoke-static {v9, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 497
    .line 498
    .line 499
    const-string v2, "vehicle_connection_statuses_title_battery_protection"

    .line 500
    .line 501
    invoke-static {v1, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 502
    .line 503
    .line 504
    move-result-object v4

    .line 505
    invoke-static {v0}, Lkp/t9;->a(Lra0/c;)I

    .line 506
    .line 507
    .line 508
    move-result v0

    .line 509
    invoke-static {v9, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 510
    .line 511
    .line 512
    move-result-object v2

    .line 513
    invoke-static {v9}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 514
    .line 515
    .line 516
    move-result-object v0

    .line 517
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 518
    .line 519
    .line 520
    move-result-object v3

    .line 521
    const/16 v22, 0x0

    .line 522
    .line 523
    const v23, 0xfff8

    .line 524
    .line 525
    .line 526
    const-wide/16 v5, 0x0

    .line 527
    .line 528
    const-wide/16 v7, 0x0

    .line 529
    .line 530
    move-object/from16 v20, v9

    .line 531
    .line 532
    const/4 v9, 0x0

    .line 533
    const-wide/16 v10, 0x0

    .line 534
    .line 535
    const/4 v12, 0x0

    .line 536
    const/4 v13, 0x0

    .line 537
    const-wide/16 v14, 0x0

    .line 538
    .line 539
    const/16 v16, 0x0

    .line 540
    .line 541
    const/16 v17, 0x0

    .line 542
    .line 543
    const/16 v18, 0x0

    .line 544
    .line 545
    const/16 v19, 0x0

    .line 546
    .line 547
    const/16 v21, 0x180

    .line 548
    .line 549
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 550
    .line 551
    .line 552
    move-object/from16 v9, v20

    .line 553
    .line 554
    const/4 v0, 0x1

    .line 555
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 556
    .line 557
    .line 558
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 559
    .line 560
    .line 561
    move-result-object v2

    .line 562
    iget v2, v2, Lj91/c;->d:F

    .line 563
    .line 564
    const-string v3, "vehicle_connection_statuses_description_battery_protection"

    .line 565
    .line 566
    invoke-static {v1, v2, v9, v1, v3}, Lvj/b;->q(Lx2/p;FLl2/t;Lx2/p;Ljava/lang/String;)Lx2/s;

    .line 567
    .line 568
    .line 569
    move-result-object v4

    .line 570
    const v1, 0x7f121492

    .line 571
    .line 572
    .line 573
    invoke-static {v9, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 574
    .line 575
    .line 576
    move-result-object v2

    .line 577
    invoke-static {v9}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 578
    .line 579
    .line 580
    move-result-object v1

    .line 581
    invoke-virtual {v1}, Lj91/f;->a()Lg4/p0;

    .line 582
    .line 583
    .line 584
    move-result-object v3

    .line 585
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 586
    .line 587
    .line 588
    move-result-object v1

    .line 589
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 590
    .line 591
    .line 592
    move-result-wide v5

    .line 593
    const v23, 0xfff0

    .line 594
    .line 595
    .line 596
    const/4 v9, 0x0

    .line 597
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 598
    .line 599
    .line 600
    move-object/from16 v9, v20

    .line 601
    .line 602
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 603
    .line 604
    .line 605
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 606
    .line 607
    .line 608
    goto :goto_c

    .line 609
    :cond_b
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 610
    .line 611
    .line 612
    :goto_c
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 613
    .line 614
    .line 615
    move-result-object v0

    .line 616
    if-eqz v0, :cond_c

    .line 617
    .line 618
    new-instance v1, Lt10/d;

    .line 619
    .line 620
    const/4 v2, 0x4

    .line 621
    move-object/from16 v3, p0

    .line 622
    .line 623
    move/from16 v4, p2

    .line 624
    .line 625
    invoke-direct {v1, v3, v4, v2}, Lt10/d;-><init>(Lay0/a;II)V

    .line 626
    .line 627
    .line 628
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 629
    .line 630
    :cond_c
    return-void
.end method

.method public static c(DDD)D
    .locals 1

    .line 1
    cmpl-double v0, p2, p4

    .line 2
    .line 3
    if-gtz v0, :cond_2

    .line 4
    .line 5
    cmpg-double v0, p0, p2

    .line 6
    .line 7
    if-gez v0, :cond_0

    .line 8
    .line 9
    return-wide p2

    .line 10
    :cond_0
    cmpl-double p2, p0, p4

    .line 11
    .line 12
    if-lez p2, :cond_1

    .line 13
    .line 14
    return-wide p4

    .line 15
    :cond_1
    return-wide p0

    .line 16
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    const-string p1, "Cannot coerce value to an empty range: maximum "

    .line 19
    .line 20
    const-string v0, " is less than minimum "

    .line 21
    .line 22
    invoke-static {p1, v0, p4, p5}, Lp3/m;->r(Ljava/lang/String;Ljava/lang/String;D)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-virtual {p1, p2, p3}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const/16 p2, 0x2e

    .line 30
    .line 31
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0
.end method

.method public static d(FFF)F
    .locals 2

    .line 1
    cmpl-float v0, p1, p2

    .line 2
    .line 3
    if-gtz v0, :cond_2

    .line 4
    .line 5
    cmpg-float v0, p0, p1

    .line 6
    .line 7
    if-gez v0, :cond_0

    .line 8
    .line 9
    return p1

    .line 10
    :cond_0
    cmpl-float p1, p0, p2

    .line 11
    .line 12
    if-lez p1, :cond_1

    .line 13
    .line 14
    return p2

    .line 15
    :cond_1
    return p0

    .line 16
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    new-instance v0, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v1, "Cannot coerce value to an empty range: maximum "

    .line 21
    .line 22
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string p2, " is less than minimum "

    .line 29
    .line 30
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const/16 p1, 0x2e

    .line 37
    .line 38
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0
.end method

.method public static e(III)I
    .locals 2

    .line 1
    if-gt p1, p2, :cond_2

    .line 2
    .line 3
    if-ge p0, p1, :cond_0

    .line 4
    .line 5
    return p1

    .line 6
    :cond_0
    if-le p0, p2, :cond_1

    .line 7
    .line 8
    return p2

    .line 9
    :cond_1
    return p0

    .line 10
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 11
    .line 12
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v1, "Cannot coerce value to an empty range: maximum "

    .line 15
    .line 16
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string p2, " is less than minimum "

    .line 23
    .line 24
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const/16 p1, 0x2e

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0
.end method

.method public static f(ILgy0/g;)I
    .locals 2

    .line 1
    const-string v0, "range"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lgy0/f;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p1, Lgy0/f;

    .line 15
    .line 16
    invoke-static {p0, p1}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Ljava/lang/Number;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :cond_0
    invoke-interface {p1}, Lgy0/g;->isEmpty()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_3

    .line 32
    .line 33
    invoke-interface {p1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-ge p0, v0, :cond_1

    .line 44
    .line 45
    invoke-interface {p1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    check-cast p0, Ljava/lang/Number;

    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    return p0

    .line 56
    :cond_1
    invoke-interface {p1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    check-cast v0, Ljava/lang/Number;

    .line 61
    .line 62
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-le p0, v0, :cond_2

    .line 67
    .line 68
    invoke-interface {p1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    check-cast p0, Ljava/lang/Number;

    .line 73
    .line 74
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    :cond_2
    return p0

    .line 79
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 80
    .line 81
    new-instance v0, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    const-string v1, "Cannot coerce value to an empty range: "

    .line 84
    .line 85
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    const/16 p1, 0x2e

    .line 92
    .line 93
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    throw p0
.end method

.method public static g(JJJ)J
    .locals 1

    .line 1
    cmp-long v0, p2, p4

    .line 2
    .line 3
    if-gtz v0, :cond_2

    .line 4
    .line 5
    cmp-long v0, p0, p2

    .line 6
    .line 7
    if-gez v0, :cond_0

    .line 8
    .line 9
    return-wide p2

    .line 10
    :cond_0
    cmp-long p2, p0, p4

    .line 11
    .line 12
    if-lez p2, :cond_1

    .line 13
    .line 14
    return-wide p4

    .line 15
    :cond_1
    return-wide p0

    .line 16
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    const-string p1, "Cannot coerce value to an empty range: maximum "

    .line 19
    .line 20
    const-string v0, " is less than minimum "

    .line 21
    .line 22
    invoke-static {p4, p5, p1, v0}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-virtual {p1, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const/16 p2, 0x2e

    .line 30
    .line 31
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0
.end method

.method public static h(JLgy0/l;)J
    .locals 6

    .line 1
    iget-wide v0, p2, Lgy0/l;->e:J

    .line 2
    .line 3
    iget-wide v2, p2, Lgy0/l;->d:J

    .line 4
    .line 5
    instance-of v4, p2, Lgy0/f;

    .line 6
    .line 7
    if-eqz v4, :cond_0

    .line 8
    .line 9
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p2, Lgy0/f;

    .line 14
    .line 15
    invoke-static {p0, p2}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Number;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 22
    .line 23
    .line 24
    move-result-wide p0

    .line 25
    return-wide p0

    .line 26
    :cond_0
    invoke-virtual {p2}, Lgy0/l;->isEmpty()Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-nez v4, :cond_3

    .line 31
    .line 32
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 33
    .line 34
    .line 35
    move-result-object p2

    .line 36
    invoke-virtual {p2}, Ljava/lang/Number;->longValue()J

    .line 37
    .line 38
    .line 39
    move-result-wide v4

    .line 40
    cmp-long p2, p0, v4

    .line 41
    .line 42
    if-gez p2, :cond_1

    .line 43
    .line 44
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 49
    .line 50
    .line 51
    move-result-wide p0

    .line 52
    return-wide p0

    .line 53
    :cond_1
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    invoke-virtual {p2}, Ljava/lang/Number;->longValue()J

    .line 58
    .line 59
    .line 60
    move-result-wide v2

    .line 61
    cmp-long p2, p0, v2

    .line 62
    .line 63
    if-lez p2, :cond_2

    .line 64
    .line 65
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 70
    .line 71
    .line 72
    move-result-wide p0

    .line 73
    :cond_2
    return-wide p0

    .line 74
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 75
    .line 76
    new-instance p1, Ljava/lang/StringBuilder;

    .line 77
    .line 78
    const-string v0, "Cannot coerce value to an empty range: "

    .line 79
    .line 80
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const/16 p2, 0x2e

    .line 87
    .line 88
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw p0
.end method

.method public static i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;
    .locals 2

    .line 1
    const-string v0, "range"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Lgy0/g;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_2

    .line 11
    .line 12
    invoke-interface {p1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-interface {p1, p0, v0}, Lgy0/f;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-interface {p1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-interface {p1, v0, p0}, Lgy0/f;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_0

    .line 31
    .line 32
    invoke-interface {p1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :cond_0
    invoke-interface {p1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-interface {p1, v0, p0}, Lgy0/f;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-eqz v0, :cond_1

    .line 46
    .line 47
    invoke-interface {p1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-interface {p1, p0, v0}, Lgy0/f;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-nez v0, :cond_1

    .line 56
    .line 57
    invoke-interface {p1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    :cond_1
    return-object p0

    .line 62
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 63
    .line 64
    new-instance v0, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    const-string v1, "Cannot coerce value to an empty range: "

    .line 67
    .line 68
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const/16 p1, 0x2e

    .line 75
    .line 76
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0
.end method

.method public static j(Ljava/lang/Comparable;Ljava/lang/Comparable;Ljava/lang/Comparable;)Ljava/lang/Comparable;
    .locals 2

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    if-eqz p2, :cond_2

    .line 4
    .line 5
    invoke-interface {p1, p2}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-gtz v0, :cond_1

    .line 10
    .line 11
    invoke-interface {p0, p1}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-gez v0, :cond_0

    .line 16
    .line 17
    return-object p1

    .line 18
    :cond_0
    invoke-interface {p0, p2}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    if-lez p1, :cond_4

    .line 23
    .line 24
    return-object p2

    .line 25
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 26
    .line 27
    new-instance v0, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v1, "Cannot coerce value to an empty range: maximum "

    .line 30
    .line 31
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string p2, " is less than minimum "

    .line 38
    .line 39
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const/16 p1, 0x2e

    .line 46
    .line 47
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    if-eqz p1, :cond_3

    .line 59
    .line 60
    invoke-interface {p0, p1}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-gez v0, :cond_3

    .line 65
    .line 66
    return-object p1

    .line 67
    :cond_3
    if-eqz p2, :cond_4

    .line 68
    .line 69
    invoke-interface {p0, p2}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    if-lez p1, :cond_4

    .line 74
    .line 75
    return-object p2

    .line 76
    :cond_4
    return-object p0
.end method

.method public static k(II)Lgy0/h;
    .locals 2

    .line 1
    new-instance v0, Lgy0/h;

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    invoke-direct {v0, p0, p1, v1}, Lgy0/h;-><init>(III)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static l(ILgy0/j;)Lgy0/h;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-lez p0, :cond_0

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :goto_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget v0, p1, Lgy0/h;->d:I

    .line 18
    .line 19
    iget v1, p1, Lgy0/h;->e:I

    .line 20
    .line 21
    iget p1, p1, Lgy0/h;->f:I

    .line 22
    .line 23
    if-lez p1, :cond_1

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_1
    neg-int p0, p0

    .line 27
    :goto_1
    new-instance p1, Lgy0/h;

    .line 28
    .line 29
    invoke-direct {p1, v0, v1, p0}, Lgy0/h;-><init>(III)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 34
    .line 35
    new-instance p1, Ljava/lang/StringBuilder;

    .line 36
    .line 37
    const-string v0, "Step must be positive, was: "

    .line 38
    .line 39
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const/16 v0, 0x2e

    .line 46
    .line 47
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0
.end method

.method public static m(II)Lgy0/j;
    .locals 2

    .line 1
    const/high16 v0, -0x80000000

    .line 2
    .line 3
    if-gt p1, v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lgy0/j;->g:Lgy0/j;

    .line 6
    .line 7
    sget-object p0, Lgy0/j;->g:Lgy0/j;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v0, Lgy0/j;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    sub-int/2addr p1, v1

    .line 14
    invoke-direct {v0, p0, p1, v1}, Lgy0/h;-><init>(III)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method
