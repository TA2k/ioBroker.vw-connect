.class public abstract Llp/ra;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/b1;Lay0/a;Ll2/o;I)V
    .locals 27

    .line 1
    move-object/from16 v8, p2

    .line 2
    .line 3
    check-cast v8, Ll2/t;

    .line 4
    .line 5
    const v2, -0x23eebb2

    .line 6
    .line 7
    .line 8
    invoke-virtual {v8, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    or-int/lit8 v2, p3, 0x30

    .line 12
    .line 13
    and-int/lit8 v3, v2, 0x13

    .line 14
    .line 15
    const/16 v4, 0x12

    .line 16
    .line 17
    const/4 v5, 0x1

    .line 18
    if-eq v3, v4, :cond_0

    .line 19
    .line 20
    move v3, v5

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v3, 0x0

    .line 23
    :goto_0
    and-int/2addr v2, v5

    .line 24
    invoke-virtual {v8, v2, v3}, Ll2/t;->O(IZ)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_6

    .line 29
    .line 30
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    new-instance v2, Lz81/g;

    .line 39
    .line 40
    const/4 v4, 0x2

    .line 41
    invoke-direct {v2, v4}, Lz81/g;-><init>(I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v8, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    check-cast v2, Lay0/a;

    .line 48
    .line 49
    sget-object v4, Lw3/h1;->t:Ll2/u2;

    .line 50
    .line 51
    invoke-virtual {v8, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    check-cast v4, Lw3/j2;

    .line 56
    .line 57
    check-cast v4, Lw3/r1;

    .line 58
    .line 59
    invoke-virtual {v4}, Lw3/r1;->a()J

    .line 60
    .line 61
    .line 62
    move-result-wide v6

    .line 63
    const/16 v4, 0x20

    .line 64
    .line 65
    shr-long/2addr v6, v4

    .line 66
    long-to-int v4, v6

    .line 67
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    invoke-static {v4}, Lxf0/i0;->N(Ljava/lang/Number;)F

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 76
    .line 77
    const/4 v7, 0x0

    .line 78
    invoke-static {v6, v7, v4, v5}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    const/high16 v6, 0x3f800000    # 1.0f

    .line 83
    .line 84
    invoke-static {v4, v6}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    sget-object v6, Lk1/j;->e:Lk1/f;

    .line 89
    .line 90
    sget-object v7, Lx2/c;->q:Lx2/h;

    .line 91
    .line 92
    const/16 v9, 0x36

    .line 93
    .line 94
    invoke-static {v6, v7, v8, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 95
    .line 96
    .line 97
    move-result-object v6

    .line 98
    iget-wide v9, v8, Ll2/t;->T:J

    .line 99
    .line 100
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 101
    .line 102
    .line 103
    move-result v7

    .line 104
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 105
    .line 106
    .line 107
    move-result-object v9

    .line 108
    invoke-static {v8, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 109
    .line 110
    .line 111
    move-result-object v4

    .line 112
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 113
    .line 114
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 118
    .line 119
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 120
    .line 121
    .line 122
    iget-boolean v11, v8, Ll2/t;->S:Z

    .line 123
    .line 124
    if-eqz v11, :cond_2

    .line 125
    .line 126
    invoke-virtual {v8, v10}, Ll2/t;->l(Lay0/a;)V

    .line 127
    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_2
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 131
    .line 132
    .line 133
    :goto_1
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 134
    .line 135
    invoke-static {v10, v6, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 136
    .line 137
    .line 138
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 139
    .line 140
    invoke-static {v6, v9, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 141
    .line 142
    .line 143
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 144
    .line 145
    iget-boolean v9, v8, Ll2/t;->S:Z

    .line 146
    .line 147
    if-nez v9, :cond_3

    .line 148
    .line 149
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v9

    .line 153
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 154
    .line 155
    .line 156
    move-result-object v10

    .line 157
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v9

    .line 161
    if-nez v9, :cond_4

    .line 162
    .line 163
    :cond_3
    invoke-static {v7, v8, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 164
    .line 165
    .line 166
    :cond_4
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 167
    .line 168
    invoke-static {v6, v4, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 169
    .line 170
    .line 171
    const v4, 0x7f120216

    .line 172
    .line 173
    .line 174
    invoke-static {v8, v4}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object v4

    .line 178
    sget-object v6, Lj91/j;->a:Ll2/u2;

    .line 179
    .line 180
    invoke-virtual {v8, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v6

    .line 184
    check-cast v6, Lj91/f;

    .line 185
    .line 186
    invoke-virtual {v6}, Lj91/f;->b()Lg4/p0;

    .line 187
    .line 188
    .line 189
    move-result-object v6

    .line 190
    const/16 v22, 0x0

    .line 191
    .line 192
    const v23, 0xfffc

    .line 193
    .line 194
    .line 195
    move-object v7, v2

    .line 196
    move-object v2, v4

    .line 197
    const/4 v4, 0x0

    .line 198
    move-object v9, v3

    .line 199
    move v10, v5

    .line 200
    move-object v3, v6

    .line 201
    const-wide/16 v5, 0x0

    .line 202
    .line 203
    move-object v11, v7

    .line 204
    move-object/from16 v20, v8

    .line 205
    .line 206
    const-wide/16 v7, 0x0

    .line 207
    .line 208
    move-object v12, v9

    .line 209
    const/4 v9, 0x0

    .line 210
    move v14, v10

    .line 211
    move-object v13, v11

    .line 212
    const-wide/16 v10, 0x0

    .line 213
    .line 214
    move-object v15, v12

    .line 215
    const/4 v12, 0x0

    .line 216
    move-object/from16 v16, v13

    .line 217
    .line 218
    const/4 v13, 0x0

    .line 219
    move/from16 v18, v14

    .line 220
    .line 221
    move-object/from16 v17, v15

    .line 222
    .line 223
    const-wide/16 v14, 0x0

    .line 224
    .line 225
    move-object/from16 v19, v16

    .line 226
    .line 227
    const/16 v16, 0x0

    .line 228
    .line 229
    move-object/from16 v21, v17

    .line 230
    .line 231
    const/16 v17, 0x0

    .line 232
    .line 233
    move/from16 v24, v18

    .line 234
    .line 235
    const/16 v18, 0x0

    .line 236
    .line 237
    move-object/from16 v25, v19

    .line 238
    .line 239
    const/16 v19, 0x0

    .line 240
    .line 241
    move-object/from16 v26, v21

    .line 242
    .line 243
    const/16 v21, 0x0

    .line 244
    .line 245
    move-object/from16 v1, v25

    .line 246
    .line 247
    move-object/from16 v0, v26

    .line 248
    .line 249
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 250
    .line 251
    .line 252
    move-object/from16 v8, v20

    .line 253
    .line 254
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v2

    .line 258
    if-ne v2, v0, :cond_5

    .line 259
    .line 260
    new-instance v2, Lb71/h;

    .line 261
    .line 262
    move-object/from16 v0, p0

    .line 263
    .line 264
    invoke-direct {v2, v1, v0}, Lb71/h;-><init>(Lay0/a;Ll2/b1;)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v8, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    goto :goto_2

    .line 271
    :cond_5
    move-object/from16 v0, p0

    .line 272
    .line 273
    :goto_2
    move-object v3, v2

    .line 274
    check-cast v3, Lay0/a;

    .line 275
    .line 276
    const/4 v9, 0x0

    .line 277
    const/16 v10, 0x1c

    .line 278
    .line 279
    const v2, 0x7f080484

    .line 280
    .line 281
    .line 282
    const/4 v4, 0x0

    .line 283
    const/4 v5, 0x0

    .line 284
    const-wide/16 v6, 0x0

    .line 285
    .line 286
    invoke-static/range {v2 .. v10}, Li91/j0;->z0(ILay0/a;Lx2/s;ZJLl2/o;II)V

    .line 287
    .line 288
    .line 289
    const/4 v14, 0x1

    .line 290
    invoke-virtual {v8, v14}, Ll2/t;->q(Z)V

    .line 291
    .line 292
    .line 293
    goto :goto_3

    .line 294
    :cond_6
    move-object/from16 v0, p0

    .line 295
    .line 296
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 297
    .line 298
    .line 299
    move-object/from16 v1, p1

    .line 300
    .line 301
    :goto_3
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 302
    .line 303
    .line 304
    move-result-object v2

    .line 305
    if-eqz v2, :cond_7

    .line 306
    .line 307
    new-instance v3, Li40/k0;

    .line 308
    .line 309
    const/16 v4, 0x1a

    .line 310
    .line 311
    move/from16 v5, p3

    .line 312
    .line 313
    invoke-direct {v3, v5, v4, v0, v1}, Li40/k0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 317
    .line 318
    :cond_7
    return-void
.end method
