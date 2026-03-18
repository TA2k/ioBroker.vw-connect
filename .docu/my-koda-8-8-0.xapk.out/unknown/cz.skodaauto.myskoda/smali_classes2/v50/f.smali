.class public final synthetic Lv50/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lu50/h;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Z


# direct methods
.method public synthetic constructor <init>(ZLu50/h;Lay0/a;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lv50/f;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Lv50/f;->e:Lu50/h;

    .line 7
    .line 8
    iput-object p3, p0, Lv50/f;->f:Lay0/a;

    .line 9
    .line 10
    iput-boolean p4, p0, Lv50/f;->g:Z

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/q;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const-string v4, "$this$GradientBox"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v1, v3, 0x11

    .line 25
    .line 26
    const/16 v4, 0x10

    .line 27
    .line 28
    const/4 v5, 0x1

    .line 29
    const/4 v6, 0x0

    .line 30
    if-eq v1, v4, :cond_0

    .line 31
    .line 32
    move v1, v5

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v1, v6

    .line 35
    :goto_0
    and-int/2addr v3, v5

    .line 36
    move-object v12, v2

    .line 37
    check-cast v12, Ll2/t;

    .line 38
    .line 39
    invoke-virtual {v12, v3, v1}, Ll2/t;->O(IZ)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_5

    .line 44
    .line 45
    sget-object v1, Lx2/c;->q:Lx2/h;

    .line 46
    .line 47
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 48
    .line 49
    const/high16 v3, 0x3f800000    # 1.0f

    .line 50
    .line 51
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    sget-object v7, Lj91/a;->a:Ll2/u2;

    .line 56
    .line 57
    invoke-virtual {v12, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v8

    .line 61
    check-cast v8, Lj91/c;

    .line 62
    .line 63
    iget v8, v8, Lj91/c;->e:F

    .line 64
    .line 65
    const/4 v9, 0x2

    .line 66
    const/4 v10, 0x0

    .line 67
    invoke-static {v4, v8, v10, v9}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    sget-object v8, Lk1/j;->c:Lk1/e;

    .line 72
    .line 73
    const/16 v9, 0x30

    .line 74
    .line 75
    invoke-static {v8, v1, v12, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    iget-wide v8, v12, Ll2/t;->T:J

    .line 80
    .line 81
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 82
    .line 83
    .line 84
    move-result v8

    .line 85
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 86
    .line 87
    .line 88
    move-result-object v9

    .line 89
    invoke-static {v12, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 94
    .line 95
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 99
    .line 100
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 101
    .line 102
    .line 103
    iget-boolean v11, v12, Ll2/t;->S:Z

    .line 104
    .line 105
    if-eqz v11, :cond_1

    .line 106
    .line 107
    invoke-virtual {v12, v10}, Ll2/t;->l(Lay0/a;)V

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_1
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 112
    .line 113
    .line 114
    :goto_1
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 115
    .line 116
    invoke-static {v10, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 117
    .line 118
    .line 119
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 120
    .line 121
    invoke-static {v1, v9, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 122
    .line 123
    .line 124
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 125
    .line 126
    iget-boolean v9, v12, Ll2/t;->S:Z

    .line 127
    .line 128
    if-nez v9, :cond_2

    .line 129
    .line 130
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v9

    .line 134
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 135
    .line 136
    .line 137
    move-result-object v10

    .line 138
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v9

    .line 142
    if-nez v9, :cond_3

    .line 143
    .line 144
    :cond_2
    invoke-static {v8, v12, v8, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 145
    .line 146
    .line 147
    :cond_3
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 148
    .line 149
    invoke-static {v1, v4, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 150
    .line 151
    .line 152
    iget-boolean v1, v0, Lv50/f;->d:Z

    .line 153
    .line 154
    if-nez v1, :cond_4

    .line 155
    .line 156
    const v1, -0x5dfe3367

    .line 157
    .line 158
    .line 159
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v12, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    check-cast v1, Lj91/c;

    .line 167
    .line 168
    iget v1, v1, Lj91/c;->e:F

    .line 169
    .line 170
    const v4, 0x7f12075b

    .line 171
    .line 172
    .line 173
    invoke-static {v2, v1, v12, v4, v12}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    iget-object v4, v0, Lv50/f;->e:Lu50/h;

    .line 178
    .line 179
    iget-object v4, v4, Lu50/h;->g:Ljava/lang/String;

    .line 180
    .line 181
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v4

    .line 185
    invoke-static {v4, v5}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v4

    .line 189
    invoke-static {v1, v4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 194
    .line 195
    invoke-virtual {v12, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v8

    .line 199
    check-cast v8, Lj91/f;

    .line 200
    .line 201
    invoke-virtual {v8}, Lj91/f;->e()Lg4/p0;

    .line 202
    .line 203
    .line 204
    move-result-object v9

    .line 205
    invoke-virtual {v12, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v4

    .line 209
    check-cast v4, Lj91/f;

    .line 210
    .line 211
    invoke-virtual {v4}, Lj91/f;->g()Lg4/p0;

    .line 212
    .line 213
    .line 214
    move-result-object v25

    .line 215
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 216
    .line 217
    .line 218
    move-result-object v8

    .line 219
    const/16 v30, 0x0

    .line 220
    .line 221
    const v31, 0x1bfe8

    .line 222
    .line 223
    .line 224
    const-wide/16 v10, 0x0

    .line 225
    .line 226
    move-object/from16 v28, v12

    .line 227
    .line 228
    const/4 v12, 0x3

    .line 229
    const-wide/16 v13, 0x0

    .line 230
    .line 231
    const-wide/16 v15, 0x0

    .line 232
    .line 233
    const-wide/16 v17, 0x0

    .line 234
    .line 235
    const/16 v19, 0x0

    .line 236
    .line 237
    const/16 v20, 0x0

    .line 238
    .line 239
    const/16 v21, 0x0

    .line 240
    .line 241
    const/16 v22, 0x0

    .line 242
    .line 243
    const/16 v23, 0x0

    .line 244
    .line 245
    const/16 v24, 0x0

    .line 246
    .line 247
    const/16 v26, 0x0

    .line 248
    .line 249
    const/16 v27, 0x0

    .line 250
    .line 251
    const/16 v29, 0x30

    .line 252
    .line 253
    move-object/from16 v32, v7

    .line 254
    .line 255
    move-object v7, v1

    .line 256
    move-object/from16 v1, v32

    .line 257
    .line 258
    invoke-static/range {v7 .. v31}, Lxf0/y1;->d(Ljava/lang/String;Lx2/s;Lg4/p0;JIJJJLg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;Lg4/p0;ZLay0/k;Ll2/o;III)V

    .line 259
    .line 260
    .line 261
    move-object/from16 v12, v28

    .line 262
    .line 263
    :goto_2
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 264
    .line 265
    .line 266
    goto :goto_3

    .line 267
    :cond_4
    move-object v1, v7

    .line 268
    const v3, -0x5e49cf64

    .line 269
    .line 270
    .line 271
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 272
    .line 273
    .line 274
    goto :goto_2

    .line 275
    :goto_3
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v3

    .line 279
    check-cast v3, Lj91/c;

    .line 280
    .line 281
    iget v3, v3, Lj91/c;->e:F

    .line 282
    .line 283
    const v4, 0x7f12075e

    .line 284
    .line 285
    .line 286
    invoke-static {v2, v3, v12, v4, v12}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object v11

    .line 290
    const/4 v7, 0x0

    .line 291
    const/16 v8, 0x2c

    .line 292
    .line 293
    iget-object v9, v0, Lv50/f;->f:Lay0/a;

    .line 294
    .line 295
    const/4 v10, 0x0

    .line 296
    const/4 v13, 0x0

    .line 297
    iget-boolean v14, v0, Lv50/f;->g:Z

    .line 298
    .line 299
    const/4 v15, 0x0

    .line 300
    invoke-static/range {v7 .. v15}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    check-cast v0, Lj91/c;

    .line 308
    .line 309
    iget v0, v0, Lj91/c;->f:F

    .line 310
    .line 311
    invoke-static {v2, v0, v12, v5}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 312
    .line 313
    .line 314
    goto :goto_4

    .line 315
    :cond_5
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 316
    .line 317
    .line 318
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 319
    .line 320
    return-object v0
.end method
