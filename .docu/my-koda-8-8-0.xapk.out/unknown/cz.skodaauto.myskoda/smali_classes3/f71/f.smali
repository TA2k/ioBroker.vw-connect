.class public abstract Lf71/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0x78

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    const/16 v1, 0x3c

    .line 5
    .line 6
    int-to-float v1, v1

    .line 7
    div-float/2addr v1, v0

    .line 8
    sput v1, Lf71/f;->a:F

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lx2/s;ZZJLay0/a;Lay0/a;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v4, p5

    .line 4
    .line 5
    move-object/from16 v7, p6

    .line 6
    .line 7
    move/from16 v8, p8

    .line 8
    .line 9
    const-string v1, "modifier"

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v1, "onTouchDown"

    .line 15
    .line 16
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v1, "onFinishPress"

    .line 20
    .line 21
    invoke-static {v7, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    move-object/from16 v9, p7

    .line 25
    .line 26
    check-cast v9, Ll2/t;

    .line 27
    .line 28
    const v1, 0x46128bb4

    .line 29
    .line 30
    .line 31
    invoke-virtual {v9, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_0

    .line 39
    .line 40
    const/4 v1, 0x4

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 v1, 0x2

    .line 43
    :goto_0
    or-int/2addr v1, v8

    .line 44
    move/from16 v2, p1

    .line 45
    .line 46
    invoke-virtual {v9, v2}, Ll2/t;->h(Z)Z

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    if-eqz v3, :cond_1

    .line 51
    .line 52
    const/16 v3, 0x20

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_1
    const/16 v3, 0x10

    .line 56
    .line 57
    :goto_1
    or-int/2addr v1, v3

    .line 58
    and-int/lit16 v3, v8, 0x180

    .line 59
    .line 60
    move/from16 v14, p2

    .line 61
    .line 62
    if-nez v3, :cond_3

    .line 63
    .line 64
    invoke-virtual {v9, v14}, Ll2/t;->h(Z)Z

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    if-eqz v3, :cond_2

    .line 69
    .line 70
    const/16 v3, 0x100

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    const/16 v3, 0x80

    .line 74
    .line 75
    :goto_2
    or-int/2addr v1, v3

    .line 76
    :cond_3
    and-int/lit16 v3, v8, 0xc00

    .line 77
    .line 78
    move-wide/from16 v12, p3

    .line 79
    .line 80
    if-nez v3, :cond_5

    .line 81
    .line 82
    invoke-virtual {v9, v12, v13}, Ll2/t;->f(J)Z

    .line 83
    .line 84
    .line 85
    move-result v3

    .line 86
    if-eqz v3, :cond_4

    .line 87
    .line 88
    const/16 v3, 0x800

    .line 89
    .line 90
    goto :goto_3

    .line 91
    :cond_4
    const/16 v3, 0x400

    .line 92
    .line 93
    :goto_3
    or-int/2addr v1, v3

    .line 94
    :cond_5
    invoke-virtual {v9, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v3

    .line 98
    if-eqz v3, :cond_6

    .line 99
    .line 100
    const/16 v3, 0x4000

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_6
    const/16 v3, 0x2000

    .line 104
    .line 105
    :goto_4
    or-int/2addr v1, v3

    .line 106
    invoke-virtual {v9, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v3

    .line 110
    if-eqz v3, :cond_7

    .line 111
    .line 112
    const/high16 v3, 0x20000

    .line 113
    .line 114
    goto :goto_5

    .line 115
    :cond_7
    const/high16 v3, 0x10000

    .line 116
    .line 117
    :goto_5
    or-int/2addr v1, v3

    .line 118
    const v3, 0x12493

    .line 119
    .line 120
    .line 121
    and-int/2addr v3, v1

    .line 122
    const v10, 0x12492

    .line 123
    .line 124
    .line 125
    if-eq v3, v10, :cond_8

    .line 126
    .line 127
    const/4 v3, 0x1

    .line 128
    goto :goto_6

    .line 129
    :cond_8
    const/4 v3, 0x0

    .line 130
    :goto_6
    and-int/lit8 v10, v1, 0x1

    .line 131
    .line 132
    invoke-virtual {v9, v10, v3}, Ll2/t;->O(IZ)Z

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    if-eqz v3, :cond_f

    .line 137
    .line 138
    sget v3, Li81/b;->k:I

    .line 139
    .line 140
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v3

    .line 144
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 145
    .line 146
    if-ne v3, v10, :cond_9

    .line 147
    .line 148
    const/4 v3, 0x0

    .line 149
    invoke-static {v3}, Lc1/d;->a(F)Lc1/c;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    invoke-virtual {v9, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    :cond_9
    check-cast v3, Lc1/c;

    .line 157
    .line 158
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v11

    .line 162
    if-ne v11, v10, :cond_a

    .line 163
    .line 164
    sget-object v11, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 165
    .line 166
    invoke-static {v11}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 167
    .line 168
    .line 169
    move-result-object v11

    .line 170
    invoke-virtual {v9, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    :cond_a
    check-cast v11, Ll2/b1;

    .line 174
    .line 175
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v16

    .line 179
    move-object/from16 v5, v16

    .line 180
    .line 181
    check-cast v5, Ljava/lang/Boolean;

    .line 182
    .line 183
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 184
    .line 185
    .line 186
    invoke-static {v14}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 187
    .line 188
    .line 189
    move-result-object v6

    .line 190
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v17

    .line 194
    and-int/lit16 v15, v1, 0x1c00

    .line 195
    .line 196
    const/16 v0, 0x800

    .line 197
    .line 198
    if-ne v15, v0, :cond_b

    .line 199
    .line 200
    const/4 v0, 0x1

    .line 201
    goto :goto_7

    .line 202
    :cond_b
    const/4 v0, 0x0

    .line 203
    :goto_7
    or-int v0, v17, v0

    .line 204
    .line 205
    and-int/lit16 v15, v1, 0x380

    .line 206
    .line 207
    move/from16 v16, v0

    .line 208
    .line 209
    const/16 v0, 0x100

    .line 210
    .line 211
    if-ne v15, v0, :cond_c

    .line 212
    .line 213
    const/16 v18, 0x1

    .line 214
    .line 215
    goto :goto_8

    .line 216
    :cond_c
    const/16 v18, 0x0

    .line 217
    .line 218
    :goto_8
    or-int v0, v16, v18

    .line 219
    .line 220
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v15

    .line 224
    if-nez v0, :cond_e

    .line 225
    .line 226
    if-ne v15, v10, :cond_d

    .line 227
    .line 228
    goto :goto_9

    .line 229
    :cond_d
    move-object v10, v15

    .line 230
    move-object v15, v11

    .line 231
    move-object v11, v3

    .line 232
    goto :goto_a

    .line 233
    :cond_e
    :goto_9
    new-instance v10, Lf71/e;

    .line 234
    .line 235
    const/16 v16, 0x0

    .line 236
    .line 237
    move-object v15, v11

    .line 238
    move-object v11, v3

    .line 239
    invoke-direct/range {v10 .. v16}, Lf71/e;-><init>(Lc1/c;JZLl2/b1;Lkotlin/coroutines/Continuation;)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 243
    .line 244
    .line 245
    :goto_a
    check-cast v10, Lay0/n;

    .line 246
    .line 247
    invoke-static {v5, v6, v10, v9}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 248
    .line 249
    .line 250
    move v0, v1

    .line 251
    new-instance v1, Lf71/c;

    .line 252
    .line 253
    move/from16 v6, p2

    .line 254
    .line 255
    move v3, v2

    .line 256
    move-object v5, v7

    .line 257
    move-object v2, v11

    .line 258
    move-object v7, v15

    .line 259
    invoke-direct/range {v1 .. v7}, Lf71/c;-><init>(Lc1/c;ZLay0/a;Lay0/a;ZLl2/b1;)V

    .line 260
    .line 261
    .line 262
    const v2, -0x515918f6

    .line 263
    .line 264
    .line 265
    invoke-static {v2, v9, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 266
    .line 267
    .line 268
    move-result-object v3

    .line 269
    and-int/lit8 v0, v0, 0xe

    .line 270
    .line 271
    or-int/lit16 v5, v0, 0xc00

    .line 272
    .line 273
    const/4 v6, 0x6

    .line 274
    const/4 v1, 0x0

    .line 275
    const/4 v2, 0x0

    .line 276
    move-object/from16 v0, p0

    .line 277
    .line 278
    move-object v4, v9

    .line 279
    invoke-static/range {v0 .. v6}, Lk1/d;->a(Lx2/s;Lx2/e;ZLt2/b;Ll2/o;II)V

    .line 280
    .line 281
    .line 282
    goto :goto_b

    .line 283
    :cond_f
    move-object v4, v9

    .line 284
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 285
    .line 286
    .line 287
    :goto_b
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 288
    .line 289
    .line 290
    move-result-object v9

    .line 291
    if-eqz v9, :cond_10

    .line 292
    .line 293
    new-instance v0, Lf71/d;

    .line 294
    .line 295
    move-object/from16 v1, p0

    .line 296
    .line 297
    move/from16 v2, p1

    .line 298
    .line 299
    move/from16 v3, p2

    .line 300
    .line 301
    move-wide/from16 v4, p3

    .line 302
    .line 303
    move-object/from16 v6, p5

    .line 304
    .line 305
    move-object/from16 v7, p6

    .line 306
    .line 307
    invoke-direct/range {v0 .. v8}, Lf71/d;-><init>(Lx2/s;ZZJLay0/a;Lay0/a;I)V

    .line 308
    .line 309
    .line 310
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 311
    .line 312
    :cond_10
    return-void
.end method
