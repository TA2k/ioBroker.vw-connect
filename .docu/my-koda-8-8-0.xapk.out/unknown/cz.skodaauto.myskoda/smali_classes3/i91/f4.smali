.class public final synthetic Li91/f4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Li91/f4;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li91/f4;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-boolean p2, p0, Li91/f4;->f:Z

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/f4;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lvv/m0;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const-string v4, "$this$RichText"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v4, v3, 0x6

    .line 30
    .line 31
    if-nez v4, :cond_1

    .line 32
    .line 33
    move-object v4, v2

    .line 34
    check-cast v4, Ll2/t;

    .line 35
    .line 36
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    if-eqz v4, :cond_0

    .line 41
    .line 42
    const/4 v4, 0x4

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    const/4 v4, 0x2

    .line 45
    :goto_0
    or-int/2addr v3, v4

    .line 46
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 47
    .line 48
    const/16 v5, 0x12

    .line 49
    .line 50
    if-eq v4, v5, :cond_2

    .line 51
    .line 52
    const/4 v4, 0x1

    .line 53
    goto :goto_1

    .line 54
    :cond_2
    const/4 v4, 0x0

    .line 55
    :goto_1
    and-int/lit8 v5, v3, 0x1

    .line 56
    .line 57
    check-cast v2, Ll2/t;

    .line 58
    .line 59
    invoke-virtual {v2, v5, v4}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    if-eqz v4, :cond_3

    .line 64
    .line 65
    new-instance v4, Lsv/d;

    .line 66
    .line 67
    iget-boolean v5, v0, Li91/f4;->f:Z

    .line 68
    .line 69
    invoke-direct {v4, v5}, Lsv/d;-><init>(Z)V

    .line 70
    .line 71
    .line 72
    and-int/lit8 v3, v3, 0xe

    .line 73
    .line 74
    iget-object v0, v0, Li91/f4;->e:Ljava/lang/String;

    .line 75
    .line 76
    invoke-static {v1, v0, v4, v2, v3}, Lkp/s8;->a(Lvv/m0;Ljava/lang/String;Lsv/d;Ll2/o;I)V

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 81
    .line 82
    .line 83
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    return-object v0

    .line 86
    :pswitch_0
    move-object/from16 v1, p1

    .line 87
    .line 88
    check-cast v1, Lb1/a0;

    .line 89
    .line 90
    move-object/from16 v21, p2

    .line 91
    .line 92
    check-cast v21, Ll2/o;

    .line 93
    .line 94
    move-object/from16 v2, p3

    .line 95
    .line 96
    check-cast v2, Ljava/lang/Integer;

    .line 97
    .line 98
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    const-string v2, "$this$AnimatedVisibility"

    .line 102
    .line 103
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    iget-object v1, v0, Li91/f4;->e:Ljava/lang/String;

    .line 107
    .line 108
    if-nez v1, :cond_4

    .line 109
    .line 110
    const-string v1, ""

    .line 111
    .line 112
    :cond_4
    move-object v2, v1

    .line 113
    iget-boolean v0, v0, Li91/f4;->f:Z

    .line 114
    .line 115
    const/4 v1, 0x0

    .line 116
    if-eqz v0, :cond_5

    .line 117
    .line 118
    move-object/from16 v0, v21

    .line 119
    .line 120
    check-cast v0, Ll2/t;

    .line 121
    .line 122
    const v3, -0x1ae9cc44

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 126
    .line 127
    .line 128
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 129
    .line 130
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    check-cast v3, Lj91/e;

    .line 135
    .line 136
    invoke-virtual {v3}, Lj91/e;->a()J

    .line 137
    .line 138
    .line 139
    move-result-wide v3

    .line 140
    :goto_3
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 141
    .line 142
    .line 143
    move-wide v4, v3

    .line 144
    goto :goto_4

    .line 145
    :cond_5
    move-object/from16 v0, v21

    .line 146
    .line 147
    check-cast v0, Ll2/t;

    .line 148
    .line 149
    const v3, -0x1ae9c8bb

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 153
    .line 154
    .line 155
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 156
    .line 157
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    check-cast v3, Lj91/e;

    .line 162
    .line 163
    invoke-virtual {v3}, Lj91/e;->r()J

    .line 164
    .line 165
    .line 166
    move-result-wide v3

    .line 167
    goto :goto_3

    .line 168
    :goto_4
    invoke-static/range {v21 .. v21}, Li91/j4;->f(Ll2/o;)Lg4/p0;

    .line 169
    .line 170
    .line 171
    move-result-object v20

    .line 172
    const/4 v0, 0x4

    .line 173
    int-to-float v8, v0

    .line 174
    const/4 v10, 0x0

    .line 175
    const/16 v11, 0xd

    .line 176
    .line 177
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 178
    .line 179
    const/4 v7, 0x0

    .line 180
    const/4 v9, 0x0

    .line 181
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    const/16 v23, 0x0

    .line 186
    .line 187
    const v24, 0x1fff8

    .line 188
    .line 189
    .line 190
    const-wide/16 v6, 0x0

    .line 191
    .line 192
    const/4 v8, 0x0

    .line 193
    const-wide/16 v9, 0x0

    .line 194
    .line 195
    const/4 v11, 0x0

    .line 196
    const/4 v12, 0x0

    .line 197
    const-wide/16 v13, 0x0

    .line 198
    .line 199
    const/4 v15, 0x0

    .line 200
    const/16 v16, 0x0

    .line 201
    .line 202
    const/16 v17, 0x0

    .line 203
    .line 204
    const/16 v18, 0x0

    .line 205
    .line 206
    const/16 v19, 0x0

    .line 207
    .line 208
    const/16 v22, 0x30

    .line 209
    .line 210
    invoke-static/range {v2 .. v24}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 211
    .line 212
    .line 213
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 214
    .line 215
    return-object v0

    .line 216
    :pswitch_1
    move-object/from16 v1, p1

    .line 217
    .line 218
    check-cast v1, Lb1/a0;

    .line 219
    .line 220
    move-object/from16 v21, p2

    .line 221
    .line 222
    check-cast v21, Ll2/o;

    .line 223
    .line 224
    move-object/from16 v2, p3

    .line 225
    .line 226
    check-cast v2, Ljava/lang/Integer;

    .line 227
    .line 228
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 229
    .line 230
    .line 231
    const-string v2, "$this$AnimatedVisibility"

    .line 232
    .line 233
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    iget-object v1, v0, Li91/f4;->e:Ljava/lang/String;

    .line 237
    .line 238
    if-nez v1, :cond_6

    .line 239
    .line 240
    const-string v1, ""

    .line 241
    .line 242
    :cond_6
    move-object v2, v1

    .line 243
    iget-boolean v0, v0, Li91/f4;->f:Z

    .line 244
    .line 245
    const/4 v1, 0x0

    .line 246
    if-eqz v0, :cond_7

    .line 247
    .line 248
    move-object/from16 v0, v21

    .line 249
    .line 250
    check-cast v0, Ll2/t;

    .line 251
    .line 252
    const v3, -0x7d971a66

    .line 253
    .line 254
    .line 255
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 256
    .line 257
    .line 258
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 259
    .line 260
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v3

    .line 264
    check-cast v3, Lj91/e;

    .line 265
    .line 266
    invoke-virtual {v3}, Lj91/e;->t()J

    .line 267
    .line 268
    .line 269
    move-result-wide v3

    .line 270
    :goto_6
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 271
    .line 272
    .line 273
    move-wide v4, v3

    .line 274
    goto :goto_7

    .line 275
    :cond_7
    move-object/from16 v0, v21

    .line 276
    .line 277
    check-cast v0, Ll2/t;

    .line 278
    .line 279
    const v3, -0x7d971604

    .line 280
    .line 281
    .line 282
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 283
    .line 284
    .line 285
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 286
    .line 287
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v3

    .line 291
    check-cast v3, Lj91/e;

    .line 292
    .line 293
    invoke-virtual {v3}, Lj91/e;->r()J

    .line 294
    .line 295
    .line 296
    move-result-wide v3

    .line 297
    goto :goto_6

    .line 298
    :goto_7
    invoke-static/range {v21 .. v21}, Li91/j4;->f(Ll2/o;)Lg4/p0;

    .line 299
    .line 300
    .line 301
    move-result-object v20

    .line 302
    const/4 v0, 0x4

    .line 303
    int-to-float v8, v0

    .line 304
    const/4 v10, 0x0

    .line 305
    const/16 v11, 0xd

    .line 306
    .line 307
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 308
    .line 309
    const/4 v7, 0x0

    .line 310
    const/4 v9, 0x0

    .line 311
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 312
    .line 313
    .line 314
    move-result-object v3

    .line 315
    const/16 v23, 0x0

    .line 316
    .line 317
    const v24, 0x1fff8

    .line 318
    .line 319
    .line 320
    const-wide/16 v6, 0x0

    .line 321
    .line 322
    const/4 v8, 0x0

    .line 323
    const-wide/16 v9, 0x0

    .line 324
    .line 325
    const/4 v11, 0x0

    .line 326
    const/4 v12, 0x0

    .line 327
    const-wide/16 v13, 0x0

    .line 328
    .line 329
    const/4 v15, 0x0

    .line 330
    const/16 v16, 0x0

    .line 331
    .line 332
    const/16 v17, 0x0

    .line 333
    .line 334
    const/16 v18, 0x0

    .line 335
    .line 336
    const/16 v19, 0x0

    .line 337
    .line 338
    const/16 v22, 0x30

    .line 339
    .line 340
    invoke-static/range {v2 .. v24}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 341
    .line 342
    .line 343
    goto/16 :goto_5

    .line 344
    .line 345
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
