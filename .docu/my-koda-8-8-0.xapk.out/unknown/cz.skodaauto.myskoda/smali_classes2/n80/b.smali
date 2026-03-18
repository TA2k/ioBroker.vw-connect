.class public final synthetic Ln80/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll80/a;

.field public final synthetic f:Ll80/c;

.field public final synthetic g:Lm80/b;


# direct methods
.method public synthetic constructor <init>(Ll80/a;Ll80/c;Lm80/b;I)V
    .locals 0

    .line 1
    const/4 p4, 0x1

    iput p4, p0, Ln80/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln80/b;->e:Ll80/a;

    iput-object p2, p0, Ln80/b;->f:Ll80/c;

    iput-object p3, p0, Ln80/b;->g:Lm80/b;

    return-void
.end method

.method public synthetic constructor <init>(Lm80/b;Ll80/a;Ll80/c;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Ln80/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln80/b;->g:Lm80/b;

    iput-object p2, p0, Ln80/b;->e:Ll80/a;

    iput-object p3, p0, Ln80/b;->f:Ll80/c;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ln80/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    iget-object v3, v0, Ln80/b;->e:Ll80/a;

    .line 25
    .line 26
    iget-object v4, v0, Ln80/b;->f:Ll80/c;

    .line 27
    .line 28
    iget-object v0, v0, Ln80/b;->g:Lm80/b;

    .line 29
    .line 30
    invoke-static {v3, v4, v0, v1, v2}, Ln80/a;->l(Ll80/a;Ll80/c;Lm80/b;Ll2/o;I)V

    .line 31
    .line 32
    .line 33
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object v0

    .line 36
    :pswitch_0
    move-object/from16 v1, p1

    .line 37
    .line 38
    check-cast v1, Ll2/o;

    .line 39
    .line 40
    move-object/from16 v2, p2

    .line 41
    .line 42
    check-cast v2, Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    and-int/lit8 v3, v2, 0x3

    .line 49
    .line 50
    const/4 v4, 0x2

    .line 51
    const/4 v5, 0x1

    .line 52
    const/4 v6, 0x0

    .line 53
    if-eq v3, v4, :cond_0

    .line 54
    .line 55
    move v3, v5

    .line 56
    goto :goto_0

    .line 57
    :cond_0
    move v3, v6

    .line 58
    :goto_0
    and-int/2addr v2, v5

    .line 59
    move-object v15, v1

    .line 60
    check-cast v15, Ll2/t;

    .line 61
    .line 62
    invoke-virtual {v15, v2, v3}, Ll2/t;->O(IZ)Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_6

    .line 67
    .line 68
    iget-object v1, v0, Ln80/b;->g:Lm80/b;

    .line 69
    .line 70
    iget-boolean v2, v1, Lm80/b;->f:Z

    .line 71
    .line 72
    const/4 v3, 0x0

    .line 73
    if-eqz v2, :cond_1

    .line 74
    .line 75
    iget-object v2, v0, Ln80/b;->e:Ll80/a;

    .line 76
    .line 77
    iget-wide v4, v2, Ll80/a;->d:D

    .line 78
    .line 79
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    move-object v7, v2

    .line 84
    goto :goto_1

    .line 85
    :cond_1
    move-object v7, v3

    .line 86
    :goto_1
    iget-boolean v1, v1, Lm80/b;->f:Z

    .line 87
    .line 88
    if-eqz v1, :cond_2

    .line 89
    .line 90
    const v1, -0x30e5557c

    .line 91
    .line 92
    .line 93
    const v2, 0x7f1201d8

    .line 94
    .line 95
    .line 96
    invoke-static {v1, v2, v15, v15, v6}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    move-object v8, v1

    .line 101
    goto :goto_2

    .line 102
    :cond_2
    const v1, 0x143b75aa

    .line 103
    .line 104
    .line 105
    invoke-virtual {v15, v1}, Ll2/t;->Y(I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 109
    .line 110
    .line 111
    move-object v8, v3

    .line 112
    :goto_2
    iget-object v0, v0, Ln80/b;->f:Ll80/c;

    .line 113
    .line 114
    iget-object v1, v0, Ll80/c;->a:Ll80/b;

    .line 115
    .line 116
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 117
    .line 118
    .line 119
    move-result v2

    .line 120
    const v4, 0x7f1201dc

    .line 121
    .line 122
    .line 123
    packed-switch v2, :pswitch_data_1

    .line 124
    .line 125
    .line 126
    const v0, 0x248eb47b

    .line 127
    .line 128
    .line 129
    invoke-static {v0, v15, v6}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    throw v0

    .line 134
    :pswitch_1
    const v0, 0x248f1c40

    .line 135
    .line 136
    .line 137
    const v2, 0x7f1201db

    .line 138
    .line 139
    .line 140
    :goto_3
    invoke-static {v0, v2, v15, v15, v6}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    :goto_4
    move-object v9, v0

    .line 145
    goto :goto_6

    .line 146
    :pswitch_2
    const v0, 0x248f0fa4

    .line 147
    .line 148
    .line 149
    const v2, 0x7f1201de

    .line 150
    .line 151
    .line 152
    goto :goto_3

    .line 153
    :pswitch_3
    const v0, 0x248f0324

    .line 154
    .line 155
    .line 156
    const v2, 0x7f1201e0

    .line 157
    .line 158
    .line 159
    goto :goto_3

    .line 160
    :pswitch_4
    const v0, 0x248ef622    # 6.199965E-17f

    .line 161
    .line 162
    .line 163
    :goto_5
    invoke-static {v0, v4, v15, v15, v6}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    goto :goto_4

    .line 168
    :pswitch_5
    const v0, 0x248ee902

    .line 169
    .line 170
    .line 171
    goto :goto_5

    .line 172
    :pswitch_6
    const v0, 0x248edbe2

    .line 173
    .line 174
    .line 175
    goto :goto_5

    .line 176
    :pswitch_7
    const v0, 0x248ece82

    .line 177
    .line 178
    .line 179
    goto :goto_5

    .line 180
    :pswitch_8
    const v2, 0x248eb904

    .line 181
    .line 182
    .line 183
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 184
    .line 185
    .line 186
    sget-object v2, Ln80/f;->a:Ljava/text/DecimalFormat;

    .line 187
    .line 188
    iget-object v0, v0, Ll80/c;->b:Ll80/a;

    .line 189
    .line 190
    if-eqz v0, :cond_3

    .line 191
    .line 192
    iget-wide v3, v0, Ll80/a;->c:D

    .line 193
    .line 194
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    :cond_3
    invoke-virtual {v2, v3}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    invoke-virtual {v0}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    const v2, 0x7f1201d7

    .line 211
    .line 212
    .line 213
    invoke-static {v2, v0, v15}, Ljp/ga;->c(I[Ljava/lang/Object;Ll2/o;)Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 218
    .line 219
    .line 220
    goto :goto_4

    .line 221
    :goto_6
    sget-object v0, Ll80/b;->d:Ll80/b;

    .line 222
    .line 223
    if-ne v1, v0, :cond_4

    .line 224
    .line 225
    const v2, 0x143da7e8

    .line 226
    .line 227
    .line 228
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 229
    .line 230
    .line 231
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 232
    .line 233
    invoke-virtual {v15, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v2

    .line 237
    check-cast v2, Lj91/f;

    .line 238
    .line 239
    invoke-virtual {v2}, Lj91/f;->e()Lg4/p0;

    .line 240
    .line 241
    .line 242
    move-result-object v2

    .line 243
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 244
    .line 245
    .line 246
    :goto_7
    move-object v10, v2

    .line 247
    goto :goto_8

    .line 248
    :cond_4
    const v2, 0x143ed2c4

    .line 249
    .line 250
    .line 251
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 252
    .line 253
    .line 254
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 255
    .line 256
    invoke-virtual {v15, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v2

    .line 260
    check-cast v2, Lj91/f;

    .line 261
    .line 262
    invoke-virtual {v2}, Lj91/f;->f()Lg4/p0;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 267
    .line 268
    .line 269
    goto :goto_7

    .line 270
    :goto_8
    if-ne v1, v0, :cond_5

    .line 271
    .line 272
    const v0, 0x1441592a

    .line 273
    .line 274
    .line 275
    invoke-virtual {v15, v0}, Ll2/t;->Y(I)V

    .line 276
    .line 277
    .line 278
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 279
    .line 280
    invoke-virtual {v15, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    check-cast v0, Lj91/e;

    .line 285
    .line 286
    invoke-virtual {v0}, Lj91/e;->t()J

    .line 287
    .line 288
    .line 289
    move-result-wide v2

    .line 290
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 291
    .line 292
    .line 293
    :goto_9
    move-wide v11, v2

    .line 294
    goto :goto_a

    .line 295
    :cond_5
    const v0, 0x14427bab

    .line 296
    .line 297
    .line 298
    invoke-virtual {v15, v0}, Ll2/t;->Y(I)V

    .line 299
    .line 300
    .line 301
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 302
    .line 303
    invoke-virtual {v15, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    check-cast v0, Lj91/e;

    .line 308
    .line 309
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 310
    .line 311
    .line 312
    move-result-wide v2

    .line 313
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 314
    .line 315
    .line 316
    goto :goto_9

    .line 317
    :goto_a
    invoke-static {v1, v15}, Ln80/a;->q(Ll80/b;Ll2/o;)J

    .line 318
    .line 319
    .line 320
    move-result-wide v13

    .line 321
    const/16 v16, 0x0

    .line 322
    .line 323
    invoke-static/range {v7 .. v16}, Ln80/a;->c(Ljava/lang/Double;Ljava/lang/String;Ljava/lang/String;Lg4/p0;JJLl2/o;I)V

    .line 324
    .line 325
    .line 326
    goto :goto_b

    .line 327
    :cond_6
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 328
    .line 329
    .line 330
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 331
    .line 332
    return-object v0

    .line 333
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch

    .line 334
    .line 335
    .line 336
    .line 337
    .line 338
    .line 339
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method
