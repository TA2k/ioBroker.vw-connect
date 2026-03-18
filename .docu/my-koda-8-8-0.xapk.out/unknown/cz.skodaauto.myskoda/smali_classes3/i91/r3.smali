.class public final synthetic Li91/r3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lay0/k;

.field public final synthetic e:Z

.field public final synthetic f:I

.field public final synthetic g:F

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lgy0/f;

.field public final synthetic k:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lay0/k;ZIFLay0/k;Lay0/a;Lgy0/f;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/r3;->d:Lay0/k;

    .line 5
    .line 6
    iput-boolean p2, p0, Li91/r3;->e:Z

    .line 7
    .line 8
    iput p3, p0, Li91/r3;->f:I

    .line 9
    .line 10
    iput p4, p0, Li91/r3;->g:F

    .line 11
    .line 12
    iput-object p5, p0, Li91/r3;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Li91/r3;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Li91/r3;->j:Lgy0/f;

    .line 17
    .line 18
    iput-object p8, p0, Li91/r3;->k:Lay0/k;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Landroidx/compose/foundation/layout/c;

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
    const-string v4, "$this$BoxWithConstraints"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v4, v3, 0x6

    .line 25
    .line 26
    if-nez v4, :cond_1

    .line 27
    .line 28
    move-object v4, v2

    .line 29
    check-cast v4, Ll2/t;

    .line 30
    .line 31
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_0

    .line 36
    .line 37
    const/4 v4, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v4, 0x2

    .line 40
    :goto_0
    or-int/2addr v3, v4

    .line 41
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 42
    .line 43
    const/16 v5, 0x12

    .line 44
    .line 45
    const/4 v6, 0x1

    .line 46
    const/4 v7, 0x0

    .line 47
    if-eq v4, v5, :cond_2

    .line 48
    .line 49
    move v4, v6

    .line 50
    goto :goto_1

    .line 51
    :cond_2
    move v4, v7

    .line 52
    :goto_1
    and-int/2addr v3, v6

    .line 53
    move-object v12, v2

    .line 54
    check-cast v12, Ll2/t;

    .line 55
    .line 56
    invoke-virtual {v12, v3, v4}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_d

    .line 61
    .line 62
    iget-object v2, v0, Li91/r3;->d:Lay0/k;

    .line 63
    .line 64
    if-eqz v2, :cond_3

    .line 65
    .line 66
    const v3, 0x3cd59fb1

    .line 67
    .line 68
    .line 69
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 70
    .line 71
    .line 72
    invoke-static {v12}, Li91/u3;->g(Ll2/t;)Li91/v3;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    const v3, 0x5ddecfc6

    .line 81
    .line 82
    .line 83
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 87
    .line 88
    .line 89
    const/4 v3, 0x0

    .line 90
    :goto_2
    iget v8, v0, Li91/r3;->g:F

    .line 91
    .line 92
    iget-object v10, v0, Li91/r3;->j:Lgy0/f;

    .line 93
    .line 94
    if-nez v3, :cond_4

    .line 95
    .line 96
    const v1, 0x5ddf5cd9

    .line 97
    .line 98
    .line 99
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 103
    .line 104
    .line 105
    move-object/from16 v18, v10

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_4
    const v4, 0x5ddf5cda

    .line 109
    .line 110
    .line 111
    invoke-virtual {v12, v4}, Ll2/t;->Y(I)V

    .line 112
    .line 113
    .line 114
    if-eqz v2, :cond_c

    .line 115
    .line 116
    invoke-static {v8}, Lcy0/a;->i(F)I

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    invoke-interface {v2, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    check-cast v2, Ljava/lang/String;

    .line 129
    .line 130
    iget-wide v4, v1, Landroidx/compose/foundation/layout/c;->b:J

    .line 131
    .line 132
    invoke-static {v4, v5}, Lt4/a;->h(J)I

    .line 133
    .line 134
    .line 135
    move-result v11

    .line 136
    iget-object v1, v3, Li91/v3;->a:Ll2/b1;

    .line 137
    .line 138
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    check-cast v1, Ljava/lang/Boolean;

    .line 143
    .line 144
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    const/4 v14, 0x0

    .line 149
    move v9, v8

    .line 150
    move-object v13, v12

    .line 151
    move v12, v1

    .line 152
    move-object v8, v2

    .line 153
    invoke-static/range {v8 .. v14}, Li91/u3;->e(Ljava/lang/String;FLgy0/f;IZLl2/o;I)V

    .line 154
    .line 155
    .line 156
    move v8, v9

    .line 157
    move-object/from16 v18, v10

    .line 158
    .line 159
    move-object v12, v13

    .line 160
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 161
    .line 162
    .line 163
    :goto_3
    iget-boolean v1, v0, Li91/r3;->e:Z

    .line 164
    .line 165
    if-eqz v1, :cond_5

    .line 166
    .line 167
    const v2, 0x7f0804c7

    .line 168
    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_5
    const v2, 0x7f0804c6

    .line 172
    .line 173
    .line 174
    :goto_4
    iget v4, v0, Li91/r3;->f:I

    .line 175
    .line 176
    if-gez v4, :cond_6

    .line 177
    .line 178
    move v15, v7

    .line 179
    goto :goto_5

    .line 180
    :cond_6
    move v15, v4

    .line 181
    :goto_5
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v5

    .line 185
    iget-object v6, v0, Li91/r3;->h:Lay0/k;

    .line 186
    .line 187
    invoke-virtual {v12, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result v9

    .line 191
    or-int/2addr v5, v9

    .line 192
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v9

    .line 196
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 197
    .line 198
    if-nez v5, :cond_7

    .line 199
    .line 200
    if-ne v9, v10, :cond_8

    .line 201
    .line 202
    :cond_7
    new-instance v9, Li40/j0;

    .line 203
    .line 204
    const/4 v5, 0x5

    .line 205
    invoke-direct {v9, v5, v3, v6}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v12, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    :cond_8
    check-cast v9, Lay0/k;

    .line 212
    .line 213
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    move-result v5

    .line 217
    iget-object v6, v0, Li91/r3;->i:Lay0/a;

    .line 218
    .line 219
    invoke-virtual {v12, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v11

    .line 223
    or-int/2addr v5, v11

    .line 224
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v11

    .line 228
    if-nez v5, :cond_9

    .line 229
    .line 230
    if-ne v11, v10, :cond_a

    .line 231
    .line 232
    :cond_9
    new-instance v11, Li2/t;

    .line 233
    .line 234
    const/16 v5, 0xe

    .line 235
    .line 236
    invoke-direct {v11, v5, v3, v6}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v12, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    :cond_a
    check-cast v11, Lay0/a;

    .line 243
    .line 244
    new-instance v3, Ldl0/a;

    .line 245
    .line 246
    const/4 v5, 0x7

    .line 247
    invoke-direct {v3, v2, v5}, Ldl0/a;-><init>(II)V

    .line 248
    .line 249
    .line 250
    const v2, -0x5d5874ed

    .line 251
    .line 252
    .line 253
    invoke-static {v2, v12, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 254
    .line 255
    .line 256
    move-result-object v16

    .line 257
    new-instance v2, La71/m;

    .line 258
    .line 259
    const/4 v3, 0x3

    .line 260
    invoke-direct {v2, v3, v1}, La71/m;-><init>(IZ)V

    .line 261
    .line 262
    .line 263
    const v1, -0x74da94ec

    .line 264
    .line 265
    .line 266
    invoke-static {v1, v12, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 267
    .line 268
    .line 269
    move-result-object v17

    .line 270
    const/high16 v20, 0x36000000

    .line 271
    .line 272
    const/4 v10, 0x0

    .line 273
    move-object v13, v12

    .line 274
    move-object v12, v11

    .line 275
    const/4 v11, 0x0

    .line 276
    move-object/from16 v19, v13

    .line 277
    .line 278
    const/4 v13, 0x0

    .line 279
    const/4 v14, 0x0

    .line 280
    invoke-static/range {v8 .. v20}, Lh2/q9;->d(FLay0/k;Lx2/s;ZLay0/a;Lh2/u8;Li1/l;ILt2/b;Lt2/b;Lgy0/f;Ll2/o;I)V

    .line 281
    .line 282
    .line 283
    move-object/from16 v12, v19

    .line 284
    .line 285
    iget-object v10, v0, Li91/r3;->k:Lay0/k;

    .line 286
    .line 287
    if-nez v10, :cond_b

    .line 288
    .line 289
    const v0, 0x5df6b7da

    .line 290
    .line 291
    .line 292
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 293
    .line 294
    .line 295
    :goto_6
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 296
    .line 297
    .line 298
    goto :goto_7

    .line 299
    :cond_b
    const v0, 0x5df6b7db

    .line 300
    .line 301
    .line 302
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 303
    .line 304
    .line 305
    const/4 v11, 0x0

    .line 306
    const/4 v13, 0x0

    .line 307
    move v9, v4

    .line 308
    move-object/from16 v8, v18

    .line 309
    .line 310
    invoke-static/range {v8 .. v13}, Li91/u3;->d(Lgy0/f;ILay0/k;Lx2/s;Ll2/o;I)V

    .line 311
    .line 312
    .line 313
    goto :goto_6

    .line 314
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 315
    .line 316
    const-string v1, "Required value was null."

    .line 317
    .line 318
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    throw v0

    .line 322
    :cond_d
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 323
    .line 324
    .line 325
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 326
    .line 327
    return-object v0
.end method
