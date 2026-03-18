.class public final synthetic Li91/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Z

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Z

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Z

.field public final synthetic m:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILay0/a;Le1/t;Li91/h1;Ljava/lang/Integer;Ljava/lang/String;Lx2/s;ZZZ)V
    .locals 0

    .line 1
    iput p1, p0, Li91/v;->d:I

    iput-object p6, p0, Li91/v;->e:Ljava/lang/String;

    iput-object p4, p0, Li91/v;->f:Ljava/lang/Object;

    iput-object p7, p0, Li91/v;->g:Lx2/s;

    iput-boolean p8, p0, Li91/v;->h:Z

    iput-object p2, p0, Li91/v;->i:Lay0/a;

    iput-boolean p9, p0, Li91/v;->j:Z

    iput-object p3, p0, Li91/v;->k:Ljava/lang/Object;

    iput-boolean p10, p0, Li91/v;->l:Z

    iput-object p5, p0, Li91/v;->m:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;ZZZLjava/lang/String;Lay0/a;Lay0/a;Lay0/a;Lh2/z1;I)V
    .locals 0

    .line 2
    const/4 p10, 0x2

    iput p10, p0, Li91/v;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/v;->g:Lx2/s;

    iput-boolean p2, p0, Li91/v;->h:Z

    iput-boolean p3, p0, Li91/v;->j:Z

    iput-boolean p4, p0, Li91/v;->l:Z

    iput-object p5, p0, Li91/v;->e:Ljava/lang/String;

    iput-object p6, p0, Li91/v;->i:Lay0/a;

    iput-object p7, p0, Li91/v;->f:Ljava/lang/Object;

    iput-object p8, p0, Li91/v;->k:Ljava/lang/Object;

    iput-object p9, p0, Li91/v;->m:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/v;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li91/v;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v8, v1

    .line 11
    check-cast v8, Lay0/a;

    .line 12
    .line 13
    iget-object v1, v0, Li91/v;->k:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v9, v1

    .line 16
    check-cast v9, Lay0/a;

    .line 17
    .line 18
    iget-object v1, v0, Li91/v;->m:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v10, v1

    .line 21
    check-cast v10, Lh2/z1;

    .line 22
    .line 23
    move-object/from16 v11, p1

    .line 24
    .line 25
    check-cast v11, Ll2/o;

    .line 26
    .line 27
    move-object/from16 v1, p2

    .line 28
    .line 29
    check-cast v1, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const/4 v1, 0x7

    .line 35
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 36
    .line 37
    .line 38
    move-result v12

    .line 39
    iget-object v2, v0, Li91/v;->g:Lx2/s;

    .line 40
    .line 41
    iget-boolean v3, v0, Li91/v;->h:Z

    .line 42
    .line 43
    iget-boolean v4, v0, Li91/v;->j:Z

    .line 44
    .line 45
    iget-boolean v5, v0, Li91/v;->l:Z

    .line 46
    .line 47
    iget-object v6, v0, Li91/v;->e:Ljava/lang/String;

    .line 48
    .line 49
    iget-object v7, v0, Li91/v;->i:Lay0/a;

    .line 50
    .line 51
    invoke-static/range {v2 .. v12}, Lh2/m3;->j(Lx2/s;ZZZLjava/lang/String;Lay0/a;Lay0/a;Lay0/a;Lh2/z1;Ll2/o;I)V

    .line 52
    .line 53
    .line 54
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    return-object v0

    .line 57
    :pswitch_0
    iget-object v1, v0, Li91/v;->f:Ljava/lang/Object;

    .line 58
    .line 59
    move-object v6, v1

    .line 60
    check-cast v6, Li91/h1;

    .line 61
    .line 62
    iget-object v1, v0, Li91/v;->k:Ljava/lang/Object;

    .line 63
    .line 64
    move-object v13, v1

    .line 65
    check-cast v13, Le1/t;

    .line 66
    .line 67
    iget-object v1, v0, Li91/v;->m:Ljava/lang/Object;

    .line 68
    .line 69
    move-object v4, v1

    .line 70
    check-cast v4, Ljava/lang/Integer;

    .line 71
    .line 72
    move-object/from16 v1, p1

    .line 73
    .line 74
    check-cast v1, Ll2/o;

    .line 75
    .line 76
    move-object/from16 v2, p2

    .line 77
    .line 78
    check-cast v2, Ljava/lang/Integer;

    .line 79
    .line 80
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    and-int/lit8 v3, v2, 0x3

    .line 85
    .line 86
    const/4 v5, 0x2

    .line 87
    const/4 v7, 0x1

    .line 88
    const/4 v8, 0x0

    .line 89
    if-eq v3, v5, :cond_0

    .line 90
    .line 91
    move v3, v7

    .line 92
    goto :goto_0

    .line 93
    :cond_0
    move v3, v8

    .line 94
    :goto_0
    and-int/2addr v2, v7

    .line 95
    check-cast v1, Ll2/t;

    .line 96
    .line 97
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    if-eqz v2, :cond_4

    .line 102
    .line 103
    sget-object v10, Ls1/f;->a:Ls1/e;

    .line 104
    .line 105
    int-to-float v14, v8

    .line 106
    const/16 v19, 0x0

    .line 107
    .line 108
    move v15, v14

    .line 109
    move/from16 v16, v14

    .line 110
    .line 111
    move/from16 v17, v14

    .line 112
    .line 113
    move/from16 v18, v14

    .line 114
    .line 115
    invoke-static/range {v14 .. v19}, Lh2/o0;->b(FFFFFI)Lh2/q0;

    .line 116
    .line 117
    .line 118
    move-result-object v12

    .line 119
    iget-object v5, v0, Li91/v;->e:Ljava/lang/String;

    .line 120
    .line 121
    if-eqz v5, :cond_1

    .line 122
    .line 123
    const/16 v2, 0x18

    .line 124
    .line 125
    int-to-float v2, v2

    .line 126
    const/16 v3, 0xa

    .line 127
    .line 128
    int-to-float v3, v3

    .line 129
    new-instance v7, Lk1/a1;

    .line 130
    .line 131
    invoke-direct {v7, v2, v3, v2, v3}, Lk1/a1;-><init>(FFFF)V

    .line 132
    .line 133
    .line 134
    :goto_1
    move-object v14, v7

    .line 135
    goto :goto_2

    .line 136
    :cond_1
    new-instance v7, Lk1/a1;

    .line 137
    .line 138
    invoke-direct {v7, v14, v14, v14, v14}, Lk1/a1;-><init>(FFFF)V

    .line 139
    .line 140
    .line 141
    goto :goto_1

    .line 142
    :goto_2
    invoke-virtual {v6, v1}, Li91/h1;->a(Ll2/o;)Lh2/n0;

    .line 143
    .line 144
    .line 145
    move-result-object v11

    .line 146
    iget-object v2, v0, Li91/v;->g:Lx2/s;

    .line 147
    .line 148
    const/16 v3, 0x2c

    .line 149
    .line 150
    if-eqz v5, :cond_3

    .line 151
    .line 152
    iget-boolean v7, v0, Li91/v;->h:Z

    .line 153
    .line 154
    if-eqz v7, :cond_2

    .line 155
    .line 156
    const/high16 v7, 0x3f800000    # 1.0f

    .line 157
    .line 158
    goto :goto_3

    .line 159
    :cond_2
    const v7, 0x3f19999a    # 0.6f

    .line 160
    .line 161
    .line 162
    :goto_3
    invoke-static {v2, v7}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    int-to-float v3, v3

    .line 167
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->i(Lx2/s;F)Lx2/s;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    :goto_4
    move-object v8, v2

    .line 172
    goto :goto_5

    .line 173
    :cond_3
    int-to-float v3, v3

    .line 174
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    goto :goto_4

    .line 179
    :goto_5
    new-instance v2, Li91/k;

    .line 180
    .line 181
    iget-boolean v3, v0, Li91/v;->l:Z

    .line 182
    .line 183
    iget-boolean v7, v0, Li91/v;->j:Z

    .line 184
    .line 185
    invoke-direct/range {v2 .. v7}, Li91/k;-><init>(ZLjava/lang/Integer;Ljava/lang/String;Li91/h1;Z)V

    .line 186
    .line 187
    .line 188
    const v3, 0x59052a7b

    .line 189
    .line 190
    .line 191
    invoke-static {v3, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 192
    .line 193
    .line 194
    move-result-object v15

    .line 195
    const/high16 v17, 0x30000000

    .line 196
    .line 197
    const/16 v18, 0x100

    .line 198
    .line 199
    move v9, v7

    .line 200
    iget-object v7, v0, Li91/v;->i:Lay0/a;

    .line 201
    .line 202
    move-object/from16 v16, v1

    .line 203
    .line 204
    invoke-static/range {v7 .. v18}, Lh2/r;->d(Lay0/a;Lx2/s;ZLe3/n0;Lh2/n0;Lh2/q0;Le1/t;Lk1/z0;Lt2/b;Ll2/o;II)V

    .line 205
    .line 206
    .line 207
    goto :goto_6

    .line 208
    :cond_4
    move-object/from16 v16, v1

    .line 209
    .line 210
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 211
    .line 212
    .line 213
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 214
    .line 215
    return-object v0

    .line 216
    :pswitch_1
    iget-object v1, v0, Li91/v;->f:Ljava/lang/Object;

    .line 217
    .line 218
    move-object v6, v1

    .line 219
    check-cast v6, Li91/h1;

    .line 220
    .line 221
    iget-object v1, v0, Li91/v;->k:Ljava/lang/Object;

    .line 222
    .line 223
    move-object v5, v1

    .line 224
    check-cast v5, Le1/t;

    .line 225
    .line 226
    iget-object v1, v0, Li91/v;->m:Ljava/lang/Object;

    .line 227
    .line 228
    move-object v7, v1

    .line 229
    check-cast v7, Ljava/lang/Integer;

    .line 230
    .line 231
    move-object/from16 v1, p1

    .line 232
    .line 233
    check-cast v1, Ll2/o;

    .line 234
    .line 235
    move-object/from16 v2, p2

    .line 236
    .line 237
    check-cast v2, Ljava/lang/Integer;

    .line 238
    .line 239
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 240
    .line 241
    .line 242
    move-result v2

    .line 243
    and-int/lit8 v3, v2, 0x3

    .line 244
    .line 245
    const/4 v4, 0x2

    .line 246
    const/4 v8, 0x0

    .line 247
    const/4 v9, 0x1

    .line 248
    if-eq v3, v4, :cond_5

    .line 249
    .line 250
    move v3, v9

    .line 251
    goto :goto_7

    .line 252
    :cond_5
    move v3, v8

    .line 253
    :goto_7
    and-int/2addr v2, v9

    .line 254
    check-cast v1, Ll2/t;

    .line 255
    .line 256
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 257
    .line 258
    .line 259
    move-result v2

    .line 260
    if-eqz v2, :cond_6

    .line 261
    .line 262
    sget-object v2, Lh2/k5;->c:Ll2/u2;

    .line 263
    .line 264
    int-to-float v3, v8

    .line 265
    new-instance v4, Lt4/f;

    .line 266
    .line 267
    invoke-direct {v4, v3}, Lt4/f;-><init>(F)V

    .line 268
    .line 269
    .line 270
    invoke-virtual {v2, v4}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 271
    .line 272
    .line 273
    move-result-object v13

    .line 274
    new-instance v2, Li91/v;

    .line 275
    .line 276
    const/4 v3, 0x1

    .line 277
    iget-object v4, v0, Li91/v;->i:Lay0/a;

    .line 278
    .line 279
    iget-object v8, v0, Li91/v;->e:Ljava/lang/String;

    .line 280
    .line 281
    iget-object v9, v0, Li91/v;->g:Lx2/s;

    .line 282
    .line 283
    iget-boolean v10, v0, Li91/v;->h:Z

    .line 284
    .line 285
    iget-boolean v11, v0, Li91/v;->j:Z

    .line 286
    .line 287
    iget-boolean v12, v0, Li91/v;->l:Z

    .line 288
    .line 289
    invoke-direct/range {v2 .. v12}, Li91/v;-><init>(ILay0/a;Le1/t;Li91/h1;Ljava/lang/Integer;Ljava/lang/String;Lx2/s;ZZZ)V

    .line 290
    .line 291
    .line 292
    const v0, 0x9e0e06b

    .line 293
    .line 294
    .line 295
    invoke-static {v0, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    const/16 v2, 0x38

    .line 300
    .line 301
    invoke-static {v13, v0, v1, v2}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 302
    .line 303
    .line 304
    goto :goto_8

    .line 305
    :cond_6
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 306
    .line 307
    .line 308
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 309
    .line 310
    return-object v0

    .line 311
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
