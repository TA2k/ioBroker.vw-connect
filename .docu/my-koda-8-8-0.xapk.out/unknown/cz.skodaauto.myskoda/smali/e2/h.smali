.class public final Le2/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Llx0/e;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Le2/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le2/h;->f:Llx0/e;

    .line 4
    .line 5
    iput-boolean p2, p0, Le2/h;->e:Z

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
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Le2/h;->d:I

    .line 4
    .line 5
    iget-object v2, v0, Le2/h;->f:Llx0/e;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    iget-boolean v0, v0, Le2/h;->e:Z

    .line 9
    .line 10
    packed-switch v1, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    move-object/from16 v1, p1

    .line 14
    .line 15
    check-cast v1, Lk1/h1;

    .line 16
    .line 17
    move-object/from16 v1, p2

    .line 18
    .line 19
    check-cast v1, Ll2/o;

    .line 20
    .line 21
    move-object/from16 v4, p3

    .line 22
    .line 23
    check-cast v4, Ljava/lang/Number;

    .line 24
    .line 25
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    and-int/lit8 v5, v4, 0x11

    .line 30
    .line 31
    const/16 v6, 0x10

    .line 32
    .line 33
    const/4 v7, 0x1

    .line 34
    if-eq v5, v6, :cond_0

    .line 35
    .line 36
    move v5, v7

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move v5, v3

    .line 39
    :goto_0
    and-int/2addr v4, v7

    .line 40
    move-object v11, v1

    .line 41
    check-cast v11, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {v11, v4, v5}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_4

    .line 48
    .line 49
    check-cast v2, Lt2/b;

    .line 50
    .line 51
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {v2, v11, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    sget v1, Lh2/o0;->d:F

    .line 59
    .line 60
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 61
    .line 62
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-static {v11, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 67
    .line 68
    .line 69
    sget-object v1, Li2/a1;->g:Lj3/f;

    .line 70
    .line 71
    if-eqz v1, :cond_1

    .line 72
    .line 73
    :goto_1
    move-object v6, v1

    .line 74
    goto :goto_2

    .line 75
    :cond_1
    new-instance v12, Lj3/e;

    .line 76
    .line 77
    const/16 v21, 0x0

    .line 78
    .line 79
    const/16 v22, 0xe0

    .line 80
    .line 81
    const-string v13, "Filled.ArrowDropDown"

    .line 82
    .line 83
    const/high16 v14, 0x41c00000    # 24.0f

    .line 84
    .line 85
    const/high16 v15, 0x41c00000    # 24.0f

    .line 86
    .line 87
    const/high16 v16, 0x41c00000    # 24.0f

    .line 88
    .line 89
    const/high16 v17, 0x41c00000    # 24.0f

    .line 90
    .line 91
    const-wide/16 v18, 0x0

    .line 92
    .line 93
    const/16 v20, 0x0

    .line 94
    .line 95
    invoke-direct/range {v12 .. v22}, Lj3/e;-><init>(Ljava/lang/String;FFFFJIZI)V

    .line 96
    .line 97
    .line 98
    sget v1, Lj3/h0;->a:I

    .line 99
    .line 100
    new-instance v1, Le3/p0;

    .line 101
    .line 102
    sget-wide v4, Le3/s;->b:J

    .line 103
    .line 104
    invoke-direct {v1, v4, v5}, Le3/p0;-><init>(J)V

    .line 105
    .line 106
    .line 107
    new-instance v4, Ljava/util/ArrayList;

    .line 108
    .line 109
    const/16 v5, 0x20

    .line 110
    .line 111
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 112
    .line 113
    .line 114
    new-instance v5, Lj3/n;

    .line 115
    .line 116
    const/high16 v6, 0x40e00000    # 7.0f

    .line 117
    .line 118
    const/high16 v7, 0x41200000    # 10.0f

    .line 119
    .line 120
    invoke-direct {v5, v6, v7}, Lj3/n;-><init>(FF)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    new-instance v5, Lj3/u;

    .line 127
    .line 128
    const/high16 v6, 0x40a00000    # 5.0f

    .line 129
    .line 130
    invoke-direct {v5, v6, v6}, Lj3/u;-><init>(FF)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    new-instance v5, Lj3/u;

    .line 137
    .line 138
    const/high16 v7, -0x3f600000    # -5.0f

    .line 139
    .line 140
    invoke-direct {v5, v6, v7}, Lj3/u;-><init>(FF)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    sget-object v5, Lj3/j;->c:Lj3/j;

    .line 147
    .line 148
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    invoke-static {v12, v4, v1}, Lj3/e;->a(Lj3/e;Ljava/util/ArrayList;Le3/p0;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v12}, Lj3/e;->b()Lj3/f;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    sput-object v1, Li2/a1;->g:Lj3/f;

    .line 159
    .line 160
    goto :goto_1

    .line 161
    :goto_2
    if-eqz v0, :cond_2

    .line 162
    .line 163
    const v1, 0x59f760c7

    .line 164
    .line 165
    .line 166
    invoke-virtual {v11, v1}, Ll2/t;->Y(I)V

    .line 167
    .line 168
    .line 169
    const v1, 0x7f1205a2

    .line 170
    .line 171
    .line 172
    invoke-static {v11, v1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 177
    .line 178
    .line 179
    :goto_3
    move-object v7, v1

    .line 180
    goto :goto_4

    .line 181
    :cond_2
    const v1, 0x59f8d106

    .line 182
    .line 183
    .line 184
    invoke-virtual {v11, v1}, Ll2/t;->Y(I)V

    .line 185
    .line 186
    .line 187
    const v1, 0x7f1205a6

    .line 188
    .line 189
    .line 190
    invoke-static {v11, v1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 195
    .line 196
    .line 197
    goto :goto_3

    .line 198
    :goto_4
    if-eqz v0, :cond_3

    .line 199
    .line 200
    const/high16 v0, 0x43340000    # 180.0f

    .line 201
    .line 202
    goto :goto_5

    .line 203
    :cond_3
    const/4 v0, 0x0

    .line 204
    :goto_5
    invoke-static {v2, v0}, Ljp/ca;->c(Lx2/s;F)Lx2/s;

    .line 205
    .line 206
    .line 207
    move-result-object v8

    .line 208
    const/4 v12, 0x0

    .line 209
    const/16 v13, 0x8

    .line 210
    .line 211
    const-wide/16 v9, 0x0

    .line 212
    .line 213
    invoke-static/range {v6 .. v13}, Lh2/f5;->b(Lj3/f;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 214
    .line 215
    .line 216
    goto :goto_6

    .line 217
    :cond_4
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 218
    .line 219
    .line 220
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 221
    .line 222
    return-object v0

    .line 223
    :pswitch_0
    move-object/from16 v1, p1

    .line 224
    .line 225
    check-cast v1, Lx2/s;

    .line 226
    .line 227
    move-object/from16 v4, p2

    .line 228
    .line 229
    check-cast v4, Ll2/o;

    .line 230
    .line 231
    move-object/from16 v5, p3

    .line 232
    .line 233
    check-cast v5, Ljava/lang/Number;

    .line 234
    .line 235
    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    .line 236
    .line 237
    .line 238
    check-cast v4, Ll2/t;

    .line 239
    .line 240
    const v5, -0xbba9706

    .line 241
    .line 242
    .line 243
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 244
    .line 245
    .line 246
    sget-object v5, Le2/e1;->a:Ll2/e0;

    .line 247
    .line 248
    invoke-virtual {v4, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v5

    .line 252
    check-cast v5, Le2/d1;

    .line 253
    .line 254
    iget-wide v5, v5, Le2/d1;->a:J

    .line 255
    .line 256
    invoke-virtual {v4, v5, v6}, Ll2/t;->f(J)Z

    .line 257
    .line 258
    .line 259
    move-result v7

    .line 260
    check-cast v2, Lay0/a;

    .line 261
    .line 262
    invoke-virtual {v4, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 263
    .line 264
    .line 265
    move-result v8

    .line 266
    or-int/2addr v7, v8

    .line 267
    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    .line 268
    .line 269
    .line 270
    move-result v8

    .line 271
    or-int/2addr v7, v8

    .line 272
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v8

    .line 276
    if-nez v7, :cond_5

    .line 277
    .line 278
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 279
    .line 280
    if-ne v8, v7, :cond_6

    .line 281
    .line 282
    :cond_5
    new-instance v8, Le2/f;

    .line 283
    .line 284
    invoke-direct {v8, v5, v6, v2, v0}, Le2/f;-><init>(JLay0/a;Z)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 288
    .line 289
    .line 290
    :cond_6
    check-cast v8, Lay0/k;

    .line 291
    .line 292
    invoke-static {v1, v8}, Landroidx/compose/ui/draw/a;->b(Lx2/s;Lay0/k;)Lx2/s;

    .line 293
    .line 294
    .line 295
    move-result-object v0

    .line 296
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    .line 297
    .line 298
    .line 299
    return-object v0

    .line 300
    nop

    .line 301
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
