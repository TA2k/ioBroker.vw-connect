.class public final synthetic Li91/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILi91/h1;Z)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li91/u;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Li91/u;->e:I

    iput-object p2, p0, Li91/u;->g:Ljava/lang/Object;

    iput-boolean p3, p0, Li91/u;->f:Z

    return-void
.end method

.method public synthetic constructor <init>(IZLl2/t2;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Li91/u;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Li91/u;->e:I

    iput-boolean p2, p0, Li91/u;->f:Z

    iput-object p3, p0, Li91/u;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/u;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li91/u;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ll2/t2;

    .line 11
    .line 12
    move-object/from16 v2, p1

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Boolean;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    move-object/from16 v3, p2

    .line 21
    .line 22
    check-cast v3, Ll2/o;

    .line 23
    .line 24
    move-object/from16 v4, p3

    .line 25
    .line 26
    check-cast v4, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    and-int/lit8 v5, v4, 0x6

    .line 33
    .line 34
    if-nez v5, :cond_1

    .line 35
    .line 36
    move-object v5, v3

    .line 37
    check-cast v5, Ll2/t;

    .line 38
    .line 39
    invoke-virtual {v5, v2}, Ll2/t;->h(Z)Z

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    if-eqz v5, :cond_0

    .line 44
    .line 45
    const/4 v5, 0x4

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 v5, 0x2

    .line 48
    :goto_0
    or-int/2addr v4, v5

    .line 49
    :cond_1
    and-int/lit8 v5, v4, 0x13

    .line 50
    .line 51
    const/16 v6, 0x12

    .line 52
    .line 53
    const/4 v7, 0x1

    .line 54
    const/4 v8, 0x0

    .line 55
    if-eq v5, v6, :cond_2

    .line 56
    .line 57
    move v5, v7

    .line 58
    goto :goto_1

    .line 59
    :cond_2
    move v5, v8

    .line 60
    :goto_1
    and-int/2addr v4, v7

    .line 61
    move-object v14, v3

    .line 62
    check-cast v14, Ll2/t;

    .line 63
    .line 64
    invoke-virtual {v14, v4, v5}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    if-eqz v3, :cond_5

    .line 69
    .line 70
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 71
    .line 72
    iget v4, v0, Li91/u;->e:I

    .line 73
    .line 74
    if-eqz v2, :cond_4

    .line 75
    .line 76
    const v2, 0x694515e1

    .line 77
    .line 78
    .line 79
    invoke-virtual {v14, v2}, Ll2/t;->Y(I)V

    .line 80
    .line 81
    .line 82
    const v2, 0x7f0804b1

    .line 83
    .line 84
    .line 85
    invoke-static {v2, v8, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 86
    .line 87
    .line 88
    move-result-object v9

    .line 89
    invoke-static {v4}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v10

    .line 93
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 94
    .line 95
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    check-cast v2, Lj91/c;

    .line 100
    .line 101
    iget v2, v2, Lj91/c;->g:F

    .line 102
    .line 103
    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 104
    .line 105
    .line 106
    move-result-object v11

    .line 107
    iget-boolean v0, v0, Li91/u;->f:Z

    .line 108
    .line 109
    if-eqz v0, :cond_3

    .line 110
    .line 111
    const v0, -0xd1eabc1

    .line 112
    .line 113
    .line 114
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 118
    .line 119
    .line 120
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Le3/s;

    .line 125
    .line 126
    iget-wide v0, v0, Le3/s;->a:J

    .line 127
    .line 128
    :goto_2
    move-wide v12, v0

    .line 129
    goto :goto_3

    .line 130
    :cond_3
    const v0, -0xd1ea837

    .line 131
    .line 132
    .line 133
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 134
    .line 135
    .line 136
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 137
    .line 138
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    check-cast v0, Lj91/e;

    .line 143
    .line 144
    invoke-virtual {v0}, Lj91/e;->m()J

    .line 145
    .line 146
    .line 147
    move-result-wide v0

    .line 148
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    goto :goto_2

    .line 152
    :goto_3
    const/4 v15, 0x0

    .line 153
    const/16 v16, 0x0

    .line 154
    .line 155
    invoke-static/range {v9 .. v16}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 159
    .line 160
    .line 161
    goto :goto_4

    .line 162
    :cond_4
    const v0, 0x694a955a

    .line 163
    .line 164
    .line 165
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 166
    .line 167
    .line 168
    const v0, 0x7f0804ae

    .line 169
    .line 170
    .line 171
    invoke-static {v0, v8, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 172
    .line 173
    .line 174
    move-result-object v9

    .line 175
    invoke-static {v4}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v10

    .line 179
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 180
    .line 181
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    check-cast v0, Lj91/c;

    .line 186
    .line 187
    iget v0, v0, Lj91/c;->g:F

    .line 188
    .line 189
    invoke-static {v3, v0}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 190
    .line 191
    .line 192
    move-result-object v11

    .line 193
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    check-cast v0, Le3/s;

    .line 198
    .line 199
    iget-wide v12, v0, Le3/s;->a:J

    .line 200
    .line 201
    const/4 v15, 0x0

    .line 202
    const/16 v16, 0x0

    .line 203
    .line 204
    invoke-static/range {v9 .. v16}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 208
    .line 209
    .line 210
    goto :goto_4

    .line 211
    :cond_5
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 212
    .line 213
    .line 214
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 215
    .line 216
    return-object v0

    .line 217
    :pswitch_0
    iget-object v1, v0, Li91/u;->g:Ljava/lang/Object;

    .line 218
    .line 219
    check-cast v1, Li91/h1;

    .line 220
    .line 221
    move-object/from16 v2, p1

    .line 222
    .line 223
    check-cast v2, Lk1/h1;

    .line 224
    .line 225
    move-object/from16 v3, p2

    .line 226
    .line 227
    check-cast v3, Ll2/o;

    .line 228
    .line 229
    move-object/from16 v4, p3

    .line 230
    .line 231
    check-cast v4, Ljava/lang/Integer;

    .line 232
    .line 233
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 234
    .line 235
    .line 236
    move-result v4

    .line 237
    const-string v5, "$this$Button"

    .line 238
    .line 239
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    and-int/lit8 v2, v4, 0x11

    .line 243
    .line 244
    const/16 v5, 0x10

    .line 245
    .line 246
    const/4 v6, 0x1

    .line 247
    const/4 v7, 0x0

    .line 248
    if-eq v2, v5, :cond_6

    .line 249
    .line 250
    move v2, v6

    .line 251
    goto :goto_5

    .line 252
    :cond_6
    move v2, v7

    .line 253
    :goto_5
    and-int/2addr v4, v6

    .line 254
    move-object v13, v3

    .line 255
    check-cast v13, Ll2/t;

    .line 256
    .line 257
    invoke-virtual {v13, v4, v2}, Ll2/t;->O(IZ)Z

    .line 258
    .line 259
    .line 260
    move-result v2

    .line 261
    if-eqz v2, :cond_8

    .line 262
    .line 263
    const v2, 0x4da296df    # 3.4097456E8f

    .line 264
    .line 265
    .line 266
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 267
    .line 268
    .line 269
    iget v2, v0, Li91/u;->e:I

    .line 270
    .line 271
    invoke-static {v2, v7, v13}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 272
    .line 273
    .line 274
    move-result-object v8

    .line 275
    const/16 v2, 0x14

    .line 276
    .line 277
    int-to-float v2, v2

    .line 278
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 279
    .line 280
    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 281
    .line 282
    .line 283
    move-result-object v10

    .line 284
    iget-boolean v0, v0, Li91/u;->f:Z

    .line 285
    .line 286
    if-eqz v0, :cond_7

    .line 287
    .line 288
    iget-wide v0, v1, Li91/h1;->b:J

    .line 289
    .line 290
    :goto_6
    move-wide v11, v0

    .line 291
    goto :goto_7

    .line 292
    :cond_7
    iget-wide v0, v1, Li91/h1;->d:J

    .line 293
    .line 294
    goto :goto_6

    .line 295
    :goto_7
    const/16 v14, 0x1b0

    .line 296
    .line 297
    const/4 v15, 0x0

    .line 298
    const/4 v9, 0x0

    .line 299
    invoke-static/range {v8 .. v15}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v13, v7}, Ll2/t;->q(Z)V

    .line 303
    .line 304
    .line 305
    goto :goto_8

    .line 306
    :cond_8
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 307
    .line 308
    .line 309
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 310
    .line 311
    return-object v0

    .line 312
    nop

    .line 313
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
