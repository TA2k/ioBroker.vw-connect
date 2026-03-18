.class public final synthetic Ld2/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ld2/l;


# direct methods
.method public synthetic constructor <init>(Ld2/l;I)V
    .locals 0

    .line 1
    iput p2, p0, Ld2/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld2/j;->e:Ld2/l;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld2/j;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ljava/lang/Boolean;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    iget-object v0, v0, Ld2/j;->e:Ld2/l;

    .line 17
    .line 18
    iget-object v2, v0, Ld2/l;->C:Ld2/k;

    .line 19
    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    iput-boolean v1, v2, Ld2/k;->c:Z

    .line 25
    .line 26
    invoke-static {v0}, Lv3/f;->o(Lv3/x1;)V

    .line 27
    .line 28
    .line 29
    invoke-static {v0}, Lv3/f;->n(Lv3/y;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v0}, Lv3/f;->m(Lv3/p;)V

    .line 33
    .line 34
    .line 35
    const/4 v0, 0x1

    .line 36
    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    return-object v0

    .line 41
    :pswitch_0
    move-object/from16 v1, p1

    .line 42
    .line 43
    check-cast v1, Lg4/g;

    .line 44
    .line 45
    iget-object v3, v1, Lg4/g;->e:Ljava/lang/String;

    .line 46
    .line 47
    iget-object v0, v0, Ld2/j;->e:Ld2/l;

    .line 48
    .line 49
    iget-object v1, v0, Ld2/l;->C:Ld2/k;

    .line 50
    .line 51
    if-eqz v1, :cond_2

    .line 52
    .line 53
    iget-object v2, v1, Ld2/k;->b:Ljava/lang/String;

    .line 54
    .line 55
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-eqz v2, :cond_1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    iput-object v3, v1, Ld2/k;->b:Ljava/lang/String;

    .line 63
    .line 64
    iget-object v1, v1, Ld2/k;->d:Ld2/e;

    .line 65
    .line 66
    if-eqz v1, :cond_3

    .line 67
    .line 68
    iget-object v2, v0, Ld2/l;->s:Lg4/p0;

    .line 69
    .line 70
    iget-object v4, v0, Ld2/l;->t:Lk4/m;

    .line 71
    .line 72
    iget v5, v0, Ld2/l;->u:I

    .line 73
    .line 74
    iget-boolean v6, v0, Ld2/l;->v:Z

    .line 75
    .line 76
    iget v7, v0, Ld2/l;->w:I

    .line 77
    .line 78
    iget v8, v0, Ld2/l;->x:I

    .line 79
    .line 80
    iput-object v3, v1, Ld2/e;->a:Ljava/lang/String;

    .line 81
    .line 82
    iput-object v2, v1, Ld2/e;->b:Lg4/p0;

    .line 83
    .line 84
    iput-object v4, v1, Ld2/e;->c:Lk4/m;

    .line 85
    .line 86
    iput v5, v1, Ld2/e;->d:I

    .line 87
    .line 88
    iput-boolean v6, v1, Ld2/e;->e:Z

    .line 89
    .line 90
    iput v7, v1, Ld2/e;->f:I

    .line 91
    .line 92
    iput v8, v1, Ld2/e;->g:I

    .line 93
    .line 94
    iget-wide v2, v1, Ld2/e;->s:J

    .line 95
    .line 96
    const/4 v4, 0x2

    .line 97
    shl-long/2addr v2, v4

    .line 98
    const-wide/16 v4, 0x2

    .line 99
    .line 100
    or-long/2addr v2, v4

    .line 101
    iput-wide v2, v1, Ld2/e;->s:J

    .line 102
    .line 103
    invoke-virtual {v1}, Ld2/e;->c()V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_2
    new-instance v1, Ld2/k;

    .line 108
    .line 109
    iget-object v2, v0, Ld2/l;->r:Ljava/lang/String;

    .line 110
    .line 111
    invoke-direct {v1, v2, v3}, Ld2/k;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    new-instance v2, Ld2/e;

    .line 115
    .line 116
    iget-object v4, v0, Ld2/l;->s:Lg4/p0;

    .line 117
    .line 118
    iget-object v5, v0, Ld2/l;->t:Lk4/m;

    .line 119
    .line 120
    iget v6, v0, Ld2/l;->u:I

    .line 121
    .line 122
    iget-boolean v7, v0, Ld2/l;->v:Z

    .line 123
    .line 124
    iget v8, v0, Ld2/l;->w:I

    .line 125
    .line 126
    iget v9, v0, Ld2/l;->x:I

    .line 127
    .line 128
    invoke-direct/range {v2 .. v9}, Ld2/e;-><init>(Ljava/lang/String;Lg4/p0;Lk4/m;IZII)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Ld2/l;->X0()Ld2/e;

    .line 132
    .line 133
    .line 134
    move-result-object v3

    .line 135
    iget-object v3, v3, Ld2/e;->i:Lt4/c;

    .line 136
    .line 137
    invoke-virtual {v2, v3}, Ld2/e;->d(Lt4/c;)V

    .line 138
    .line 139
    .line 140
    iput-object v2, v1, Ld2/k;->d:Ld2/e;

    .line 141
    .line 142
    iput-object v1, v0, Ld2/l;->C:Ld2/k;

    .line 143
    .line 144
    :cond_3
    :goto_1
    invoke-static {v0}, Lv3/f;->o(Lv3/x1;)V

    .line 145
    .line 146
    .line 147
    invoke-static {v0}, Lv3/f;->n(Lv3/y;)V

    .line 148
    .line 149
    .line 150
    invoke-static {v0}, Lv3/f;->m(Lv3/p;)V

    .line 151
    .line 152
    .line 153
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 154
    .line 155
    return-object v0

    .line 156
    :pswitch_1
    move-object/from16 v1, p1

    .line 157
    .line 158
    check-cast v1, Ljava/util/List;

    .line 159
    .line 160
    iget-object v0, v0, Ld2/j;->e:Ld2/l;

    .line 161
    .line 162
    invoke-virtual {v0}, Ld2/l;->X0()Ld2/e;

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    iget-object v3, v0, Ld2/l;->s:Lg4/p0;

    .line 167
    .line 168
    iget-object v0, v0, Ld2/l;->y:Le3/t;

    .line 169
    .line 170
    if-eqz v0, :cond_4

    .line 171
    .line 172
    invoke-interface {v0}, Le3/t;->a()J

    .line 173
    .line 174
    .line 175
    move-result-wide v4

    .line 176
    goto :goto_2

    .line 177
    :cond_4
    sget-wide v4, Le3/s;->i:J

    .line 178
    .line 179
    :goto_2
    const-wide/16 v14, 0x0

    .line 180
    .line 181
    const v16, 0xfffffe

    .line 182
    .line 183
    .line 184
    const-wide/16 v6, 0x0

    .line 185
    .line 186
    const/4 v8, 0x0

    .line 187
    const/4 v9, 0x0

    .line 188
    const-wide/16 v10, 0x0

    .line 189
    .line 190
    const/4 v12, 0x0

    .line 191
    const/4 v13, 0x0

    .line 192
    invoke-static/range {v3 .. v16}, Lg4/p0;->e(Lg4/p0;JJLk4/x;Lk4/t;JLr4/l;IJI)Lg4/p0;

    .line 193
    .line 194
    .line 195
    move-result-object v19

    .line 196
    iget-object v0, v2, Ld2/e;->o:Lt4/m;

    .line 197
    .line 198
    const/4 v3, 0x0

    .line 199
    if-nez v0, :cond_5

    .line 200
    .line 201
    :goto_3
    move-object v6, v3

    .line 202
    goto :goto_4

    .line 203
    :cond_5
    iget-object v4, v2, Ld2/e;->i:Lt4/c;

    .line 204
    .line 205
    if-nez v4, :cond_6

    .line 206
    .line 207
    goto :goto_3

    .line 208
    :cond_6
    new-instance v5, Lg4/g;

    .line 209
    .line 210
    iget-object v6, v2, Ld2/e;->a:Ljava/lang/String;

    .line 211
    .line 212
    invoke-direct {v5, v6}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    iget-object v6, v2, Ld2/e;->j:Lg4/a;

    .line 216
    .line 217
    if-nez v6, :cond_7

    .line 218
    .line 219
    goto :goto_3

    .line 220
    :cond_7
    iget-object v6, v2, Ld2/e;->n:Lg4/s;

    .line 221
    .line 222
    if-nez v6, :cond_8

    .line 223
    .line 224
    goto :goto_3

    .line 225
    :cond_8
    iget-wide v6, v2, Ld2/e;->p:J

    .line 226
    .line 227
    const-wide v8, -0x1fffffffdL

    .line 228
    .line 229
    .line 230
    .line 231
    .line 232
    and-long v27, v6, v8

    .line 233
    .line 234
    new-instance v6, Lg4/l0;

    .line 235
    .line 236
    new-instance v17, Lg4/k0;

    .line 237
    .line 238
    iget v7, v2, Ld2/e;->f:I

    .line 239
    .line 240
    iget-boolean v8, v2, Ld2/e;->e:Z

    .line 241
    .line 242
    iget v9, v2, Ld2/e;->d:I

    .line 243
    .line 244
    iget-object v10, v2, Ld2/e;->c:Lk4/m;

    .line 245
    .line 246
    sget-object v20, Lmx0/s;->d:Lmx0/s;

    .line 247
    .line 248
    move-object/from16 v25, v0

    .line 249
    .line 250
    move-object/from16 v24, v4

    .line 251
    .line 252
    move-object/from16 v18, v5

    .line 253
    .line 254
    move/from16 v21, v7

    .line 255
    .line 256
    move/from16 v22, v8

    .line 257
    .line 258
    move/from16 v23, v9

    .line 259
    .line 260
    move-object/from16 v26, v10

    .line 261
    .line 262
    invoke-direct/range {v17 .. v28}, Lg4/k0;-><init>(Lg4/g;Lg4/p0;Ljava/util/List;IZILt4/c;Lt4/m;Lk4/m;J)V

    .line 263
    .line 264
    .line 265
    move-object/from16 v0, v17

    .line 266
    .line 267
    move-object/from16 v21, v24

    .line 268
    .line 269
    move-object/from16 v22, v26

    .line 270
    .line 271
    new-instance v10, Lg4/o;

    .line 272
    .line 273
    new-instance v17, Landroidx/lifecycle/c1;

    .line 274
    .line 275
    invoke-direct/range {v17 .. v22}, Landroidx/lifecycle/c1;-><init>(Lg4/g;Lg4/p0;Ljava/util/List;Lt4/c;Lk4/m;)V

    .line 276
    .line 277
    .line 278
    iget v14, v2, Ld2/e;->f:I

    .line 279
    .line 280
    iget v15, v2, Ld2/e;->d:I

    .line 281
    .line 282
    move-object/from16 v11, v17

    .line 283
    .line 284
    move-wide/from16 v12, v27

    .line 285
    .line 286
    invoke-direct/range {v10 .. v15}, Lg4/o;-><init>(Landroidx/lifecycle/c1;JII)V

    .line 287
    .line 288
    .line 289
    iget-wide v4, v2, Ld2/e;->l:J

    .line 290
    .line 291
    invoke-direct {v6, v0, v10, v4, v5}, Lg4/l0;-><init>(Lg4/k0;Lg4/o;J)V

    .line 292
    .line 293
    .line 294
    :goto_4
    if-eqz v6, :cond_9

    .line 295
    .line 296
    invoke-interface {v1, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    move-object v3, v6

    .line 300
    :cond_9
    if-eqz v3, :cond_a

    .line 301
    .line 302
    const/4 v0, 0x1

    .line 303
    goto :goto_5

    .line 304
    :cond_a
    const/4 v0, 0x0

    .line 305
    :goto_5
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    return-object v0

    .line 310
    nop

    .line 311
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
