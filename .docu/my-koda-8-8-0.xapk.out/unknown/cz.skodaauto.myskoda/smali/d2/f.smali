.class public final synthetic Ld2/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ld2/i;


# direct methods
.method public synthetic constructor <init>(Ld2/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Ld2/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld2/f;->e:Ld2/i;

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
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld2/f;->d:I

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
    iget-object v0, v0, Ld2/f;->e:Ld2/i;

    .line 17
    .line 18
    iget-object v2, v0, Ld2/i;->G:Ld2/h;

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
    iget-object v3, v0, Ld2/i;->C:Lay0/k;

    .line 25
    .line 26
    if-eqz v3, :cond_1

    .line 27
    .line 28
    invoke-interface {v3, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    :cond_1
    iget-object v2, v0, Ld2/i;->G:Ld2/h;

    .line 32
    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    iput-boolean v1, v2, Ld2/h;->c:Z

    .line 36
    .line 37
    :cond_2
    invoke-static {v0}, Lv3/f;->o(Lv3/x1;)V

    .line 38
    .line 39
    .line 40
    invoke-static {v0}, Lv3/f;->n(Lv3/y;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v0}, Lv3/f;->m(Lv3/p;)V

    .line 44
    .line 45
    .line 46
    const/4 v0, 0x1

    .line 47
    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    return-object v0

    .line 52
    :pswitch_0
    move-object/from16 v2, p1

    .line 53
    .line 54
    check-cast v2, Lg4/g;

    .line 55
    .line 56
    iget-object v0, v0, Ld2/f;->e:Ld2/i;

    .line 57
    .line 58
    iget-object v1, v0, Ld2/i;->G:Ld2/h;

    .line 59
    .line 60
    sget-object v9, Lmx0/s;->d:Lmx0/s;

    .line 61
    .line 62
    if-eqz v1, :cond_5

    .line 63
    .line 64
    iget-object v3, v1, Ld2/h;->b:Lg4/g;

    .line 65
    .line 66
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    if-eqz v3, :cond_3

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_3
    iput-object v2, v1, Ld2/h;->b:Lg4/g;

    .line 74
    .line 75
    iget-object v1, v1, Ld2/h;->d:Ld2/d;

    .line 76
    .line 77
    if-eqz v1, :cond_6

    .line 78
    .line 79
    iget-object v3, v0, Ld2/i;->s:Lg4/p0;

    .line 80
    .line 81
    iget-object v4, v0, Ld2/i;->t:Lk4/m;

    .line 82
    .line 83
    iget v5, v0, Ld2/i;->v:I

    .line 84
    .line 85
    iget-boolean v6, v0, Ld2/i;->w:Z

    .line 86
    .line 87
    iget v7, v0, Ld2/i;->x:I

    .line 88
    .line 89
    iget v8, v0, Ld2/i;->y:I

    .line 90
    .line 91
    iput-object v2, v1, Ld2/d;->a:Lg4/g;

    .line 92
    .line 93
    iget-object v2, v1, Ld2/d;->k:Lg4/p0;

    .line 94
    .line 95
    invoke-virtual {v3, v2}, Lg4/p0;->c(Lg4/p0;)Z

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    iput-object v3, v1, Ld2/d;->k:Lg4/p0;

    .line 100
    .line 101
    const/4 v3, -0x1

    .line 102
    const/4 v10, 0x0

    .line 103
    const/4 v11, 0x2

    .line 104
    if-nez v2, :cond_4

    .line 105
    .line 106
    iget-wide v12, v1, Ld2/d;->q:J

    .line 107
    .line 108
    shl-long/2addr v12, v11

    .line 109
    iput-wide v12, v1, Ld2/d;->q:J

    .line 110
    .line 111
    iput-object v10, v1, Ld2/d;->l:Landroidx/lifecycle/c1;

    .line 112
    .line 113
    iput-object v10, v1, Ld2/d;->n:Lg4/l0;

    .line 114
    .line 115
    iput v3, v1, Ld2/d;->p:I

    .line 116
    .line 117
    iput v3, v1, Ld2/d;->o:I

    .line 118
    .line 119
    :cond_4
    iput-object v4, v1, Ld2/d;->b:Lk4/m;

    .line 120
    .line 121
    iput v5, v1, Ld2/d;->c:I

    .line 122
    .line 123
    iput-boolean v6, v1, Ld2/d;->d:Z

    .line 124
    .line 125
    iput v7, v1, Ld2/d;->e:I

    .line 126
    .line 127
    iput v8, v1, Ld2/d;->f:I

    .line 128
    .line 129
    iput-object v9, v1, Ld2/d;->g:Ljava/util/List;

    .line 130
    .line 131
    iget-wide v4, v1, Ld2/d;->q:J

    .line 132
    .line 133
    shl-long/2addr v4, v11

    .line 134
    const-wide/16 v6, 0x2

    .line 135
    .line 136
    or-long/2addr v4, v6

    .line 137
    iput-wide v4, v1, Ld2/d;->q:J

    .line 138
    .line 139
    iput-object v10, v1, Ld2/d;->l:Landroidx/lifecycle/c1;

    .line 140
    .line 141
    iput-object v10, v1, Ld2/d;->n:Lg4/l0;

    .line 142
    .line 143
    iput v3, v1, Ld2/d;->p:I

    .line 144
    .line 145
    iput v3, v1, Ld2/d;->o:I

    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_5
    new-instance v10, Ld2/h;

    .line 149
    .line 150
    iget-object v1, v0, Ld2/i;->r:Lg4/g;

    .line 151
    .line 152
    invoke-direct {v10, v1, v2}, Ld2/h;-><init>(Lg4/g;Lg4/g;)V

    .line 153
    .line 154
    .line 155
    new-instance v1, Ld2/d;

    .line 156
    .line 157
    iget-object v3, v0, Ld2/i;->s:Lg4/p0;

    .line 158
    .line 159
    iget-object v4, v0, Ld2/i;->t:Lk4/m;

    .line 160
    .line 161
    iget v5, v0, Ld2/i;->v:I

    .line 162
    .line 163
    iget-boolean v6, v0, Ld2/i;->w:Z

    .line 164
    .line 165
    iget v7, v0, Ld2/i;->x:I

    .line 166
    .line 167
    iget v8, v0, Ld2/i;->y:I

    .line 168
    .line 169
    invoke-direct/range {v1 .. v9}, Ld2/d;-><init>(Lg4/g;Lg4/p0;Lk4/m;IZIILjava/util/List;)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v0}, Ld2/i;->X0()Ld2/d;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    iget-object v2, v2, Ld2/d;->j:Lt4/c;

    .line 177
    .line 178
    invoke-virtual {v1, v2}, Ld2/d;->d(Lt4/c;)V

    .line 179
    .line 180
    .line 181
    iput-object v1, v10, Ld2/h;->d:Ld2/d;

    .line 182
    .line 183
    iput-object v10, v0, Ld2/i;->G:Ld2/h;

    .line 184
    .line 185
    :cond_6
    :goto_1
    invoke-static {v0}, Lv3/f;->o(Lv3/x1;)V

    .line 186
    .line 187
    .line 188
    invoke-static {v0}, Lv3/f;->n(Lv3/y;)V

    .line 189
    .line 190
    .line 191
    invoke-static {v0}, Lv3/f;->m(Lv3/p;)V

    .line 192
    .line 193
    .line 194
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 195
    .line 196
    return-object v0

    .line 197
    :pswitch_1
    move-object/from16 v1, p1

    .line 198
    .line 199
    check-cast v1, Ljava/util/List;

    .line 200
    .line 201
    iget-object v0, v0, Ld2/f;->e:Ld2/i;

    .line 202
    .line 203
    invoke-virtual {v0}, Ld2/i;->X0()Ld2/d;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    iget-object v2, v2, Ld2/d;->n:Lg4/l0;

    .line 208
    .line 209
    if-eqz v2, :cond_8

    .line 210
    .line 211
    iget-object v3, v2, Lg4/l0;->a:Lg4/k0;

    .line 212
    .line 213
    new-instance v4, Lg4/k0;

    .line 214
    .line 215
    iget-object v5, v3, Lg4/k0;->a:Lg4/g;

    .line 216
    .line 217
    iget-object v6, v0, Ld2/i;->s:Lg4/p0;

    .line 218
    .line 219
    iget-object v0, v0, Ld2/i;->B:Le3/t;

    .line 220
    .line 221
    if-eqz v0, :cond_7

    .line 222
    .line 223
    invoke-interface {v0}, Le3/t;->a()J

    .line 224
    .line 225
    .line 226
    move-result-wide v7

    .line 227
    goto :goto_2

    .line 228
    :cond_7
    sget-wide v7, Le3/s;->i:J

    .line 229
    .line 230
    :goto_2
    const-wide/16 v17, 0x0

    .line 231
    .line 232
    const v19, 0xfffffe

    .line 233
    .line 234
    .line 235
    const-wide/16 v9, 0x0

    .line 236
    .line 237
    const/4 v11, 0x0

    .line 238
    const/4 v12, 0x0

    .line 239
    const-wide/16 v13, 0x0

    .line 240
    .line 241
    const/4 v15, 0x0

    .line 242
    const/16 v16, 0x0

    .line 243
    .line 244
    invoke-static/range {v6 .. v19}, Lg4/p0;->e(Lg4/p0;JJLk4/x;Lk4/t;JLr4/l;IJI)Lg4/p0;

    .line 245
    .line 246
    .line 247
    move-result-object v6

    .line 248
    iget-object v7, v3, Lg4/k0;->c:Ljava/util/List;

    .line 249
    .line 250
    iget v8, v3, Lg4/k0;->d:I

    .line 251
    .line 252
    iget-boolean v9, v3, Lg4/k0;->e:Z

    .line 253
    .line 254
    iget v10, v3, Lg4/k0;->f:I

    .line 255
    .line 256
    iget-object v11, v3, Lg4/k0;->g:Lt4/c;

    .line 257
    .line 258
    iget-object v12, v3, Lg4/k0;->h:Lt4/m;

    .line 259
    .line 260
    iget-object v13, v3, Lg4/k0;->i:Lk4/m;

    .line 261
    .line 262
    iget-wide v14, v3, Lg4/k0;->j:J

    .line 263
    .line 264
    invoke-direct/range {v4 .. v15}, Lg4/k0;-><init>(Lg4/g;Lg4/p0;Ljava/util/List;IZILt4/c;Lt4/m;Lk4/m;J)V

    .line 265
    .line 266
    .line 267
    iget-wide v5, v2, Lg4/l0;->c:J

    .line 268
    .line 269
    new-instance v0, Lg4/l0;

    .line 270
    .line 271
    iget-object v2, v2, Lg4/l0;->b:Lg4/o;

    .line 272
    .line 273
    invoke-direct {v0, v4, v2, v5, v6}, Lg4/l0;-><init>(Lg4/k0;Lg4/o;J)V

    .line 274
    .line 275
    .line 276
    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    goto :goto_3

    .line 280
    :cond_8
    const/4 v0, 0x0

    .line 281
    :goto_3
    if-eqz v0, :cond_9

    .line 282
    .line 283
    const/4 v0, 0x1

    .line 284
    goto :goto_4

    .line 285
    :cond_9
    const/4 v0, 0x0

    .line 286
    :goto_4
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    return-object v0

    .line 291
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
