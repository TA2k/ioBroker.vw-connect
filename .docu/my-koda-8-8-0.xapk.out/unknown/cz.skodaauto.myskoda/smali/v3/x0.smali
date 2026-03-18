.class public final Lv3/x0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lv3/y0;


# direct methods
.method public synthetic constructor <init>(Lv3/y0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lv3/x0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lv3/x0;->g:Lv3/y0;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lv3/x0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lv3/x0;->g:Lv3/y0;

    .line 7
    .line 8
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 9
    .line 10
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    iget-object v1, v1, Lv3/f1;->t:Lv3/f1;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    iget-object v1, v1, Lv3/p0;->o:Lt3/n0;

    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    :cond_0
    iget-object v1, v0, Lv3/l0;->a:Lv3/h0;

    .line 23
    .line 24
    invoke-static {v1}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lw3/t;

    .line 29
    .line 30
    invoke-virtual {v1}, Lw3/t;->getPlacementScope()Lt3/d1;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    :cond_1
    iget-object v2, p0, Lv3/y0;->K:Lay0/k;

    .line 35
    .line 36
    iget-object v3, p0, Lv3/y0;->L:Lh3/c;

    .line 37
    .line 38
    if-eqz v3, :cond_2

    .line 39
    .line 40
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    iget-wide v4, p0, Lv3/y0;->M:J

    .line 45
    .line 46
    iget p0, p0, Lv3/y0;->N:F

    .line 47
    .line 48
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 49
    .line 50
    .line 51
    invoke-static {v1, v0}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 52
    .line 53
    .line 54
    iget-wide v1, v0, Lt3/e1;->h:J

    .line 55
    .line 56
    invoke-static {v4, v5, v1, v2}, Lt4/j;->d(JJ)J

    .line 57
    .line 58
    .line 59
    move-result-wide v1

    .line 60
    invoke-virtual {v0, v1, v2, p0, v3}, Lv3/f1;->m0(JFLh3/c;)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_2
    if-nez v2, :cond_3

    .line 65
    .line 66
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iget-wide v2, p0, Lv3/y0;->M:J

    .line 71
    .line 72
    iget p0, p0, Lv3/y0;->N:F

    .line 73
    .line 74
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    invoke-static {v1, v0}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 78
    .line 79
    .line 80
    iget-wide v4, v0, Lt3/e1;->h:J

    .line 81
    .line 82
    invoke-static {v2, v3, v4, v5}, Lt4/j;->d(JJ)J

    .line 83
    .line 84
    .line 85
    move-result-wide v1

    .line 86
    const/4 v3, 0x0

    .line 87
    invoke-virtual {v0, v1, v2, p0, v3}, Lt3/e1;->l0(JFLay0/k;)V

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_3
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    iget-wide v3, p0, Lv3/y0;->M:J

    .line 96
    .line 97
    iget p0, p0, Lv3/y0;->N:F

    .line 98
    .line 99
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    invoke-static {v1, v0}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 103
    .line 104
    .line 105
    iget-wide v5, v0, Lt3/e1;->h:J

    .line 106
    .line 107
    invoke-static {v3, v4, v5, v6}, Lt4/j;->d(JJ)J

    .line 108
    .line 109
    .line 110
    move-result-wide v3

    .line 111
    invoke-virtual {v0, v3, v4, p0, v2}, Lt3/e1;->l0(JFLay0/k;)V

    .line 112
    .line 113
    .line 114
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0

    .line 117
    :pswitch_0
    iget-object p0, p0, Lv3/x0;->g:Lv3/y0;

    .line 118
    .line 119
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 120
    .line 121
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    iget-wide v1, p0, Lv3/y0;->F:J

    .line 126
    .line 127
    invoke-interface {v0, v1, v2}, Lt3/p0;->L(J)Lt3/e1;

    .line 128
    .line 129
    .line 130
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    return-object p0

    .line 133
    :pswitch_1
    iget-object p0, p0, Lv3/x0;->g:Lv3/y0;

    .line 134
    .line 135
    iget-object v0, p0, Lv3/y0;->i:Lv3/l0;

    .line 136
    .line 137
    const/4 v1, 0x0

    .line 138
    iput v1, v0, Lv3/l0;->i:I

    .line 139
    .line 140
    iget-object v2, v0, Lv3/l0;->a:Lv3/h0;

    .line 141
    .line 142
    invoke-virtual {v2}, Lv3/h0;->z()Ln2/b;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    iget-object v3, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 147
    .line 148
    iget v2, v2, Ln2/b;->f:I

    .line 149
    .line 150
    move v4, v1

    .line 151
    :goto_1
    const v5, 0x7fffffff

    .line 152
    .line 153
    .line 154
    if-ge v4, v2, :cond_5

    .line 155
    .line 156
    aget-object v6, v3, v4

    .line 157
    .line 158
    check-cast v6, Lv3/h0;

    .line 159
    .line 160
    iget-object v6, v6, Lv3/h0;->I:Lv3/l0;

    .line 161
    .line 162
    iget-object v6, v6, Lv3/l0;->p:Lv3/y0;

    .line 163
    .line 164
    iget v7, v6, Lv3/y0;->l:I

    .line 165
    .line 166
    iput v7, v6, Lv3/y0;->k:I

    .line 167
    .line 168
    iput v5, v6, Lv3/y0;->l:I

    .line 169
    .line 170
    iput-boolean v1, v6, Lv3/y0;->x:Z

    .line 171
    .line 172
    iget-object v5, v6, Lv3/y0;->o:Lv3/f0;

    .line 173
    .line 174
    sget-object v7, Lv3/f0;->e:Lv3/f0;

    .line 175
    .line 176
    if-ne v5, v7, :cond_4

    .line 177
    .line 178
    sget-object v5, Lv3/f0;->f:Lv3/f0;

    .line 179
    .line 180
    iput-object v5, v6, Lv3/y0;->o:Lv3/f0;

    .line 181
    .line 182
    :cond_4
    add-int/lit8 v4, v4, 0x1

    .line 183
    .line 184
    goto :goto_1

    .line 185
    :cond_5
    iget-object v2, v0, Lv3/l0;->a:Lv3/h0;

    .line 186
    .line 187
    iget-object v0, v0, Lv3/l0;->a:Lv3/h0;

    .line 188
    .line 189
    invoke-virtual {v2}, Lv3/h0;->z()Ln2/b;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    iget-object v3, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 194
    .line 195
    iget v2, v2, Ln2/b;->f:I

    .line 196
    .line 197
    move v4, v1

    .line 198
    :goto_2
    if-ge v4, v2, :cond_6

    .line 199
    .line 200
    aget-object v6, v3, v4

    .line 201
    .line 202
    check-cast v6, Lv3/h0;

    .line 203
    .line 204
    iget-object v6, v6, Lv3/h0;->I:Lv3/l0;

    .line 205
    .line 206
    iget-object v6, v6, Lv3/l0;->p:Lv3/y0;

    .line 207
    .line 208
    iget-object v6, v6, Lv3/y0;->B:Lv3/i0;

    .line 209
    .line 210
    iput-boolean v1, v6, Lv3/i0;->d:Z

    .line 211
    .line 212
    add-int/lit8 v4, v4, 0x1

    .line 213
    .line 214
    goto :goto_2

    .line 215
    :cond_6
    invoke-virtual {p0}, Lv3/y0;->E()Lv3/u;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    invoke-virtual {p0}, Lv3/f1;->N0()Lt3/r0;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    invoke-interface {p0}, Lt3/r0;->c()V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v0}, Lv3/h0;->z()Ln2/b;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    iget-object v2, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 231
    .line 232
    iget p0, p0, Ln2/b;->f:I

    .line 233
    .line 234
    move v3, v1

    .line 235
    :goto_3
    if-ge v3, p0, :cond_9

    .line 236
    .line 237
    aget-object v4, v2, v3

    .line 238
    .line 239
    check-cast v4, Lv3/h0;

    .line 240
    .line 241
    iget-object v6, v4, Lv3/h0;->I:Lv3/l0;

    .line 242
    .line 243
    iget-object v7, v6, Lv3/l0;->p:Lv3/y0;

    .line 244
    .line 245
    iget v7, v7, Lv3/y0;->k:I

    .line 246
    .line 247
    invoke-virtual {v4}, Lv3/h0;->w()I

    .line 248
    .line 249
    .line 250
    move-result v8

    .line 251
    if-eq v7, v8, :cond_8

    .line 252
    .line 253
    invoke-virtual {v0}, Lv3/h0;->P()V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v0}, Lv3/h0;->C()V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v4}, Lv3/h0;->w()I

    .line 260
    .line 261
    .line 262
    move-result v4

    .line 263
    if-ne v4, v5, :cond_8

    .line 264
    .line 265
    iget-boolean v4, v6, Lv3/l0;->c:Z

    .line 266
    .line 267
    if-eqz v4, :cond_7

    .line 268
    .line 269
    iget-object v4, v6, Lv3/l0;->q:Lv3/u0;

    .line 270
    .line 271
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v4, v1}, Lv3/u0;->B0(Z)V

    .line 275
    .line 276
    .line 277
    :cond_7
    iget-object v4, v6, Lv3/l0;->p:Lv3/y0;

    .line 278
    .line 279
    invoke-virtual {v4}, Lv3/y0;->E0()V

    .line 280
    .line 281
    .line 282
    :cond_8
    add-int/lit8 v3, v3, 0x1

    .line 283
    .line 284
    goto :goto_3

    .line 285
    :cond_9
    invoke-virtual {v0}, Lv3/h0;->z()Ln2/b;

    .line 286
    .line 287
    .line 288
    move-result-object p0

    .line 289
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 290
    .line 291
    iget p0, p0, Ln2/b;->f:I

    .line 292
    .line 293
    :goto_4
    if-ge v1, p0, :cond_a

    .line 294
    .line 295
    aget-object v2, v0, v1

    .line 296
    .line 297
    check-cast v2, Lv3/h0;

    .line 298
    .line 299
    iget-object v2, v2, Lv3/h0;->I:Lv3/l0;

    .line 300
    .line 301
    iget-object v2, v2, Lv3/l0;->p:Lv3/y0;

    .line 302
    .line 303
    iget-object v2, v2, Lv3/y0;->B:Lv3/i0;

    .line 304
    .line 305
    iget-boolean v3, v2, Lv3/i0;->d:Z

    .line 306
    .line 307
    iput-boolean v3, v2, Lv3/i0;->e:Z

    .line 308
    .line 309
    add-int/lit8 v1, v1, 0x1

    .line 310
    .line 311
    goto :goto_4

    .line 312
    :cond_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 313
    .line 314
    return-object p0

    .line 315
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
