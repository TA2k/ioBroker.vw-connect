.class public final synthetic Lda/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lda/i;->d:I

    iput-object p3, p0, Lda/i;->g:Ljava/lang/Object;

    iput-object p4, p0, Lda/i;->h:Ljava/lang/Object;

    iput-object p5, p0, Lda/i;->e:Ljava/lang/Object;

    iput p1, p0, Lda/i;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/ArrayList;Ljava/lang/String;ILay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lda/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lda/i;->g:Ljava/lang/Object;

    iput-object p2, p0, Lda/i;->e:Ljava/lang/Object;

    iput p3, p0, Lda/i;->f:I

    iput-object p4, p0, Lda/i;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lqz0/a;ILjava/util/Map;Ljava/lang/String;)V
    .locals 1

    .line 3
    const/4 v0, 0x0

    iput v0, p0, Lda/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lda/i;->g:Ljava/lang/Object;

    iput p2, p0, Lda/i;->f:I

    iput-object p3, p0, Lda/i;->h:Ljava/lang/Object;

    iput-object p4, p0, Lda/i;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lda/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lda/i;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lt1/e0;

    .line 9
    .line 10
    iget-object v1, p0, Lda/i;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lt3/s0;

    .line 13
    .line 14
    iget-object v2, p0, Lda/i;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Lt3/e1;

    .line 17
    .line 18
    move-object v3, p1

    .line 19
    check-cast v3, Lt3/d1;

    .line 20
    .line 21
    iget v4, v0, Lt1/e0;->c:I

    .line 22
    .line 23
    iget-object p1, v0, Lt1/e0;->b:Lt1/h1;

    .line 24
    .line 25
    iget-object v5, v0, Lt1/e0;->d:Ll4/b0;

    .line 26
    .line 27
    iget-object v0, v0, Lt1/e0;->e:Lay0/a;

    .line 28
    .line 29
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast v0, Lt1/j1;

    .line 34
    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    iget-object v0, v0, Lt1/j1;->a:Lg4/l0;

    .line 38
    .line 39
    :goto_0
    move-object v6, v0

    .line 40
    goto :goto_1

    .line 41
    :cond_0
    const/4 v0, 0x0

    .line 42
    goto :goto_0

    .line 43
    :goto_1
    invoke-interface {v1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sget-object v1, Lt4/m;->e:Lt4/m;

    .line 48
    .line 49
    const/4 v9, 0x0

    .line 50
    if-ne v0, v1, :cond_1

    .line 51
    .line 52
    const/4 v0, 0x1

    .line 53
    move v7, v0

    .line 54
    goto :goto_2

    .line 55
    :cond_1
    move v7, v9

    .line 56
    :goto_2
    iget v8, v2, Lt3/e1;->d:I

    .line 57
    .line 58
    invoke-static/range {v3 .. v8}, Lt1/l0;->l(Lt3/d1;ILl4/b0;Lg4/l0;ZI)Ld3/c;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    sget-object v1, Lg1/w1;->e:Lg1/w1;

    .line 63
    .line 64
    iget v4, v2, Lt3/e1;->d:I

    .line 65
    .line 66
    iget p0, p0, Lda/i;->f:I

    .line 67
    .line 68
    invoke-virtual {p1, v1, v0, p0, v4}, Lt1/h1;->a(Lg1/w1;Ld3/c;II)V

    .line 69
    .line 70
    .line 71
    iget-object p0, p1, Lt1/h1;->a:Ll2/f1;

    .line 72
    .line 73
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    neg-float p0, p0

    .line 78
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    invoke-static {v3, v2, p0, v9}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 83
    .line 84
    .line 85
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    return-object p0

    .line 88
    :pswitch_0
    iget-object v0, p0, Lda/i;->g:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v0, Ll2/h0;

    .line 91
    .line 92
    iget-object v1, p0, Lda/i;->h:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v1, Lt2/d;

    .line 95
    .line 96
    iget-object v2, p0, Lda/i;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v2, Landroidx/collection/h0;

    .line 99
    .line 100
    if-eq p1, v0, :cond_4

    .line 101
    .line 102
    instance-of v0, p1, Lv2/t;

    .line 103
    .line 104
    if-eqz v0, :cond_3

    .line 105
    .line 106
    iget v0, v1, Lt2/d;->a:I

    .line 107
    .line 108
    iget p0, p0, Lda/i;->f:I

    .line 109
    .line 110
    sub-int/2addr v0, p0

    .line 111
    invoke-virtual {v2, p1}, Landroidx/collection/h0;->d(Ljava/lang/Object;)I

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    if-ltz p0, :cond_2

    .line 116
    .line 117
    iget-object v1, v2, Landroidx/collection/h0;->c:[I

    .line 118
    .line 119
    aget p0, v1, p0

    .line 120
    .line 121
    goto :goto_4

    .line 122
    :cond_2
    const p0, 0x7fffffff

    .line 123
    .line 124
    .line 125
    :goto_4
    invoke-static {v0, p0}, Ljava/lang/Math;->min(II)I

    .line 126
    .line 127
    .line 128
    move-result p0

    .line 129
    invoke-virtual {v2, p0, p1}, Landroidx/collection/h0;->h(ILjava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    return-object p0

    .line 135
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 136
    .line 137
    const-string p1, "A derived state calculation cannot read itself"

    .line 138
    .line 139
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    throw p0

    .line 143
    :pswitch_1
    iget-object v0, p0, Lda/i;->g:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v0, Ljava/util/ArrayList;

    .line 146
    .line 147
    iget-object v1, p0, Lda/i;->e:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v1, Ljava/lang/String;

    .line 150
    .line 151
    iget-object v2, p0, Lda/i;->h:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v2, Lay0/k;

    .line 154
    .line 155
    check-cast p1, Lm1/f;

    .line 156
    .line 157
    const-string v3, "$this$LazyColumn"

    .line 158
    .line 159
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    new-instance v3, La71/z0;

    .line 163
    .line 164
    const/4 v4, 0x4

    .line 165
    invoke-direct {v3, v1, v4}, La71/z0;-><init>(Ljava/lang/String;I)V

    .line 166
    .line 167
    .line 168
    new-instance v1, Lt2/b;

    .line 169
    .line 170
    const/4 v4, 0x1

    .line 171
    const v5, 0x45ead9a7

    .line 172
    .line 173
    .line 174
    invoke-direct {v1, v3, v4, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 175
    .line 176
    .line 177
    const/4 v3, 0x3

    .line 178
    invoke-static {p1, v1, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 182
    .line 183
    .line 184
    move-result v1

    .line 185
    new-instance v3, Lal/n;

    .line 186
    .line 187
    const/4 v5, 0x4

    .line 188
    invoke-direct {v3, v0, v5}, Lal/n;-><init>(Ljava/util/ArrayList;I)V

    .line 189
    .line 190
    .line 191
    new-instance v5, Li40/h2;

    .line 192
    .line 193
    const/4 v6, 0x0

    .line 194
    iget p0, p0, Lda/i;->f:I

    .line 195
    .line 196
    invoke-direct {v5, p0, v6, v2, v0}, Li40/h2;-><init>(IILay0/k;Ljava/util/List;)V

    .line 197
    .line 198
    .line 199
    new-instance p0, Lt2/b;

    .line 200
    .line 201
    const v0, 0x799532c4

    .line 202
    .line 203
    .line 204
    invoke-direct {p0, v5, v4, v0}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 205
    .line 206
    .line 207
    const/4 v0, 0x0

    .line 208
    invoke-virtual {p1, v1, v0, v3, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 209
    .line 210
    .line 211
    goto :goto_3

    .line 212
    :pswitch_2
    iget-object v0, p0, Lda/i;->g:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast v0, Lqz0/a;

    .line 215
    .line 216
    iget-object v1, p0, Lda/i;->h:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v1, Ljava/util/Map;

    .line 219
    .line 220
    iget-object v2, p0, Lda/i;->e:Ljava/lang/Object;

    .line 221
    .line 222
    check-cast v2, Ljava/lang/String;

    .line 223
    .line 224
    check-cast p1, Lz9/j;

    .line 225
    .line 226
    const-string v3, "$this$navArgument"

    .line 227
    .line 228
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    iget-object p1, p1, Lz9/j;->a:Lg11/k;

    .line 232
    .line 233
    invoke-interface {v0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 234
    .line 235
    .line 236
    move-result-object v3

    .line 237
    iget p0, p0, Lda/i;->f:I

    .line 238
    .line 239
    invoke-interface {v3, p0}, Lsz0/g;->g(I)Lsz0/g;

    .line 240
    .line 241
    .line 242
    move-result-object v3

    .line 243
    invoke-interface {v3}, Lsz0/g;->b()Z

    .line 244
    .line 245
    .line 246
    move-result v4

    .line 247
    invoke-static {v3, v1}, Lda/d;->a(Lsz0/g;Ljava/util/Map;)Lz9/g0;

    .line 248
    .line 249
    .line 250
    move-result-object v5

    .line 251
    if-eqz v5, :cond_6

    .line 252
    .line 253
    iput-object v5, p1, Lg11/k;->c:Ljava/lang/Object;

    .line 254
    .line 255
    iput-boolean v4, p1, Lg11/k;->a:Z

    .line 256
    .line 257
    invoke-interface {v0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 258
    .line 259
    .line 260
    move-result-object v0

    .line 261
    invoke-interface {v0, p0}, Lsz0/g;->i(I)Z

    .line 262
    .line 263
    .line 264
    move-result p0

    .line 265
    if-eqz p0, :cond_5

    .line 266
    .line 267
    const/4 p0, 0x1

    .line 268
    iput-boolean p0, p1, Lg11/k;->b:Z

    .line 269
    .line 270
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 271
    .line 272
    return-object p0

    .line 273
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 274
    .line 275
    invoke-interface {v3}, Lsz0/g;->h()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object p1

    .line 279
    invoke-interface {v0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    invoke-interface {v0}, Lsz0/g;->h()Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object v0

    .line 287
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 288
    .line 289
    .line 290
    move-result-object v1

    .line 291
    invoke-static {v2, p1, v0, v1}, Lda/d;->h(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object p1

    .line 295
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    throw p0

    .line 299
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
