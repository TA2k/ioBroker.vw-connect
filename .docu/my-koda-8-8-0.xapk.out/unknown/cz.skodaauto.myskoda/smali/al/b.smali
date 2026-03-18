.class public final synthetic Lal/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt2/b;

.field public final synthetic f:Lt2/b;

.field public final synthetic g:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lt2/b;Lt2/b;Lt2/b;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lal/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lal/b;->e:Lt2/b;

    iput-object p2, p0, Lal/b;->f:Lt2/b;

    iput-object p3, p0, Lal/b;->g:Lt2/b;

    return-void
.end method

.method public synthetic constructor <init>(Lt2/b;Lt2/b;Lt2/b;II)V
    .locals 0

    .line 2
    iput p5, p0, Lal/b;->d:I

    iput-object p1, p0, Lal/b;->e:Lt2/b;

    iput-object p2, p0, Lal/b;->f:Lt2/b;

    iput-object p3, p0, Lal/b;->g:Lt2/b;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lal/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v3, p1

    .line 7
    check-cast v3, Lt3/p1;

    .line 8
    .line 9
    move-object v6, p2

    .line 10
    check-cast v6, Lt4/a;

    .line 11
    .line 12
    iget-wide p1, v6, Lt4/a;->a:J

    .line 13
    .line 14
    invoke-static {p1, p2}, Lt4/a;->h(J)I

    .line 15
    .line 16
    .line 17
    move-result v10

    .line 18
    sget-object p1, Lh2/db;->d:Lh2/db;

    .line 19
    .line 20
    iget-object p2, p0, Lal/b;->e:Lt2/b;

    .line 21
    .line 22
    invoke-interface {v3, p1, p2}, Lt3/p1;->C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    new-instance v5, Lkotlin/jvm/internal/d0;

    .line 31
    .line 32
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 33
    .line 34
    .line 35
    if-lez p2, :cond_0

    .line 36
    .line 37
    div-int v0, v10, p2

    .line 38
    .line 39
    iput v0, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 40
    .line 41
    :cond_0
    const/4 v0, 0x0

    .line 42
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    move-object v2, p1

    .line 47
    check-cast v2, Ljava/util/Collection;

    .line 48
    .line 49
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    move v7, v0

    .line 54
    :goto_0
    if-ge v7, v4, :cond_1

    .line 55
    .line 56
    invoke-interface {p1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v8

    .line 60
    check-cast v8, Lt3/p0;

    .line 61
    .line 62
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    iget v9, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 67
    .line 68
    invoke-interface {v8, v9}, Lt3/p0;->c(I)I

    .line 69
    .line 70
    .line 71
    move-result v8

    .line 72
    invoke-static {v8, v1}, Ljava/lang/Math;->max(II)I

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    add-int/lit8 v7, v7, 0x1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_1
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 84
    .line 85
    .line 86
    move-result v7

    .line 87
    move-object v1, v2

    .line 88
    new-instance v2, Ljava/util/ArrayList;

    .line 89
    .line 90
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 91
    .line 92
    .line 93
    move-result v4

    .line 94
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 95
    .line 96
    .line 97
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    move v4, v0

    .line 102
    :goto_1
    if-ge v4, v1, :cond_3

    .line 103
    .line 104
    invoke-interface {p1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v8

    .line 108
    check-cast v8, Lt3/p0;

    .line 109
    .line 110
    iget v9, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 111
    .line 112
    if-ltz v9, :cond_2

    .line 113
    .line 114
    if-ltz v7, :cond_2

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_2
    const-string v11, "maxWidth must be >= than minWidth,\nmaxHeight must be >= than minHeight,\nminWidth and minHeight must be >= 0"

    .line 118
    .line 119
    invoke-static {v11}, Lt4/i;->a(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    :goto_2
    invoke-static {v9, v9, v7, v7}, Lt4/b;->h(IIII)J

    .line 123
    .line 124
    .line 125
    move-result-wide v11

    .line 126
    invoke-interface {v8, v11, v12}, Lt3/p0;->L(J)Lt3/e1;

    .line 127
    .line 128
    .line 129
    move-result-object v8

    .line 130
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    add-int/lit8 v4, v4, 0x1

    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_3
    new-instance v9, Ljava/util/ArrayList;

    .line 137
    .line 138
    invoke-direct {v9, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 139
    .line 140
    .line 141
    :goto_3
    if-ge v0, p2, :cond_4

    .line 142
    .line 143
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    check-cast v1, Lt3/p0;

    .line 148
    .line 149
    invoke-interface {v1, v7}, Lt3/p0;->J(I)I

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    iget v4, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 154
    .line 155
    invoke-static {v1, v4}, Ljava/lang/Math;->min(II)I

    .line 156
    .line 157
    .line 158
    move-result v1

    .line 159
    invoke-interface {v3, v1}, Lt4/c;->n0(I)F

    .line 160
    .line 161
    .line 162
    move-result v1

    .line 163
    sget v4, Lh2/wa;->b:F

    .line 164
    .line 165
    const/4 v8, 0x2

    .line 166
    int-to-float v8, v8

    .line 167
    mul-float/2addr v4, v8

    .line 168
    sub-float/2addr v1, v4

    .line 169
    new-instance v4, Lt4/f;

    .line 170
    .line 171
    invoke-direct {v4, v1}, Lt4/f;-><init>(F)V

    .line 172
    .line 173
    .line 174
    const/16 v1, 0x18

    .line 175
    .line 176
    int-to-float v1, v1

    .line 177
    new-instance v8, Lt4/f;

    .line 178
    .line 179
    invoke-direct {v8, v1}, Lt4/f;-><init>(F)V

    .line 180
    .line 181
    .line 182
    invoke-static {v4, v8}, Ljp/vc;->d(Lt4/f;Lt4/f;)Ljava/lang/Comparable;

    .line 183
    .line 184
    .line 185
    move-result-object v1

    .line 186
    check-cast v1, Lt4/f;

    .line 187
    .line 188
    iget v1, v1, Lt4/f;->d:F

    .line 189
    .line 190
    new-instance v4, Lh2/xa;

    .line 191
    .line 192
    iget v8, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 193
    .line 194
    invoke-interface {v3, v8}, Lt4/c;->n0(I)F

    .line 195
    .line 196
    .line 197
    move-result v8

    .line 198
    int-to-float v11, v0

    .line 199
    mul-float/2addr v8, v11

    .line 200
    iget v11, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 201
    .line 202
    invoke-interface {v3, v11}, Lt4/c;->n0(I)F

    .line 203
    .line 204
    .line 205
    move-result v11

    .line 206
    invoke-direct {v4, v8, v11, v1}, Lh2/xa;-><init>(FFF)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    add-int/lit8 v0, v0, 0x1

    .line 213
    .line 214
    goto :goto_3

    .line 215
    :cond_4
    new-instance v1, Lh2/cb;

    .line 216
    .line 217
    iget-object v4, p0, Lal/b;->f:Lt2/b;

    .line 218
    .line 219
    iget-object v8, p0, Lal/b;->g:Lt2/b;

    .line 220
    .line 221
    invoke-direct/range {v1 .. v10}, Lh2/cb;-><init>(Ljava/util/ArrayList;Lt3/p1;Lt2/b;Lkotlin/jvm/internal/d0;Lt4/a;ILt2/b;Ljava/util/ArrayList;I)V

    .line 222
    .line 223
    .line 224
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 225
    .line 226
    invoke-interface {v3, v10, v7, p0, v1}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    return-object p0

    .line 231
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 232
    .line 233
    check-cast p2, Ljava/lang/Integer;

    .line 234
    .line 235
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 236
    .line 237
    .line 238
    const/16 p2, 0x1b7

    .line 239
    .line 240
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 241
    .line 242
    .line 243
    move-result p2

    .line 244
    iget-object v0, p0, Lal/b;->e:Lt2/b;

    .line 245
    .line 246
    iget-object v1, p0, Lal/b;->f:Lt2/b;

    .line 247
    .line 248
    iget-object p0, p0, Lal/b;->g:Lt2/b;

    .line 249
    .line 250
    invoke-static {v0, v1, p0, p1, p2}, Lal/a;->n(Lt2/b;Lt2/b;Lt2/b;Ll2/o;I)V

    .line 251
    .line 252
    .line 253
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 254
    .line 255
    return-object p0

    .line 256
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 257
    .line 258
    check-cast p2, Ljava/lang/Integer;

    .line 259
    .line 260
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 261
    .line 262
    .line 263
    const/16 p2, 0xdb1

    .line 264
    .line 265
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 266
    .line 267
    .line 268
    move-result p2

    .line 269
    iget-object v0, p0, Lal/b;->e:Lt2/b;

    .line 270
    .line 271
    iget-object v1, p0, Lal/b;->f:Lt2/b;

    .line 272
    .line 273
    iget-object p0, p0, Lal/b;->g:Lt2/b;

    .line 274
    .line 275
    invoke-static {v0, v1, p0, p1, p2}, Lal/a;->m(Lt2/b;Lt2/b;Lt2/b;Ll2/o;I)V

    .line 276
    .line 277
    .line 278
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 279
    .line 280
    return-object p0

    .line 281
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
