.class public final synthetic Lh2/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;FI)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/x;->d:I

    iput-object p1, p0, Lh2/x;->f:Ljava/lang/Object;

    iput p2, p0, Lh2/x;->e:F

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;FII)V
    .locals 0

    .line 2
    iput p4, p0, Lh2/x;->d:I

    iput-object p1, p0, Lh2/x;->f:Ljava/lang/Object;

    iput p2, p0, Lh2/x;->e:F

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lh2/x;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/x;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lx2/s;

    .line 9
    .line 10
    check-cast p1, Ll2/o;

    .line 11
    .line 12
    check-cast p2, Ljava/lang/Integer;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const/4 p2, 0x1

    .line 18
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    iget p0, p0, Lh2/x;->e:F

    .line 23
    .line 24
    invoke-static {p0, p2, p1, v0}, Lz61/m;->a(FILl2/o;Lx2/s;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    iget-object v0, p0, Lh2/x;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Ls71/k;

    .line 33
    .line 34
    check-cast p1, Ll2/o;

    .line 35
    .line 36
    check-cast p2, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    const/4 p2, 0x1

    .line 42
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    iget p0, p0, Lh2/x;->e:F

    .line 47
    .line 48
    invoke-static {v0, p0, p1, p2}, Llp/bf;->f(Ls71/k;FLl2/o;I)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :pswitch_1
    iget-object v0, p0, Lh2/x;->f:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Lt2/b;

    .line 55
    .line 56
    check-cast p1, Ll2/o;

    .line 57
    .line 58
    check-cast p2, Ljava/lang/Integer;

    .line 59
    .line 60
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    and-int/lit8 v1, p2, 0x3

    .line 65
    .line 66
    const/4 v2, 0x2

    .line 67
    const/4 v3, 0x0

    .line 68
    const/4 v4, 0x1

    .line 69
    if-eq v1, v2, :cond_0

    .line 70
    .line 71
    move v1, v4

    .line 72
    goto :goto_1

    .line 73
    :cond_0
    move v1, v3

    .line 74
    :goto_1
    and-int/2addr p2, v4

    .line 75
    check-cast p1, Ll2/t;

    .line 76
    .line 77
    invoke-virtual {p1, p2, v1}, Ll2/t;->O(IZ)Z

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    if-eqz p2, :cond_1

    .line 82
    .line 83
    new-instance p2, Lt4/f;

    .line 84
    .line 85
    iget p0, p0, Lh2/x;->e:F

    .line 86
    .line 87
    invoke-direct {p2, p0}, Lt4/f;-><init>(F)V

    .line 88
    .line 89
    .line 90
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-virtual {v0, p2, p1, p0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 99
    .line 100
    .line 101
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    return-object p0

    .line 104
    :pswitch_2
    iget-object v0, p0, Lh2/x;->f:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v0, Lh2/r8;

    .line 107
    .line 108
    check-cast p1, Lt4/l;

    .line 109
    .line 110
    check-cast p2, Lt4/a;

    .line 111
    .line 112
    iget-wide v1, p2, Lt4/a;->a:J

    .line 113
    .line 114
    invoke-static {v1, v2}, Lt4/a;->g(J)I

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    int-to-float p2, p2

    .line 119
    iget-wide v1, p1, Lt4/l;->a:J

    .line 120
    .line 121
    const-wide v3, 0xffffffffL

    .line 122
    .line 123
    .line 124
    .line 125
    .line 126
    and-long/2addr v1, v3

    .line 127
    long-to-int p1, v1

    .line 128
    int-to-float p1, p1

    .line 129
    new-instance v1, Li2/u0;

    .line 130
    .line 131
    new-instance v2, Ljava/util/LinkedHashMap;

    .line 132
    .line 133
    invoke-direct {v2}, Ljava/util/LinkedHashMap;-><init>()V

    .line 134
    .line 135
    .line 136
    iget-boolean v3, v0, Lh2/r8;->a:Z

    .line 137
    .line 138
    iget p0, p0, Lh2/x;->e:F

    .line 139
    .line 140
    if-nez v3, :cond_2

    .line 141
    .line 142
    sget-object v3, Lh2/s8;->f:Lh2/s8;

    .line 143
    .line 144
    sub-float v4, p2, p0

    .line 145
    .line 146
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 147
    .line 148
    .line 149
    move-result-object v4

    .line 150
    invoke-interface {v2, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    :cond_2
    cmpg-float p0, p1, p0

    .line 154
    .line 155
    if-nez p0, :cond_3

    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_3
    sget-object p0, Lh2/s8;->e:Lh2/s8;

    .line 159
    .line 160
    sub-float p1, p2, p1

    .line 161
    .line 162
    const/4 v3, 0x0

    .line 163
    invoke-static {p1, v3}, Ljava/lang/Math;->max(FF)F

    .line 164
    .line 165
    .line 166
    move-result p1

    .line 167
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    invoke-interface {v2, p0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    :goto_3
    iget-boolean p0, v0, Lh2/r8;->c:Z

    .line 175
    .line 176
    if-nez p0, :cond_4

    .line 177
    .line 178
    sget-object p0, Lh2/s8;->d:Lh2/s8;

    .line 179
    .line 180
    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    invoke-interface {v2, p0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    :cond_4
    invoke-direct {v1, v2}, Li2/u0;-><init>(Ljava/util/Map;)V

    .line 188
    .line 189
    .line 190
    iget-object p0, v0, Lh2/r8;->e:Li2/p;

    .line 191
    .line 192
    iget-object p0, p0, Li2/p;->h:Ll2/h0;

    .line 193
    .line 194
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    check-cast p0, Lh2/s8;

    .line 199
    .line 200
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 201
    .line 202
    .line 203
    move-result p1

    .line 204
    if-eqz p1, :cond_b

    .line 205
    .line 206
    const/4 p2, 0x1

    .line 207
    if-eq p1, p2, :cond_8

    .line 208
    .line 209
    const/4 p2, 0x2

    .line 210
    if-ne p1, p2, :cond_7

    .line 211
    .line 212
    sget-object p1, Lh2/s8;->f:Lh2/s8;

    .line 213
    .line 214
    invoke-interface {v2, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result p2

    .line 218
    if-eqz p2, :cond_5

    .line 219
    .line 220
    :goto_4
    move-object p0, p1

    .line 221
    goto :goto_5

    .line 222
    :cond_5
    sget-object p1, Lh2/s8;->e:Lh2/s8;

    .line 223
    .line 224
    invoke-interface {v2, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    move-result p2

    .line 228
    if-eqz p2, :cond_6

    .line 229
    .line 230
    goto :goto_4

    .line 231
    :cond_6
    sget-object p1, Lh2/s8;->d:Lh2/s8;

    .line 232
    .line 233
    invoke-interface {v2, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result p2

    .line 237
    if-eqz p2, :cond_c

    .line 238
    .line 239
    goto :goto_4

    .line 240
    :cond_7
    new-instance p0, La8/r0;

    .line 241
    .line 242
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 243
    .line 244
    .line 245
    throw p0

    .line 246
    :cond_8
    sget-object p1, Lh2/s8;->e:Lh2/s8;

    .line 247
    .line 248
    invoke-interface {v2, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    move-result p2

    .line 252
    if-eqz p2, :cond_9

    .line 253
    .line 254
    goto :goto_4

    .line 255
    :cond_9
    sget-object p1, Lh2/s8;->f:Lh2/s8;

    .line 256
    .line 257
    invoke-interface {v2, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result p2

    .line 261
    if-eqz p2, :cond_a

    .line 262
    .line 263
    goto :goto_4

    .line 264
    :cond_a
    sget-object p1, Lh2/s8;->d:Lh2/s8;

    .line 265
    .line 266
    invoke-interface {v2, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result p2

    .line 270
    if-eqz p2, :cond_c

    .line 271
    .line 272
    goto :goto_4

    .line 273
    :cond_b
    sget-object p1, Lh2/s8;->d:Lh2/s8;

    .line 274
    .line 275
    invoke-interface {v2, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result p2

    .line 279
    if-eqz p2, :cond_c

    .line 280
    .line 281
    goto :goto_4

    .line 282
    :cond_c
    :goto_5
    new-instance p1, Llx0/l;

    .line 283
    .line 284
    invoke-direct {p1, v1, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    return-object p1

    .line 288
    nop

    .line 289
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
