.class public abstract Li3/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Le3/g;

.field public e:Z

.field public f:Le3/m;

.field public g:F

.field public h:Lt4/m;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x3f800000    # 1.0f

    .line 5
    .line 6
    iput v0, p0, Li3/c;->g:F

    .line 7
    .line 8
    sget-object v0, Lt4/m;->d:Lt4/m;

    .line 9
    .line 10
    iput-object v0, p0, Li3/c;->h:Lt4/m;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public a(F)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public b(Le3/m;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public d(Lt4/m;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(Lg3/d;JFLe3/m;)V
    .locals 8

    .line 1
    iget v0, p0, Li3/c;->g:F

    .line 2
    .line 3
    cmpg-float v0, v0, p4

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    const/4 v2, 0x0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    invoke-virtual {p0, p4}, Li3/c;->a(F)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_4

    .line 15
    .line 16
    const/high16 v0, 0x3f800000    # 1.0f

    .line 17
    .line 18
    cmpg-float v0, p4, v0

    .line 19
    .line 20
    if-nez v0, :cond_2

    .line 21
    .line 22
    iget-object v0, p0, Li3/c;->d:Le3/g;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    invoke-virtual {v0, p4}, Le3/g;->c(F)V

    .line 27
    .line 28
    .line 29
    :cond_1
    iput-boolean v2, p0, Li3/c;->e:Z

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    iget-object v0, p0, Li3/c;->d:Le3/g;

    .line 33
    .line 34
    if-nez v0, :cond_3

    .line 35
    .line 36
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    iput-object v0, p0, Li3/c;->d:Le3/g;

    .line 41
    .line 42
    :cond_3
    invoke-virtual {v0, p4}, Le3/g;->c(F)V

    .line 43
    .line 44
    .line 45
    iput-boolean v1, p0, Li3/c;->e:Z

    .line 46
    .line 47
    :cond_4
    :goto_0
    iput p4, p0, Li3/c;->g:F

    .line 48
    .line 49
    :goto_1
    iget-object v0, p0, Li3/c;->f:Le3/m;

    .line 50
    .line 51
    invoke-static {v0, p5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-nez v0, :cond_9

    .line 56
    .line 57
    invoke-virtual {p0, p5}, Li3/c;->b(Le3/m;)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-nez v0, :cond_8

    .line 62
    .line 63
    if-nez p5, :cond_6

    .line 64
    .line 65
    iget-object v0, p0, Li3/c;->d:Le3/g;

    .line 66
    .line 67
    if-eqz v0, :cond_5

    .line 68
    .line 69
    const/4 v1, 0x0

    .line 70
    invoke-virtual {v0, v1}, Le3/g;->f(Le3/m;)V

    .line 71
    .line 72
    .line 73
    :cond_5
    iput-boolean v2, p0, Li3/c;->e:Z

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_6
    iget-object v0, p0, Li3/c;->d:Le3/g;

    .line 77
    .line 78
    if-nez v0, :cond_7

    .line 79
    .line 80
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    iput-object v0, p0, Li3/c;->d:Le3/g;

    .line 85
    .line 86
    :cond_7
    invoke-virtual {v0, p5}, Le3/g;->f(Le3/m;)V

    .line 87
    .line 88
    .line 89
    iput-boolean v1, p0, Li3/c;->e:Z

    .line 90
    .line 91
    :cond_8
    :goto_2
    iput-object p5, p0, Li3/c;->f:Le3/m;

    .line 92
    .line 93
    :cond_9
    invoke-interface {p1}, Lg3/d;->getLayoutDirection()Lt4/m;

    .line 94
    .line 95
    .line 96
    move-result-object p5

    .line 97
    iget-object v0, p0, Li3/c;->h:Lt4/m;

    .line 98
    .line 99
    if-eq v0, p5, :cond_a

    .line 100
    .line 101
    invoke-virtual {p0, p5}, Li3/c;->d(Lt4/m;)V

    .line 102
    .line 103
    .line 104
    iput-object p5, p0, Li3/c;->h:Lt4/m;

    .line 105
    .line 106
    :cond_a
    invoke-interface {p1}, Lg3/d;->e()J

    .line 107
    .line 108
    .line 109
    move-result-wide v0

    .line 110
    const/16 p5, 0x20

    .line 111
    .line 112
    shr-long/2addr v0, p5

    .line 113
    long-to-int v0, v0

    .line 114
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    shr-long v1, p2, p5

    .line 119
    .line 120
    long-to-int v1, v1

    .line 121
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    sub-float/2addr v0, v2

    .line 126
    invoke-interface {p1}, Lg3/d;->e()J

    .line 127
    .line 128
    .line 129
    move-result-wide v2

    .line 130
    const-wide v4, 0xffffffffL

    .line 131
    .line 132
    .line 133
    .line 134
    .line 135
    and-long/2addr v2, v4

    .line 136
    long-to-int v2, v2

    .line 137
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    and-long/2addr p2, v4

    .line 142
    long-to-int p2, p2

    .line 143
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 144
    .line 145
    .line 146
    move-result p3

    .line 147
    sub-float/2addr v2, p3

    .line 148
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 149
    .line 150
    .line 151
    move-result-object p3

    .line 152
    iget-object p3, p3, Lgw0/c;->e:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast p3, Lbu/c;

    .line 155
    .line 156
    const/4 v3, 0x0

    .line 157
    invoke-virtual {p3, v3, v3, v0, v2}, Lbu/c;->v(FFFF)V

    .line 158
    .line 159
    .line 160
    cmpl-float p3, p4, v3

    .line 161
    .line 162
    const/high16 p4, -0x80000000

    .line 163
    .line 164
    if-lez p3, :cond_d

    .line 165
    .line 166
    :try_start_0
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 167
    .line 168
    .line 169
    move-result p3

    .line 170
    cmpl-float p3, p3, v3

    .line 171
    .line 172
    if-lez p3, :cond_d

    .line 173
    .line 174
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 175
    .line 176
    .line 177
    move-result p3

    .line 178
    cmpl-float p3, p3, v3

    .line 179
    .line 180
    if-lez p3, :cond_d

    .line 181
    .line 182
    iget-boolean p3, p0, Li3/c;->e:Z

    .line 183
    .line 184
    if-eqz p3, :cond_c

    .line 185
    .line 186
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 187
    .line 188
    .line 189
    move-result p3

    .line 190
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 191
    .line 192
    .line 193
    move-result p2

    .line 194
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 195
    .line 196
    .line 197
    move-result p3

    .line 198
    int-to-long v6, p3

    .line 199
    invoke-static {p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 200
    .line 201
    .line 202
    move-result p2

    .line 203
    int-to-long p2, p2

    .line 204
    shl-long/2addr v6, p5

    .line 205
    and-long/2addr p2, v4

    .line 206
    or-long/2addr p2, v6

    .line 207
    const-wide/16 v3, 0x0

    .line 208
    .line 209
    invoke-static {v3, v4, p2, p3}, Ljp/cf;->c(JJ)Ld3/c;

    .line 210
    .line 211
    .line 212
    move-result-object p2

    .line 213
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 214
    .line 215
    .line 216
    move-result-object p3

    .line 217
    invoke-virtual {p3}, Lgw0/c;->h()Le3/r;

    .line 218
    .line 219
    .line 220
    move-result-object p3

    .line 221
    iget-object p5, p0, Li3/c;->d:Le3/g;

    .line 222
    .line 223
    if-nez p5, :cond_b

    .line 224
    .line 225
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 226
    .line 227
    .line 228
    move-result-object p5

    .line 229
    iput-object p5, p0, Li3/c;->d:Le3/g;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 230
    .line 231
    :cond_b
    :try_start_1
    invoke-interface {p3, p2, p5}, Le3/r;->t(Ld3/c;Le3/g;)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {p0, p1}, Li3/c;->i(Lg3/d;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 235
    .line 236
    .line 237
    :try_start_2
    invoke-interface {p3}, Le3/r;->i()V

    .line 238
    .line 239
    .line 240
    goto :goto_4

    .line 241
    :catchall_0
    move-exception p0

    .line 242
    goto :goto_3

    .line 243
    :catchall_1
    move-exception p0

    .line 244
    invoke-interface {p3}, Le3/r;->i()V

    .line 245
    .line 246
    .line 247
    throw p0

    .line 248
    :cond_c
    invoke-virtual {p0, p1}, Li3/c;->i(Lg3/d;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 249
    .line 250
    .line 251
    goto :goto_4

    .line 252
    :goto_3
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 253
    .line 254
    .line 255
    move-result-object p1

    .line 256
    iget-object p1, p1, Lgw0/c;->e:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast p1, Lbu/c;

    .line 259
    .line 260
    neg-float p2, v0

    .line 261
    neg-float p3, v2

    .line 262
    invoke-virtual {p1, p4, p4, p2, p3}, Lbu/c;->v(FFFF)V

    .line 263
    .line 264
    .line 265
    throw p0

    .line 266
    :cond_d
    :goto_4
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 267
    .line 268
    .line 269
    move-result-object p0

    .line 270
    iget-object p0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 271
    .line 272
    check-cast p0, Lbu/c;

    .line 273
    .line 274
    neg-float p1, v0

    .line 275
    neg-float p2, v2

    .line 276
    invoke-virtual {p0, p4, p4, p1, p2}, Lbu/c;->v(FFFF)V

    .line 277
    .line 278
    .line 279
    return-void
.end method

.method public abstract g()J
.end method

.method public abstract i(Lg3/d;)V
.end method
