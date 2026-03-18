.class public final Lb1/q0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lb1/s0;

.field public final synthetic h:J


# direct methods
.method public synthetic constructor <init>(Lb1/s0;JI)V
    .locals 0

    .line 1
    iput p4, p0, Lb1/q0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/q0;->g:Lb1/s0;

    .line 4
    .line 5
    iput-wide p2, p0, Lb1/q0;->h:J

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lb1/q0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lb1/i0;

    .line 7
    .line 8
    iget-object v0, p0, Lb1/q0;->g:Lb1/s0;

    .line 9
    .line 10
    iget-object v1, v0, Lb1/s0;->w:Lb1/t0;

    .line 11
    .line 12
    iget-object v1, v1, Lb1/t0;->a:Lb1/i1;

    .line 13
    .line 14
    iget-object v1, v1, Lb1/i1;->b:Lb1/g1;

    .line 15
    .line 16
    iget-wide v2, p0, Lb1/q0;->h:J

    .line 17
    .line 18
    const-wide/16 v4, 0x0

    .line 19
    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    iget-object p0, v1, Lb1/g1;->a:Lkotlin/jvm/internal/n;

    .line 23
    .line 24
    new-instance v1, Lt4/l;

    .line 25
    .line 26
    invoke-direct {v1, v2, v3}, Lt4/l;-><init>(J)V

    .line 27
    .line 28
    .line 29
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Lt4/j;

    .line 34
    .line 35
    iget-wide v6, p0, Lt4/j;->a:J

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move-wide v6, v4

    .line 39
    :goto_0
    iget-object p0, v0, Lb1/s0;->x:Lb1/u0;

    .line 40
    .line 41
    iget-object p0, p0, Lb1/u0;->a:Lb1/i1;

    .line 42
    .line 43
    iget-object p0, p0, Lb1/i1;->b:Lb1/g1;

    .line 44
    .line 45
    if-eqz p0, :cond_1

    .line 46
    .line 47
    iget-object p0, p0, Lb1/g1;->a:Lkotlin/jvm/internal/n;

    .line 48
    .line 49
    new-instance v0, Lt4/l;

    .line 50
    .line 51
    invoke-direct {v0, v2, v3}, Lt4/l;-><init>(J)V

    .line 52
    .line 53
    .line 54
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    check-cast p0, Lt4/j;

    .line 59
    .line 60
    iget-wide v0, p0, Lt4/j;->a:J

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    move-wide v0, v4

    .line 64
    :goto_1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-eqz p0, :cond_3

    .line 69
    .line 70
    const/4 p1, 0x1

    .line 71
    if-eq p0, p1, :cond_4

    .line 72
    .line 73
    const/4 p1, 0x2

    .line 74
    if-ne p0, p1, :cond_2

    .line 75
    .line 76
    move-wide v4, v0

    .line 77
    goto :goto_2

    .line 78
    :cond_2
    new-instance p0, La8/r0;

    .line 79
    .line 80
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :cond_3
    move-wide v4, v6

    .line 85
    :cond_4
    :goto_2
    new-instance p0, Lt4/j;

    .line 86
    .line 87
    invoke-direct {p0, v4, v5}, Lt4/j;-><init>(J)V

    .line 88
    .line 89
    .line 90
    return-object p0

    .line 91
    :pswitch_0
    check-cast p1, Lb1/i0;

    .line 92
    .line 93
    iget-object v0, p0, Lb1/q0;->g:Lb1/s0;

    .line 94
    .line 95
    iget-object v1, v0, Lb1/s0;->B:Lx2/e;

    .line 96
    .line 97
    if-nez v1, :cond_5

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_5
    invoke-virtual {v0}, Lb1/s0;->Z0()Lx2/e;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    if-nez v1, :cond_6

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_6
    iget-object v1, v0, Lb1/s0;->B:Lx2/e;

    .line 108
    .line 109
    invoke-virtual {v0}, Lb1/s0;->Z0()Lx2/e;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    if-eqz v1, :cond_7

    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    if-eqz p1, :cond_9

    .line 125
    .line 126
    const/4 v1, 0x1

    .line 127
    if-eq p1, v1, :cond_9

    .line 128
    .line 129
    const/4 v1, 0x2

    .line 130
    if-ne p1, v1, :cond_8

    .line 131
    .line 132
    iget-object p1, v0, Lb1/s0;->x:Lb1/u0;

    .line 133
    .line 134
    iget-object p1, p1, Lb1/u0;->a:Lb1/i1;

    .line 135
    .line 136
    iget-object p1, p1, Lb1/i1;->c:Lb1/c0;

    .line 137
    .line 138
    if-eqz p1, :cond_9

    .line 139
    .line 140
    iget-object p1, p1, Lb1/c0;->b:Lay0/k;

    .line 141
    .line 142
    new-instance v1, Lt4/l;

    .line 143
    .line 144
    iget-wide v3, p0, Lb1/q0;->h:J

    .line 145
    .line 146
    invoke-direct {v1, v3, v4}, Lt4/l;-><init>(J)V

    .line 147
    .line 148
    .line 149
    invoke-interface {p1, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    check-cast p0, Lt4/l;

    .line 154
    .line 155
    iget-wide v5, p0, Lt4/l;->a:J

    .line 156
    .line 157
    invoke-virtual {v0}, Lb1/s0;->Z0()Lx2/e;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    sget-object v7, Lt4/m;->d:Lt4/m;

    .line 165
    .line 166
    move-object v2, p0

    .line 167
    check-cast v2, Lx2/j;

    .line 168
    .line 169
    invoke-virtual/range {v2 .. v7}, Lx2/j;->a(JJLt4/m;)J

    .line 170
    .line 171
    .line 172
    move-result-wide p0

    .line 173
    iget-object v2, v0, Lb1/s0;->B:Lx2/e;

    .line 174
    .line 175
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    invoke-interface/range {v2 .. v7}, Lx2/e;->a(JJLt4/m;)J

    .line 179
    .line 180
    .line 181
    move-result-wide v0

    .line 182
    invoke-static {p0, p1, v0, v1}, Lt4/j;->c(JJ)J

    .line 183
    .line 184
    .line 185
    move-result-wide p0

    .line 186
    goto :goto_4

    .line 187
    :cond_8
    new-instance p0, La8/r0;

    .line 188
    .line 189
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 190
    .line 191
    .line 192
    throw p0

    .line 193
    :cond_9
    :goto_3
    const-wide/16 p0, 0x0

    .line 194
    .line 195
    :goto_4
    new-instance v0, Lt4/j;

    .line 196
    .line 197
    invoke-direct {v0, p0, p1}, Lt4/j;-><init>(J)V

    .line 198
    .line 199
    .line 200
    return-object v0

    .line 201
    :pswitch_1
    check-cast p1, Lb1/i0;

    .line 202
    .line 203
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 204
    .line 205
    .line 206
    move-result p1

    .line 207
    iget-object v0, p0, Lb1/q0;->g:Lb1/s0;

    .line 208
    .line 209
    iget-wide v1, p0, Lb1/q0;->h:J

    .line 210
    .line 211
    if-eqz p1, :cond_b

    .line 212
    .line 213
    const/4 p0, 0x1

    .line 214
    if-eq p1, p0, :cond_c

    .line 215
    .line 216
    const/4 p0, 0x2

    .line 217
    if-ne p1, p0, :cond_a

    .line 218
    .line 219
    iget-object p0, v0, Lb1/s0;->x:Lb1/u0;

    .line 220
    .line 221
    iget-object p0, p0, Lb1/u0;->a:Lb1/i1;

    .line 222
    .line 223
    iget-object p0, p0, Lb1/i1;->c:Lb1/c0;

    .line 224
    .line 225
    if-eqz p0, :cond_c

    .line 226
    .line 227
    iget-object p0, p0, Lb1/c0;->b:Lay0/k;

    .line 228
    .line 229
    new-instance p1, Lt4/l;

    .line 230
    .line 231
    invoke-direct {p1, v1, v2}, Lt4/l;-><init>(J)V

    .line 232
    .line 233
    .line 234
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    check-cast p0, Lt4/l;

    .line 239
    .line 240
    iget-wide v1, p0, Lt4/l;->a:J

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :cond_a
    new-instance p0, La8/r0;

    .line 244
    .line 245
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 246
    .line 247
    .line 248
    throw p0

    .line 249
    :cond_b
    iget-object p0, v0, Lb1/s0;->w:Lb1/t0;

    .line 250
    .line 251
    iget-object p0, p0, Lb1/t0;->a:Lb1/i1;

    .line 252
    .line 253
    iget-object p0, p0, Lb1/i1;->c:Lb1/c0;

    .line 254
    .line 255
    if-eqz p0, :cond_c

    .line 256
    .line 257
    iget-object p0, p0, Lb1/c0;->b:Lay0/k;

    .line 258
    .line 259
    new-instance p1, Lt4/l;

    .line 260
    .line 261
    invoke-direct {p1, v1, v2}, Lt4/l;-><init>(J)V

    .line 262
    .line 263
    .line 264
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object p0

    .line 268
    check-cast p0, Lt4/l;

    .line 269
    .line 270
    iget-wide v1, p0, Lt4/l;->a:J

    .line 271
    .line 272
    :cond_c
    :goto_5
    new-instance p0, Lt4/l;

    .line 273
    .line 274
    invoke-direct {p0, v1, v2}, Lt4/l;-><init>(J)V

    .line 275
    .line 276
    .line 277
    return-object p0

    .line 278
    nop

    .line 279
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
