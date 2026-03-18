.class public final Lvp/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:J

.field public final synthetic g:Lvp/x;


# direct methods
.method public constructor <init>(Lvp/u2;Lvp/r2;J)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lvp/a;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lvp/a;->e:Ljava/lang/Object;

    iput-wide p3, p0, Lvp/a;->f:J

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/a;->g:Lvp/x;

    return-void
.end method

.method public synthetic constructor <init>(Lvp/w;Ljava/lang/String;JI)V
    .locals 0

    .line 1
    iput p5, p0, Lvp/a;->d:I

    iput-object p2, p0, Lvp/a;->e:Ljava/lang/Object;

    iput-wide p3, p0, Lvp/a;->f:J

    iput-object p1, p0, Lvp/a;->g:Lvp/x;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 11

    .line 1
    iget v0, p0, Lvp/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/a;->g:Lvp/x;

    .line 7
    .line 8
    check-cast v0, Lvp/u2;

    .line 9
    .line 10
    iget-object v1, p0, Lvp/a;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lvp/r2;

    .line 13
    .line 14
    iget-wide v2, p0, Lvp/a;->f:J

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    invoke-virtual {v0, v1, p0, v2, v3}, Lvp/u2;->e0(Lvp/r2;ZJ)V

    .line 18
    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    iput-object p0, v0, Lvp/u2;->i:Lvp/r2;

    .line 22
    .line 23
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v0, Lvp/g1;

    .line 26
    .line 27
    invoke-virtual {v0}, Lvp/g1;->o()Lvp/d3;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 35
    .line 36
    .line 37
    new-instance v1, Llr/b;

    .line 38
    .line 39
    invoke-direct {v1, v0, p0}, Llr/b;-><init>(Lvp/d3;Lvp/r2;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, v1}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :pswitch_0
    iget-object v0, p0, Lvp/a;->g:Lvp/x;

    .line 47
    .line 48
    check-cast v0, Lvp/w;

    .line 49
    .line 50
    iget-object v1, p0, Lvp/a;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v1, Ljava/lang/String;

    .line 53
    .line 54
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v2, Lvp/g1;

    .line 57
    .line 58
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 59
    .line 60
    .line 61
    invoke-static {v1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iget-object v3, v0, Lvp/w;->g:Landroidx/collection/f;

    .line 65
    .line 66
    invoke-interface {v3, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    check-cast v4, Ljava/lang/Integer;

    .line 71
    .line 72
    if-eqz v4, :cond_3

    .line 73
    .line 74
    iget-object v5, v2, Lvp/g1;->o:Lvp/u2;

    .line 75
    .line 76
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 77
    .line 78
    invoke-static {v5}, Lvp/g1;->i(Lvp/b0;)V

    .line 79
    .line 80
    .line 81
    const/4 v6, 0x0

    .line 82
    invoke-virtual {v5, v6}, Lvp/u2;->g0(Z)Lvp/r2;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    add-int/lit8 v4, v4, -0x1

    .line 91
    .line 92
    if-nez v4, :cond_2

    .line 93
    .line 94
    invoke-interface {v3, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    iget-object v4, v0, Lvp/w;->f:Landroidx/collection/f;

    .line 98
    .line 99
    invoke-interface {v4, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    check-cast v6, Ljava/lang/Long;

    .line 104
    .line 105
    iget-wide v7, p0, Lvp/a;->f:J

    .line 106
    .line 107
    if-nez v6, :cond_0

    .line 108
    .line 109
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 110
    .line 111
    .line 112
    iget-object p0, v2, Lvp/p0;->j:Lvp/n0;

    .line 113
    .line 114
    const-string v1, "First ad unit exposure time was never set"

    .line 115
    .line 116
    invoke-virtual {p0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_0
    invoke-virtual {v6}, Ljava/lang/Long;->longValue()J

    .line 121
    .line 122
    .line 123
    move-result-wide v9

    .line 124
    sub-long v9, v7, v9

    .line 125
    .line 126
    invoke-interface {v4, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v0, v1, v9, v10, v5}, Lvp/w;->f0(Ljava/lang/String;JLvp/r2;)V

    .line 130
    .line 131
    .line 132
    :goto_0
    invoke-interface {v3}, Ljava/util/Map;->isEmpty()Z

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    if-eqz p0, :cond_4

    .line 137
    .line 138
    iget-wide v3, v0, Lvp/w;->h:J

    .line 139
    .line 140
    const-wide/16 v9, 0x0

    .line 141
    .line 142
    cmp-long p0, v3, v9

    .line 143
    .line 144
    if-nez p0, :cond_1

    .line 145
    .line 146
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 147
    .line 148
    .line 149
    iget-object p0, v2, Lvp/p0;->j:Lvp/n0;

    .line 150
    .line 151
    const-string v0, "First ad exposure time was never set"

    .line 152
    .line 153
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    goto :goto_1

    .line 157
    :cond_1
    sub-long/2addr v7, v3

    .line 158
    invoke-virtual {v0, v7, v8, v5}, Lvp/w;->e0(JLvp/r2;)V

    .line 159
    .line 160
    .line 161
    iput-wide v9, v0, Lvp/w;->h:J

    .line 162
    .line 163
    goto :goto_1

    .line 164
    :cond_2
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    invoke-interface {v3, v1, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    goto :goto_1

    .line 172
    :cond_3
    iget-object p0, v2, Lvp/g1;->i:Lvp/p0;

    .line 173
    .line 174
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 175
    .line 176
    .line 177
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 178
    .line 179
    const-string v0, "Call to endAdUnitExposure for unknown ad unit id"

    .line 180
    .line 181
    invoke-virtual {p0, v1, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    :cond_4
    :goto_1
    return-void

    .line 185
    :pswitch_1
    iget-object v0, p0, Lvp/a;->g:Lvp/x;

    .line 186
    .line 187
    check-cast v0, Lvp/w;

    .line 188
    .line 189
    iget-object v1, p0, Lvp/a;->e:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast v1, Ljava/lang/String;

    .line 192
    .line 193
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 194
    .line 195
    .line 196
    invoke-static {v1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    iget-object v2, v0, Lvp/w;->g:Landroidx/collection/f;

    .line 200
    .line 201
    invoke-interface {v2}, Ljava/util/Map;->isEmpty()Z

    .line 202
    .line 203
    .line 204
    move-result v3

    .line 205
    iget-wide v4, p0, Lvp/a;->f:J

    .line 206
    .line 207
    if-eqz v3, :cond_5

    .line 208
    .line 209
    iput-wide v4, v0, Lvp/w;->h:J

    .line 210
    .line 211
    :cond_5
    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    check-cast p0, Ljava/lang/Integer;

    .line 216
    .line 217
    const/4 v3, 0x1

    .line 218
    if-eqz p0, :cond_6

    .line 219
    .line 220
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 221
    .line 222
    .line 223
    move-result p0

    .line 224
    add-int/2addr p0, v3

    .line 225
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    invoke-interface {v2, v1, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    goto :goto_2

    .line 233
    :cond_6
    invoke-interface {v2}, Ljava/util/Map;->size()I

    .line 234
    .line 235
    .line 236
    move-result p0

    .line 237
    const/16 v6, 0x64

    .line 238
    .line 239
    if-lt p0, v6, :cond_7

    .line 240
    .line 241
    iget-object p0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 242
    .line 243
    check-cast p0, Lvp/g1;

    .line 244
    .line 245
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 246
    .line 247
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 248
    .line 249
    .line 250
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 251
    .line 252
    const-string v0, "Too many ads visible"

    .line 253
    .line 254
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    goto :goto_2

    .line 258
    :cond_7
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 259
    .line 260
    .line 261
    move-result-object p0

    .line 262
    invoke-interface {v2, v1, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    iget-object p0, v0, Lvp/w;->f:Landroidx/collection/f;

    .line 266
    .line 267
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 268
    .line 269
    .line 270
    move-result-object v0

    .line 271
    invoke-interface {p0, v1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    :goto_2
    return-void

    .line 275
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
