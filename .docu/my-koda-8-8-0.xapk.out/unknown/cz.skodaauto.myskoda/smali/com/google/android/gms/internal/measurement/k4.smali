.class public final Lcom/google/android/gms/internal/measurement/k4;
.super Lcom/google/android/gms/internal/measurement/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic f:I

.field public final g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/u;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Lcom/google/android/gms/internal/measurement/k4;->f:I

    .line 1
    const-string v0, "internal.registerCallback"

    invoke-direct {p0, v0}, Lcom/google/android/gms/internal/measurement/i;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/k4;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/y5;Lb81/c;)V
    .locals 0

    const/4 p1, 0x1

    iput p1, p0, Lcom/google/android/gms/internal/measurement/k4;->f:I

    .line 2
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/k4;->g:Ljava/lang/Object;

    const-string p1, "getValue"

    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/measurement/i;-><init>(Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Lgw0/c;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/android/gms/internal/measurement/k4;->f:I

    .line 3
    const-string v0, "internal.eventLogger"

    invoke-direct {p0, v0}, Lcom/google/android/gms/internal/measurement/i;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/k4;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lro/f;)V
    .locals 6

    const/4 v0, 0x2

    iput v0, p0, Lcom/google/android/gms/internal/measurement/k4;->f:I

    .line 4
    const-string v0, "internal.logger"

    invoke-direct {p0, v0}, Lcom/google/android/gms/internal/measurement/i;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/k4;->g:Ljava/lang/Object;

    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/i;->e:Ljava/util/HashMap;

    new-instance v0, Lcom/google/android/gms/internal/measurement/y9;

    const/4 v1, 0x0

    const/4 v2, 0x1

    .line 5
    invoke-direct {v0, p0, v1, v2}, Lcom/google/android/gms/internal/measurement/y9;-><init>(Lcom/google/android/gms/internal/measurement/k4;ZZ)V

    const-string v3, "log"

    invoke-virtual {p1, v3, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/i;->e:Ljava/util/HashMap;

    new-instance v0, Lcom/google/android/gms/internal/measurement/y5;

    const/4 v4, 0x1

    .line 6
    const-string v5, "silent"

    invoke-direct {v0, v5, v4}, Lcom/google/android/gms/internal/measurement/y5;-><init>(Ljava/lang/String;I)V

    .line 7
    invoke-virtual {p1, v5, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/i;->e:Ljava/util/HashMap;

    .line 8
    invoke-virtual {p1, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/google/android/gms/internal/measurement/i;

    new-instance v0, Lcom/google/android/gms/internal/measurement/y9;

    invoke-direct {v0, p0, v2, v2}, Lcom/google/android/gms/internal/measurement/y9;-><init>(Lcom/google/android/gms/internal/measurement/k4;ZZ)V

    invoke-virtual {p1, v3, v0}, Lcom/google/android/gms/internal/measurement/i;->e(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V

    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/i;->e:Ljava/util/HashMap;

    new-instance v0, Lcom/google/android/gms/internal/measurement/y5;

    const/4 v2, 0x2

    .line 9
    const-string v4, "unmonitored"

    invoke-direct {v0, v4, v2}, Lcom/google/android/gms/internal/measurement/y5;-><init>(Ljava/lang/String;I)V

    .line 10
    invoke-virtual {p1, v4, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/i;->e:Ljava/util/HashMap;

    .line 11
    invoke-virtual {p1, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/google/android/gms/internal/measurement/i;

    new-instance v0, Lcom/google/android/gms/internal/measurement/y9;

    invoke-direct {v0, p0, v1, v1}, Lcom/google/android/gms/internal/measurement/y9;-><init>(Lcom/google/android/gms/internal/measurement/k4;ZZ)V

    invoke-virtual {p1, v3, v0}, Lcom/google/android/gms/internal/measurement/i;->e(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V

    return-void
.end method

.method public constructor <init>(Lvp/z0;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lcom/google/android/gms/internal/measurement/k4;->f:I

    .line 12
    const-string v0, "internal.appMetadata"

    invoke-direct {p0, v0}, Lcom/google/android/gms/internal/measurement/i;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/k4;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a(Lcom/google/firebase/messaging/w;Ljava/util/List;)Lcom/google/android/gms/internal/measurement/o;
    .locals 7

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/k4;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i;->d:Ljava/lang/String;

    .line 7
    .line 8
    const/4 v1, 0x3

    .line 9
    invoke-static {v1, v0, p2}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 10
    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 18
    .line 19
    iget-object v1, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 22
    .line 23
    invoke-virtual {v1, p1, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    const/4 v0, 0x1

    .line 31
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 36
    .line 37
    iget-object v2, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v2, Lcom/google/android/gms/internal/measurement/u;

    .line 40
    .line 41
    invoke-virtual {v2, p1, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    instance-of v3, v1, Lcom/google/android/gms/internal/measurement/n;

    .line 46
    .line 47
    if-eqz v3, :cond_6

    .line 48
    .line 49
    const/4 v3, 0x2

    .line 50
    invoke-interface {p2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    check-cast p2, Lcom/google/android/gms/internal/measurement/o;

    .line 55
    .line 56
    invoke-virtual {v2, p1, p2}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    instance-of p2, p1, Lcom/google/android/gms/internal/measurement/l;

    .line 61
    .line 62
    if-eqz p2, :cond_5

    .line 63
    .line 64
    check-cast p1, Lcom/google/android/gms/internal/measurement/l;

    .line 65
    .line 66
    iget-object p2, p1, Lcom/google/android/gms/internal/measurement/l;->d:Ljava/util/HashMap;

    .line 67
    .line 68
    const-string v2, "type"

    .line 69
    .line 70
    invoke-virtual {p2, v2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    if-eqz v3, :cond_4

    .line 75
    .line 76
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/measurement/l;->c(Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/o;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-interface {v2}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    const-string v3, "priority"

    .line 85
    .line 86
    invoke-virtual {p2, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    if-eqz p2, :cond_0

    .line 91
    .line 92
    invoke-virtual {p1, v3}, Lcom/google/android/gms/internal/measurement/l;->c(Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/o;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    invoke-interface {p1}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-virtual {p1}, Ljava/lang/Double;->doubleValue()D

    .line 101
    .line 102
    .line 103
    move-result-wide p1

    .line 104
    invoke-static {p1, p2}, Ljp/wd;->h(D)I

    .line 105
    .line 106
    .line 107
    move-result p1

    .line 108
    goto :goto_0

    .line 109
    :cond_0
    const/16 p1, 0x3e8

    .line 110
    .line 111
    :goto_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/k4;->g:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast p0, Lcom/google/android/gms/internal/measurement/u;

    .line 114
    .line 115
    check-cast v1, Lcom/google/android/gms/internal/measurement/n;

    .line 116
    .line 117
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    const-string p2, "create"

    .line 121
    .line 122
    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result p2

    .line 126
    if-eqz p2, :cond_1

    .line 127
    .line 128
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/u;->b:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast p0, Ljava/util/TreeMap;

    .line 131
    .line 132
    goto :goto_1

    .line 133
    :cond_1
    const-string p2, "edit"

    .line 134
    .line 135
    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result p2

    .line 139
    if-eqz p2, :cond_3

    .line 140
    .line 141
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/u;->a:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast p0, Ljava/util/TreeMap;

    .line 144
    .line 145
    :goto_1
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 146
    .line 147
    .line 148
    move-result-object p2

    .line 149
    invoke-virtual {p0, p2}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result p2

    .line 153
    if-eqz p2, :cond_2

    .line 154
    .line 155
    invoke-virtual {p0}, Ljava/util/TreeMap;->lastKey()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    check-cast p1, Ljava/lang/Integer;

    .line 160
    .line 161
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 162
    .line 163
    .line 164
    move-result p1

    .line 165
    add-int/2addr p1, v0

    .line 166
    :cond_2
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    invoke-virtual {p0, p1, v1}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    sget-object p0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 174
    .line 175
    return-object p0

    .line 176
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 177
    .line 178
    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    const-string p2, "Unknown callback type: "

    .line 183
    .line 184
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    throw p0

    .line 192
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 193
    .line 194
    const-string p1, "Undefined rule type"

    .line 195
    .line 196
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    throw p0

    .line 200
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 201
    .line 202
    const-string p1, "Invalid callback params"

    .line 203
    .line 204
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    throw p0

    .line 208
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 209
    .line 210
    const-string p1, "Invalid callback type"

    .line 211
    .line 212
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    throw p0

    .line 216
    :pswitch_0
    :try_start_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/k4;->g:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast p0, Lvp/z0;

    .line 219
    .line 220
    invoke-virtual {p0}, Lvp/z0;->call()Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    invoke-static {p0}, Ljp/xd;->b(Ljava/lang/Object;)Lcom/google/android/gms/internal/measurement/o;

    .line 225
    .line 226
    .line 227
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 228
    goto :goto_2

    .line 229
    :catch_0
    sget-object p0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 230
    .line 231
    :goto_2
    return-object p0

    .line 232
    :pswitch_1
    sget-object p0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 233
    .line 234
    return-object p0

    .line 235
    :pswitch_2
    const-string v0, "getValue"

    .line 236
    .line 237
    const/4 v1, 0x2

    .line 238
    invoke-static {v1, v0, p2}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 239
    .line 240
    .line 241
    const/4 v0, 0x0

    .line 242
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v0

    .line 246
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 247
    .line 248
    iget-object v1, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 249
    .line 250
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 251
    .line 252
    invoke-virtual {v1, p1, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    const/4 v1, 0x1

    .line 257
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object p2

    .line 261
    check-cast p2, Lcom/google/android/gms/internal/measurement/o;

    .line 262
    .line 263
    iget-object v1, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 264
    .line 265
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 266
    .line 267
    invoke-virtual {v1, p1, p2}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 268
    .line 269
    .line 270
    move-result-object p1

    .line 271
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object p2

    .line 275
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/k4;->g:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast p0, Lb81/c;

    .line 278
    .line 279
    iget-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 280
    .line 281
    check-cast v0, Lvp/a1;

    .line 282
    .line 283
    iget-object v0, v0, Lvp/a1;->h:Landroidx/collection/f;

    .line 284
    .line 285
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast p0, Ljava/lang/String;

    .line 288
    .line 289
    invoke-interface {v0, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object p0

    .line 293
    check-cast p0, Ljava/util/Map;

    .line 294
    .line 295
    if-eqz p0, :cond_8

    .line 296
    .line 297
    invoke-interface {p0, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 298
    .line 299
    .line 300
    move-result v0

    .line 301
    if-nez v0, :cond_7

    .line 302
    .line 303
    goto :goto_3

    .line 304
    :cond_7
    invoke-interface {p0, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object p0

    .line 308
    check-cast p0, Ljava/lang/String;

    .line 309
    .line 310
    goto :goto_4

    .line 311
    :cond_8
    :goto_3
    const/4 p0, 0x0

    .line 312
    :goto_4
    if-eqz p0, :cond_9

    .line 313
    .line 314
    new-instance p1, Lcom/google/android/gms/internal/measurement/r;

    .line 315
    .line 316
    invoke-direct {p1, p0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    :cond_9
    return-object p1

    .line 320
    :pswitch_3
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i;->d:Ljava/lang/String;

    .line 321
    .line 322
    const/4 v1, 0x3

    .line 323
    invoke-static {v1, v0, p2}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 324
    .line 325
    .line 326
    const/4 v0, 0x0

    .line 327
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v0

    .line 331
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 332
    .line 333
    iget-object v1, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 334
    .line 335
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 336
    .line 337
    invoke-virtual {v1, p1, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    const/4 v1, 0x1

    .line 346
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v1

    .line 350
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 351
    .line 352
    iget-object v2, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 353
    .line 354
    check-cast v2, Lcom/google/android/gms/internal/measurement/u;

    .line 355
    .line 356
    invoke-virtual {v2, p1, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 357
    .line 358
    .line 359
    move-result-object v1

    .line 360
    invoke-interface {v1}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 361
    .line 362
    .line 363
    move-result-object v1

    .line 364
    invoke-virtual {v1}, Ljava/lang/Double;->doubleValue()D

    .line 365
    .line 366
    .line 367
    move-result-wide v3

    .line 368
    invoke-static {v3, v4}, Ljp/wd;->i(D)D

    .line 369
    .line 370
    .line 371
    move-result-wide v3

    .line 372
    double-to-long v3, v3

    .line 373
    const/4 v1, 0x2

    .line 374
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object p2

    .line 378
    check-cast p2, Lcom/google/android/gms/internal/measurement/o;

    .line 379
    .line 380
    invoke-virtual {v2, p1, p2}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 381
    .line 382
    .line 383
    move-result-object p1

    .line 384
    instance-of p2, p1, Lcom/google/android/gms/internal/measurement/l;

    .line 385
    .line 386
    if-eqz p2, :cond_a

    .line 387
    .line 388
    check-cast p1, Lcom/google/android/gms/internal/measurement/l;

    .line 389
    .line 390
    invoke-static {p1}, Ljp/wd;->k(Lcom/google/android/gms/internal/measurement/l;)Ljava/util/HashMap;

    .line 391
    .line 392
    .line 393
    move-result-object p1

    .line 394
    goto :goto_5

    .line 395
    :cond_a
    new-instance p1, Ljava/util/HashMap;

    .line 396
    .line 397
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 398
    .line 399
    .line 400
    :goto_5
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/k4;->g:Ljava/lang/Object;

    .line 401
    .line 402
    check-cast p0, Lgw0/c;

    .line 403
    .line 404
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 405
    .line 406
    .line 407
    new-instance p2, Ljava/util/HashMap;

    .line 408
    .line 409
    invoke-direct {p2}, Ljava/util/HashMap;-><init>()V

    .line 410
    .line 411
    .line 412
    invoke-interface {p1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 413
    .line 414
    .line 415
    move-result-object v1

    .line 416
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 417
    .line 418
    .line 419
    move-result-object v1

    .line 420
    :goto_6
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 421
    .line 422
    .line 423
    move-result v2

    .line 424
    if-eqz v2, :cond_c

    .line 425
    .line 426
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 427
    .line 428
    .line 429
    move-result-object v2

    .line 430
    check-cast v2, Ljava/lang/String;

    .line 431
    .line 432
    iget-object v5, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 433
    .line 434
    check-cast v5, Lcom/google/android/gms/internal/measurement/b;

    .line 435
    .line 436
    iget-object v5, v5, Lcom/google/android/gms/internal/measurement/b;->c:Ljava/util/HashMap;

    .line 437
    .line 438
    invoke-virtual {v5, v2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 439
    .line 440
    .line 441
    move-result v6

    .line 442
    if-eqz v6, :cond_b

    .line 443
    .line 444
    invoke-virtual {v5, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    move-result-object v5

    .line 448
    goto :goto_7

    .line 449
    :cond_b
    const/4 v5, 0x0

    .line 450
    :goto_7
    invoke-interface {p1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    move-result-object v6

    .line 454
    invoke-static {v5, v6, v2}, Lcom/google/android/gms/internal/measurement/b;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    move-result-object v5

    .line 458
    invoke-virtual {p2, v2, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    goto :goto_6

    .line 462
    :cond_c
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 463
    .line 464
    check-cast p0, Ljava/util/ArrayList;

    .line 465
    .line 466
    new-instance p1, Lcom/google/android/gms/internal/measurement/b;

    .line 467
    .line 468
    invoke-direct {p1, v0, v3, v4, p2}, Lcom/google/android/gms/internal/measurement/b;-><init>(Ljava/lang/String;JLjava/util/HashMap;)V

    .line 469
    .line 470
    .line 471
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 472
    .line 473
    .line 474
    sget-object p0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 475
    .line 476
    return-object p0

    .line 477
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
