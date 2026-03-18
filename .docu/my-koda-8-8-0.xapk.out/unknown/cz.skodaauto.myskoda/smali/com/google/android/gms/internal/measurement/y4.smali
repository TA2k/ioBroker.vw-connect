.class public final Lcom/google/android/gms/internal/measurement/y4;
.super Lcom/google/android/gms/internal/measurement/l;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Lgw0/c;


# direct methods
.method public constructor <init>(Lgw0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/android/gms/internal/measurement/l;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/y4;->e:Lgw0/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final o(Ljava/lang/String;Lcom/google/firebase/messaging/w;Ljava/util/ArrayList;)Lcom/google/android/gms/internal/measurement/o;
    .locals 5

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/y4;->e:Lgw0/c;

    .line 7
    .line 8
    const/4 v3, 0x0

    .line 9
    sparse-switch v0, :sswitch_data_0

    .line 10
    .line 11
    .line 12
    goto/16 :goto_2

    .line 13
    .line 14
    :sswitch_0
    const-string v0, "setEventName"

    .line 15
    .line 16
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v4

    .line 20
    if-eqz v4, :cond_4

    .line 21
    .line 22
    invoke-static {v1, v0, p3}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p3, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Lcom/google/android/gms/internal/measurement/o;

    .line 30
    .line 31
    iget-object p1, p2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p1, Lcom/google/android/gms/internal/measurement/u;

    .line 34
    .line 35
    invoke-virtual {p1, p2, p0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    sget-object p1, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 40
    .line 41
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/measurement/s;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-nez p1, :cond_0

    .line 46
    .line 47
    sget-object p1, Lcom/google/android/gms/internal/measurement/o;->n0:Lcom/google/android/gms/internal/measurement/m;

    .line 48
    .line 49
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/measurement/m;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    if-nez p1, :cond_0

    .line 54
    .line 55
    iget-object p1, v2, Lgw0/c;->f:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p1, Lcom/google/android/gms/internal/measurement/b;

    .line 58
    .line 59
    invoke-interface {p0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    iput-object p2, p1, Lcom/google/android/gms/internal/measurement/b;->a:Ljava/lang/String;

    .line 64
    .line 65
    new-instance p1, Lcom/google/android/gms/internal/measurement/r;

    .line 66
    .line 67
    invoke-interface {p0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-direct {p1, p0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    return-object p1

    .line 75
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 76
    .line 77
    const-string p1, "Illegal event name"

    .line 78
    .line 79
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p0

    .line 83
    :sswitch_1
    const-string v0, "setParamValue"

    .line 84
    .line 85
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    if-eqz v4, :cond_4

    .line 90
    .line 91
    const/4 p0, 0x2

    .line 92
    invoke-static {p0, v0, p3}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p3, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Lcom/google/android/gms/internal/measurement/o;

    .line 100
    .line 101
    iget-object p1, p2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast p1, Lcom/google/android/gms/internal/measurement/u;

    .line 104
    .line 105
    invoke-virtual {p1, p2, p0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-interface {p0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    invoke-virtual {p3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    check-cast p1, Lcom/google/android/gms/internal/measurement/o;

    .line 118
    .line 119
    iget-object p3, p2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast p3, Lcom/google/android/gms/internal/measurement/u;

    .line 122
    .line 123
    invoke-virtual {p3, p2, p1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    iget-object p2, v2, Lgw0/c;->f:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast p2, Lcom/google/android/gms/internal/measurement/b;

    .line 130
    .line 131
    invoke-static {p1}, Ljp/wd;->j(Lcom/google/android/gms/internal/measurement/o;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p3

    .line 135
    iget-object p2, p2, Lcom/google/android/gms/internal/measurement/b;->c:Ljava/util/HashMap;

    .line 136
    .line 137
    if-nez p3, :cond_1

    .line 138
    .line 139
    invoke-virtual {p2, p0}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    return-object p1

    .line 143
    :cond_1
    invoke-virtual {p2, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    invoke-static {v0, p3, p0}, Lcom/google/android/gms/internal/measurement/b;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p3

    .line 151
    invoke-virtual {p2, p0, p3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    return-object p1

    .line 155
    :sswitch_2
    const-string v0, "getParams"

    .line 156
    .line 157
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v1

    .line 161
    if-eqz v1, :cond_4

    .line 162
    .line 163
    invoke-static {v3, v0, p3}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 164
    .line 165
    .line 166
    iget-object p0, v2, Lgw0/c;->f:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast p0, Lcom/google/android/gms/internal/measurement/b;

    .line 169
    .line 170
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/b;->c:Ljava/util/HashMap;

    .line 171
    .line 172
    new-instance p1, Lcom/google/android/gms/internal/measurement/l;

    .line 173
    .line 174
    invoke-direct {p1}, Lcom/google/android/gms/internal/measurement/l;-><init>()V

    .line 175
    .line 176
    .line 177
    invoke-virtual {p0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 178
    .line 179
    .line 180
    move-result-object p2

    .line 181
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 182
    .line 183
    .line 184
    move-result-object p2

    .line 185
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 186
    .line 187
    .line 188
    move-result p3

    .line 189
    if-eqz p3, :cond_2

    .line 190
    .line 191
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object p3

    .line 195
    check-cast p3, Ljava/lang/String;

    .line 196
    .line 197
    invoke-virtual {p0, p3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    invoke-static {v0}, Ljp/xd;->b(Ljava/lang/Object;)Lcom/google/android/gms/internal/measurement/o;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    invoke-virtual {p1, p3, v0}, Lcom/google/android/gms/internal/measurement/l;->e(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V

    .line 206
    .line 207
    .line 208
    goto :goto_0

    .line 209
    :cond_2
    return-object p1

    .line 210
    :sswitch_3
    const-string v0, "getParamValue"

    .line 211
    .line 212
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result v4

    .line 216
    if-eqz v4, :cond_4

    .line 217
    .line 218
    invoke-static {v1, v0, p3}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {p3, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    check-cast p0, Lcom/google/android/gms/internal/measurement/o;

    .line 226
    .line 227
    iget-object p1, p2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast p1, Lcom/google/android/gms/internal/measurement/u;

    .line 230
    .line 231
    invoke-virtual {p1, p2, p0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    invoke-interface {p0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    iget-object p1, v2, Lgw0/c;->f:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast p1, Lcom/google/android/gms/internal/measurement/b;

    .line 242
    .line 243
    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/b;->c:Ljava/util/HashMap;

    .line 244
    .line 245
    invoke-virtual {p1, p0}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result p2

    .line 249
    if-eqz p2, :cond_3

    .line 250
    .line 251
    invoke-virtual {p1, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    goto :goto_1

    .line 256
    :cond_3
    const/4 p0, 0x0

    .line 257
    :goto_1
    invoke-static {p0}, Ljp/xd;->b(Ljava/lang/Object;)Lcom/google/android/gms/internal/measurement/o;

    .line 258
    .line 259
    .line 260
    move-result-object p0

    .line 261
    return-object p0

    .line 262
    :sswitch_4
    const-string v0, "getTimestamp"

    .line 263
    .line 264
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v1

    .line 268
    if-eqz v1, :cond_4

    .line 269
    .line 270
    invoke-static {v3, v0, p3}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 271
    .line 272
    .line 273
    iget-object p0, v2, Lgw0/c;->f:Ljava/lang/Object;

    .line 274
    .line 275
    check-cast p0, Lcom/google/android/gms/internal/measurement/b;

    .line 276
    .line 277
    new-instance p1, Lcom/google/android/gms/internal/measurement/h;

    .line 278
    .line 279
    iget-wide p2, p0, Lcom/google/android/gms/internal/measurement/b;->b:J

    .line 280
    .line 281
    long-to-double p2, p2

    .line 282
    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 283
    .line 284
    .line 285
    move-result-object p0

    .line 286
    invoke-direct {p1, p0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 287
    .line 288
    .line 289
    return-object p1

    .line 290
    :sswitch_5
    const-string v0, "getEventName"

    .line 291
    .line 292
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 293
    .line 294
    .line 295
    move-result v1

    .line 296
    if-eqz v1, :cond_4

    .line 297
    .line 298
    invoke-static {v3, v0, p3}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 299
    .line 300
    .line 301
    iget-object p0, v2, Lgw0/c;->f:Ljava/lang/Object;

    .line 302
    .line 303
    check-cast p0, Lcom/google/android/gms/internal/measurement/b;

    .line 304
    .line 305
    new-instance p1, Lcom/google/android/gms/internal/measurement/r;

    .line 306
    .line 307
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/b;->a:Ljava/lang/String;

    .line 308
    .line 309
    invoke-direct {p1, p0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    return-object p1

    .line 313
    :cond_4
    :goto_2
    invoke-super {p0, p1, p2, p3}, Lcom/google/android/gms/internal/measurement/l;->o(Ljava/lang/String;Lcom/google/firebase/messaging/w;Ljava/util/ArrayList;)Lcom/google/android/gms/internal/measurement/o;

    .line 314
    .line 315
    .line 316
    move-result-object p0

    .line 317
    return-object p0

    .line 318
    nop

    .line 319
    :sswitch_data_0
    .sparse-switch
        0x149f58f -> :sswitch_5
        0x2b69a60 -> :sswitch_4
        0x8bc90da -> :sswitch_3
        0x29c21c7c -> :sswitch_2
        0x36e0dee6 -> :sswitch_1
        0x5d9db603 -> :sswitch_0
    .end sparse-switch
.end method
