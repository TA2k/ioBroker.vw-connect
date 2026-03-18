.class public final Lz81/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/export/LogRecordExporter;


# instance fields
.field public final d:Lb91/b;

.field public final e:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

.field public final f:Lce/s;

.field public final g:I

.field public final h:J

.field public final i:J

.field public final j:Lro/f;

.field public final k:Lpx0/g;

.field public final l:Lpw0/a;

.field public m:Lvy0/x1;


# direct methods
.method public constructor <init>(Lb91/b;Lio/opentelemetry/sdk/logs/export/LogRecordExporter;Lce/s;)V
    .locals 3

    .line 1
    new-instance v0, Lro/f;

    .line 2
    .line 3
    const/16 v1, 0x17

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lro/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sget-object v1, Lvy0/p0;->a:Lcz0/e;

    .line 9
    .line 10
    sget-object v1, Lcz0/d;->e:Lcz0/d;

    .line 11
    .line 12
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {v1, v2}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const-string v2, "persistenceCoroutineContext"

    .line 21
    .line 22
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lz81/l;->d:Lb91/b;

    .line 29
    .line 30
    iput-object p2, p0, Lz81/l;->e:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 31
    .line 32
    iput-object p3, p0, Lz81/l;->f:Lce/s;

    .line 33
    .line 34
    const/4 p1, 0x5

    .line 35
    iput p1, p0, Lz81/l;->g:I

    .line 36
    .line 37
    const-wide/16 p1, 0x2710

    .line 38
    .line 39
    iput-wide p1, p0, Lz81/l;->h:J

    .line 40
    .line 41
    const-wide/32 p1, 0xea60

    .line 42
    .line 43
    .line 44
    iput-wide p1, p0, Lz81/l;->i:J

    .line 45
    .line 46
    iput-object v0, p0, Lz81/l;->j:Lro/f;

    .line 47
    .line 48
    iput-object v1, p0, Lz81/l;->k:Lpx0/g;

    .line 49
    .line 50
    invoke-static {v1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    iput-object p1, p0, Lz81/l;->l:Lpw0/a;

    .line 55
    .line 56
    return-void
.end method

.method public static a(Ljava/util/Collection;)Ljava/util/ArrayList;
    .locals 3

    .line 1
    check-cast p0, Ljava/lang/Iterable;

    .line 2
    .line 3
    new-instance v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 6
    .line 7
    .line 8
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Lio/opentelemetry/sdk/logs/data/LogRecordData;

    .line 23
    .line 24
    invoke-interface {v1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    sget-object v2, Lz81/p;->b:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v2}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    invoke-interface {v1, v2}, Lio/opentelemetry/api/common/Attributes;->get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Ljava/lang/String;

    .line 39
    .line 40
    if-eqz v1, :cond_0

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    return-object v0
.end method

.method public static final b(Lz81/l;Ljava/util/Collection;)Ljava/util/ArrayList;
    .locals 1

    .line 1
    check-cast p1, Ljava/lang/Iterable;

    .line 2
    .line 3
    new-instance p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/16 v0, 0xa

    .line 6
    .line 7
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Lc91/x;

    .line 29
    .line 30
    iget-object v0, v0, Lc91/x;->b:Ljava/util/List;

    .line 31
    .line 32
    check-cast v0, Ljava/util/Collection;

    .line 33
    .line 34
    invoke-static {v0}, Lz81/l;->a(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-static {p0}, Lmx0/o;->t(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method


# virtual methods
.method public final close()V
    .locals 1

    .line 1
    iget-object v0, p0, Lz81/l;->e:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 2
    .line 3
    invoke-interface {v0}, Lio/opentelemetry/sdk/logs/export/LogRecordExporter;->close()V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Lio/opentelemetry/sdk/logs/export/LogRecordExporter;->close()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final export(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 10

    .line 1
    const-string v0, "logRecords"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lz81/p;->a:Lyy0/c2;

    .line 7
    .line 8
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lz81/q;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lz81/l;->m:Lvy0/x1;

    .line 18
    .line 19
    iget-object v1, p0, Lz81/l;->j:Lro/f;

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    invoke-virtual {v0}, Lvy0/p1;->isCancelled()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    const/4 v2, 0x1

    .line 28
    if-ne v0, v2, :cond_1

    .line 29
    .line 30
    :cond_0
    invoke-static {p1}, Lz81/l;->a(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    iget-object v2, v1, Lro/f;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v2, Lz81/f;

    .line 40
    .line 41
    sget-object v3, Lz81/f;->d:Lz81/f;

    .line 42
    .line 43
    invoke-virtual {v2, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-lez v2, :cond_1

    .line 48
    .line 49
    sget-object v2, Lx51/c;->o1:Lx51/b;

    .line 50
    .line 51
    iget-object v3, v2, Lx51/b;->d:La61/a;

    .line 52
    .line 53
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    iget-object v3, v1, Lro/f;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v3, Lz81/f;

    .line 59
    .line 60
    sget-object v4, Lz81/f;->e:Lz81/f;

    .line 61
    .line 62
    invoke-virtual {v3, v4}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-lez v3, :cond_1

    .line 67
    .line 68
    iget-object v2, v2, Lx51/b;->d:La61/a;

    .line 69
    .line 70
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    if-eqz v2, :cond_1

    .line 82
    .line 83
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    check-cast v2, Ljava/lang/String;

    .line 88
    .line 89
    sget-object v2, Lx51/c;->o1:Lx51/b;

    .line 90
    .line 91
    iget-object v2, v2, Lx51/b;->d:La61/a;

    .line 92
    .line 93
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_1
    move-object v0, p1

    .line 98
    check-cast v0, Ljava/lang/Iterable;

    .line 99
    .line 100
    invoke-static {v0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    new-instance v2, Lyj0/c;

    .line 105
    .line 106
    const/4 v3, 0x4

    .line 107
    const/4 v4, 0x0

    .line 108
    invoke-direct {v2, p0, v4, v3}, Lyj0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 109
    .line 110
    .line 111
    sget-object v3, Lpx0/h;->d:Lpx0/h;

    .line 112
    .line 113
    invoke-static {v3, v2}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    check-cast v2, Ljava/lang/Boolean;

    .line 118
    .line 119
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    const/4 v3, 0x3

    .line 124
    iget-object v5, p0, Lz81/l;->l:Lpw0/a;

    .line 125
    .line 126
    if-eqz v2, :cond_6

    .line 127
    .line 128
    iget-object v2, p0, Lz81/l;->e:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 129
    .line 130
    invoke-interface {v2, p1}, Lio/opentelemetry/sdk/logs/export/LogRecordExporter;->export(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    iget-wide v6, p0, Lz81/l;->i:J

    .line 135
    .line 136
    sget-object v8, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 137
    .line 138
    invoke-virtual {v2, v6, v7, v8}, Lio/opentelemetry/sdk/common/CompletableResultCode;->join(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v2}, Lio/opentelemetry/sdk/common/CompletableResultCode;->isSuccess()Z

    .line 142
    .line 143
    .line 144
    move-result v6

    .line 145
    if-nez v6, :cond_4

    .line 146
    .line 147
    invoke-static {p1}, Lz81/l;->a(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 148
    .line 149
    .line 150
    move-result-object v6

    .line 151
    invoke-virtual {v2}, Lio/opentelemetry/sdk/common/CompletableResultCode;->getFailureThrowable()Ljava/lang/Throwable;

    .line 152
    .line 153
    .line 154
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 155
    .line 156
    .line 157
    iget-object v7, v1, Lro/f;->e:Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v7, Lz81/f;

    .line 160
    .line 161
    sget-object v8, Lz81/f;->d:Lz81/f;

    .line 162
    .line 163
    invoke-virtual {v7, v8}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 164
    .line 165
    .line 166
    move-result v7

    .line 167
    if-lez v7, :cond_2

    .line 168
    .line 169
    sget-object v7, Lx51/c;->o1:Lx51/b;

    .line 170
    .line 171
    iget-object v8, v7, Lx51/b;->d:La61/a;

    .line 172
    .line 173
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    iget-object v8, v1, Lro/f;->e:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v8, Lz81/f;

    .line 179
    .line 180
    sget-object v9, Lz81/f;->e:Lz81/f;

    .line 181
    .line 182
    invoke-virtual {v8, v9}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 183
    .line 184
    .line 185
    move-result v8

    .line 186
    if-lez v8, :cond_2

    .line 187
    .line 188
    iget-object v7, v7, Lx51/b;->d:La61/a;

    .line 189
    .line 190
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 191
    .line 192
    .line 193
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 194
    .line 195
    .line 196
    move-result-object v6

    .line 197
    :goto_1
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 198
    .line 199
    .line 200
    move-result v7

    .line 201
    if-eqz v7, :cond_2

    .line 202
    .line 203
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v7

    .line 207
    check-cast v7, Ljava/lang/String;

    .line 208
    .line 209
    sget-object v7, Lx51/c;->o1:Lx51/b;

    .line 210
    .line 211
    iget-object v7, v7, Lx51/b;->d:La61/a;

    .line 212
    .line 213
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 214
    .line 215
    .line 216
    goto :goto_1

    .line 217
    :cond_2
    invoke-static {p1}, Lz81/l;->a(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 218
    .line 219
    .line 220
    move-result-object p1

    .line 221
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 222
    .line 223
    .line 224
    iget-object v6, v1, Lro/f;->e:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast v6, Lz81/f;

    .line 227
    .line 228
    sget-object v7, Lz81/f;->d:Lz81/f;

    .line 229
    .line 230
    invoke-virtual {v6, v7}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 231
    .line 232
    .line 233
    move-result v6

    .line 234
    if-lez v6, :cond_3

    .line 235
    .line 236
    sget-object v6, Lx51/c;->o1:Lx51/b;

    .line 237
    .line 238
    iget-object v7, v6, Lx51/b;->d:La61/a;

    .line 239
    .line 240
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 241
    .line 242
    .line 243
    iget-object v1, v1, Lro/f;->e:Ljava/lang/Object;

    .line 244
    .line 245
    check-cast v1, Lz81/f;

    .line 246
    .line 247
    sget-object v7, Lz81/f;->e:Lz81/f;

    .line 248
    .line 249
    invoke-virtual {v1, v7}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    if-lez v1, :cond_3

    .line 254
    .line 255
    iget-object v1, v6, Lx51/b;->d:La61/a;

    .line 256
    .line 257
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 258
    .line 259
    .line 260
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 261
    .line 262
    .line 263
    move-result-object p1

    .line 264
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 265
    .line 266
    .line 267
    move-result v1

    .line 268
    if-eqz v1, :cond_3

    .line 269
    .line 270
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v1

    .line 274
    check-cast v1, Ljava/lang/String;

    .line 275
    .line 276
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 277
    .line 278
    iget-object v1, v1, Lx51/b;->d:La61/a;

    .line 279
    .line 280
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 281
    .line 282
    .line 283
    goto :goto_2

    .line 284
    :cond_3
    new-instance p1, Lz81/i;

    .line 285
    .line 286
    const/4 v1, 0x0

    .line 287
    invoke-direct {p1, p0, v0, v4, v1}, Lz81/i;-><init>(Lz81/l;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

    .line 288
    .line 289
    .line 290
    invoke-static {v5, v4, v4, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 291
    .line 292
    .line 293
    return-object v2

    .line 294
    :cond_4
    invoke-static {p1}, Lz81/l;->a(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 295
    .line 296
    .line 297
    move-result-object p0

    .line 298
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 299
    .line 300
    .line 301
    iget-object p1, v1, Lro/f;->e:Ljava/lang/Object;

    .line 302
    .line 303
    check-cast p1, Lz81/f;

    .line 304
    .line 305
    sget-object v0, Lz81/f;->d:Lz81/f;

    .line 306
    .line 307
    invoke-virtual {p1, v0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 308
    .line 309
    .line 310
    move-result p1

    .line 311
    if-lez p1, :cond_5

    .line 312
    .line 313
    sget-object p1, Lx51/c;->o1:Lx51/b;

    .line 314
    .line 315
    iget-object v0, p1, Lx51/b;->d:La61/a;

    .line 316
    .line 317
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 318
    .line 319
    .line 320
    iget-object v0, v1, Lro/f;->e:Ljava/lang/Object;

    .line 321
    .line 322
    check-cast v0, Lz81/f;

    .line 323
    .line 324
    sget-object v1, Lz81/f;->e:Lz81/f;

    .line 325
    .line 326
    invoke-virtual {v0, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 327
    .line 328
    .line 329
    move-result v0

    .line 330
    if-lez v0, :cond_5

    .line 331
    .line 332
    iget-object p1, p1, Lx51/b;->d:La61/a;

    .line 333
    .line 334
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 335
    .line 336
    .line 337
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 338
    .line 339
    .line 340
    move-result-object p0

    .line 341
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 342
    .line 343
    .line 344
    move-result p1

    .line 345
    if-eqz p1, :cond_5

    .line 346
    .line 347
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object p1

    .line 351
    check-cast p1, Ljava/lang/String;

    .line 352
    .line 353
    sget-object p1, Lx51/c;->o1:Lx51/b;

    .line 354
    .line 355
    iget-object p1, p1, Lx51/b;->d:La61/a;

    .line 356
    .line 357
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 358
    .line 359
    .line 360
    goto :goto_3

    .line 361
    :cond_5
    return-object v2

    .line 362
    :cond_6
    invoke-static {p1}, Lz81/l;->a(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 363
    .line 364
    .line 365
    move-result-object p1

    .line 366
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 367
    .line 368
    .line 369
    iget-object v2, v1, Lro/f;->e:Ljava/lang/Object;

    .line 370
    .line 371
    check-cast v2, Lz81/f;

    .line 372
    .line 373
    sget-object v6, Lz81/f;->d:Lz81/f;

    .line 374
    .line 375
    invoke-virtual {v2, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 376
    .line 377
    .line 378
    move-result v2

    .line 379
    if-lez v2, :cond_7

    .line 380
    .line 381
    sget-object v2, Lx51/c;->o1:Lx51/b;

    .line 382
    .line 383
    iget-object v6, v2, Lx51/b;->d:La61/a;

    .line 384
    .line 385
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 386
    .line 387
    .line 388
    iget-object v1, v1, Lro/f;->e:Ljava/lang/Object;

    .line 389
    .line 390
    check-cast v1, Lz81/f;

    .line 391
    .line 392
    sget-object v6, Lz81/f;->e:Lz81/f;

    .line 393
    .line 394
    invoke-virtual {v1, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 395
    .line 396
    .line 397
    move-result v1

    .line 398
    if-lez v1, :cond_7

    .line 399
    .line 400
    iget-object v1, v2, Lx51/b;->d:La61/a;

    .line 401
    .line 402
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 403
    .line 404
    .line 405
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 406
    .line 407
    .line 408
    move-result-object p1

    .line 409
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 410
    .line 411
    .line 412
    move-result v1

    .line 413
    if-eqz v1, :cond_7

    .line 414
    .line 415
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object v1

    .line 419
    check-cast v1, Ljava/lang/String;

    .line 420
    .line 421
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 422
    .line 423
    iget-object v1, v1, Lx51/b;->d:La61/a;

    .line 424
    .line 425
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 426
    .line 427
    .line 428
    goto :goto_4

    .line 429
    :cond_7
    new-instance p1, Lz81/i;

    .line 430
    .line 431
    const/4 v1, 0x1

    .line 432
    invoke-direct {p1, p0, v0, v4, v1}, Lz81/i;-><init>(Lz81/l;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

    .line 433
    .line 434
    .line 435
    invoke-static {v5, v4, v4, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 436
    .line 437
    .line 438
    new-instance p0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 439
    .line 440
    invoke-direct {p0}, Lio/opentelemetry/sdk/common/CompletableResultCode;-><init>()V

    .line 441
    .line 442
    .line 443
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->fail()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 444
    .line 445
    .line 446
    move-result-object p0

    .line 447
    const-string p1, "fail(...)"

    .line 448
    .line 449
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 450
    .line 451
    .line 452
    return-object p0
.end method

.method public final flush()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 1

    .line 1
    iget-object p0, p0, Lz81/l;->e:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/logs/export/LogRecordExporter;->flush()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "flush(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 2

    .line 1
    iget-object v0, p0, Lz81/l;->m:Lvy0/x1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0, v1}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 7
    .line 8
    .line 9
    :cond_0
    iput-object v1, p0, Lz81/l;->m:Lvy0/x1;

    .line 10
    .line 11
    iget-object v0, p0, Lz81/l;->k:Lpx0/g;

    .line 12
    .line 13
    invoke-static {v0}, Lvy0/e0;->n(Lpx0/g;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lz81/l;->e:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 17
    .line 18
    invoke-interface {p0}, Lio/opentelemetry/sdk/logs/export/LogRecordExporter;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const-string v0, "shutdown(...)"

    .line 23
    .line 24
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    return-object p0
.end method
