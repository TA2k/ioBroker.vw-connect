.class public final Lc91/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# instance fields
.field public final synthetic a:I

.field public final b:Lqz0/a;


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lc91/e;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    sget-object p1, Lc91/c;->Companion:Lc91/b;

    .line 10
    .line 11
    invoke-virtual {p1}, Lc91/b;->serializer()Lqz0/a;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Lc91/e;->b:Lqz0/a;

    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    sget-object p1, Lc91/g0;->Companion:Lc91/f0;

    .line 22
    .line 23
    invoke-virtual {p1}, Lc91/f0;->serializer()Lqz0/a;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Lc91/e;->b:Lqz0/a;

    .line 28
    .line 29
    return-void

    .line 30
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    sget-object p1, Lc91/d0;->Companion:Lc91/c0;

    .line 34
    .line 35
    invoke-virtual {p1}, Lc91/c0;->serializer()Lqz0/a;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iput-object p1, p0, Lc91/e;->b:Lqz0/a;

    .line 40
    .line 41
    return-void

    .line 42
    :pswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 43
    .line 44
    .line 45
    sget-object p1, Lc91/s;->Companion:Lc91/r;

    .line 46
    .line 47
    invoke-virtual {p1}, Lc91/r;->serializer()Lqz0/a;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    iput-object p1, p0, Lc91/e;->b:Lqz0/a;

    .line 52
    .line 53
    return-void

    .line 54
    :pswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 55
    .line 56
    .line 57
    sget-object p1, Lc91/p;->Companion:Lc91/o;

    .line 58
    .line 59
    invoke-virtual {p1}, Lc91/o;->serializer()Lqz0/a;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    iput-object p1, p0, Lc91/e;->b:Lqz0/a;

    .line 64
    .line 65
    return-void

    .line 66
    :pswitch_4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 67
    .line 68
    .line 69
    sget-object p1, Lc91/j;->Companion:Lc91/i;

    .line 70
    .line 71
    invoke-virtual {p1}, Lc91/i;->serializer()Lqz0/a;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    iput-object p1, p0, Lc91/e;->b:Lqz0/a;

    .line 76
    .line 77
    return-void

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lc91/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 7
    .line 8
    check-cast p0, Lqz0/a;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/c;->d(Lqz0/a;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc91/g0;

    .line 15
    .line 16
    new-instance p1, Lc91/h0;

    .line 17
    .line 18
    invoke-direct {p1, p0}, Lc91/h0;-><init>(Lc91/g0;)V

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 23
    .line 24
    check-cast p0, Lqz0/a;

    .line 25
    .line 26
    invoke-interface {p1, p0}, Ltz0/c;->d(Lqz0/a;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lc91/d0;

    .line 31
    .line 32
    invoke-static {}, Lio/opentelemetry/api/trace/TraceState;->builder()Lio/opentelemetry/api/trace/TraceStateBuilder;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iget-object v0, p0, Lc91/d0;->d:Ljava/util/Map;

    .line 37
    .line 38
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_0

    .line 51
    .line 52
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    check-cast v1, Ljava/util/Map$Entry;

    .line 57
    .line 58
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    check-cast v2, Ljava/lang/String;

    .line 63
    .line 64
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    check-cast v1, Ljava/lang/String;

    .line 69
    .line 70
    invoke-interface {p1, v2, v1}, Lio/opentelemetry/api/trace/TraceStateBuilder;->put(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/TraceStateBuilder;

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_0
    iget-object v0, p0, Lc91/d0;->a:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v1, p0, Lc91/d0;->b:Ljava/lang/String;

    .line 77
    .line 78
    iget-object p0, p0, Lc91/d0;->c:Ljava/lang/String;

    .line 79
    .line 80
    const/4 v2, 0x0

    .line 81
    invoke-static {p0, v2}, Lio/opentelemetry/api/trace/TraceFlags;->fromHex(Ljava/lang/CharSequence;I)Lio/opentelemetry/api/trace/TraceFlags;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-interface {p1}, Lio/opentelemetry/api/trace/TraceStateBuilder;->build()Lio/opentelemetry/api/trace/TraceState;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    invoke-static {v0, v1, p0, p1}, Lio/opentelemetry/api/trace/SpanContext;->create(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;)Lio/opentelemetry/api/trace/SpanContext;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    const-string p1, "create(...)"

    .line 94
    .line 95
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    return-object p0

    .line 99
    :pswitch_1
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 100
    .line 101
    check-cast p0, Lqz0/a;

    .line 102
    .line 103
    invoke-interface {p1, p0}, Ltz0/c;->d(Lqz0/a;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    check-cast p0, Lc91/s;

    .line 108
    .line 109
    new-instance p1, Lc91/t;

    .line 110
    .line 111
    invoke-direct {p1, p0}, Lc91/t;-><init>(Lc91/s;)V

    .line 112
    .line 113
    .line 114
    return-object p1

    .line 115
    :pswitch_2
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 116
    .line 117
    check-cast p0, Lqz0/a;

    .line 118
    .line 119
    invoke-interface {p1, p0}, Ltz0/c;->d(Lqz0/a;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    check-cast p0, Lc91/p;

    .line 124
    .line 125
    iget-object p1, p0, Lc91/p;->a:Lio/opentelemetry/api/trace/SpanContext;

    .line 126
    .line 127
    iget-object v0, p0, Lc91/p;->b:Lio/opentelemetry/api/common/Attributes;

    .line 128
    .line 129
    iget p0, p0, Lc91/p;->c:I

    .line 130
    .line 131
    invoke-static {p1, v0, p0}, Lio/opentelemetry/sdk/trace/data/LinkData;->create(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/LinkData;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    const-string p1, "create(...)"

    .line 136
    .line 137
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    return-object p0

    .line 141
    :pswitch_3
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 142
    .line 143
    check-cast p0, Lqz0/a;

    .line 144
    .line 145
    invoke-interface {p1, p0}, Ltz0/c;->d(Lqz0/a;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    check-cast p0, Lc91/j;

    .line 150
    .line 151
    iget-wide v0, p0, Lc91/j;->a:J

    .line 152
    .line 153
    iget-object p1, p0, Lc91/j;->b:Ljava/lang/String;

    .line 154
    .line 155
    iget-object v2, p0, Lc91/j;->c:Lio/opentelemetry/api/common/Attributes;

    .line 156
    .line 157
    iget p0, p0, Lc91/j;->d:I

    .line 158
    .line 159
    invoke-static {v0, v1, p1, v2, p0}, Lio/opentelemetry/sdk/trace/data/EventData;->create(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/EventData;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    const-string p1, "create(...)"

    .line 164
    .line 165
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    return-object p0

    .line 169
    :pswitch_4
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 170
    .line 171
    check-cast p0, Lqz0/a;

    .line 172
    .line 173
    invoke-interface {p1, p0}, Ltz0/c;->d(Lqz0/a;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    check-cast p0, Lc91/c;

    .line 178
    .line 179
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 180
    .line 181
    .line 182
    move-result-object p1

    .line 183
    iget-object v0, p0, Lc91/c;->a:Ljava/util/Map;

    .line 184
    .line 185
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 194
    .line 195
    .line 196
    move-result v1

    .line 197
    if-eqz v1, :cond_1

    .line 198
    .line 199
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v1

    .line 203
    check-cast v1, Ljava/util/Map$Entry;

    .line 204
    .line 205
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v2

    .line 209
    check-cast v2, Ljava/lang/String;

    .line 210
    .line 211
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    check-cast v1, Ljava/lang/String;

    .line 216
    .line 217
    invoke-static {v2}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 218
    .line 219
    .line 220
    move-result-object v2

    .line 221
    invoke-interface {p1, v2, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 222
    .line 223
    .line 224
    goto :goto_1

    .line 225
    :cond_1
    iget-object v0, p0, Lc91/c;->b:Ljava/util/Map;

    .line 226
    .line 227
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 232
    .line 233
    .line 234
    move-result-object v0

    .line 235
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 236
    .line 237
    .line 238
    move-result v1

    .line 239
    if-eqz v1, :cond_2

    .line 240
    .line 241
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    check-cast v1, Ljava/util/Map$Entry;

    .line 246
    .line 247
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v2

    .line 251
    check-cast v2, Ljava/lang/String;

    .line 252
    .line 253
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v1

    .line 257
    check-cast v1, Ljava/lang/Boolean;

    .line 258
    .line 259
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 260
    .line 261
    .line 262
    invoke-static {v2}, Lio/opentelemetry/api/common/AttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    invoke-interface {p1, v2, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 267
    .line 268
    .line 269
    goto :goto_2

    .line 270
    :cond_2
    iget-object v0, p0, Lc91/c;->c:Ljava/util/Map;

    .line 271
    .line 272
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 277
    .line 278
    .line 279
    move-result-object v0

    .line 280
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 281
    .line 282
    .line 283
    move-result v1

    .line 284
    if-eqz v1, :cond_3

    .line 285
    .line 286
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v1

    .line 290
    check-cast v1, Ljava/util/Map$Entry;

    .line 291
    .line 292
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v2

    .line 296
    check-cast v2, Ljava/lang/String;

    .line 297
    .line 298
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v1

    .line 302
    check-cast v1, Ljava/lang/Number;

    .line 303
    .line 304
    invoke-virtual {v1}, Ljava/lang/Number;->longValue()J

    .line 305
    .line 306
    .line 307
    move-result-wide v3

    .line 308
    invoke-static {v2}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 309
    .line 310
    .line 311
    move-result-object v1

    .line 312
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 313
    .line 314
    .line 315
    move-result-object v2

    .line 316
    invoke-interface {p1, v1, v2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 317
    .line 318
    .line 319
    goto :goto_3

    .line 320
    :cond_3
    iget-object v0, p0, Lc91/c;->d:Ljava/util/Map;

    .line 321
    .line 322
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 323
    .line 324
    .line 325
    move-result-object v0

    .line 326
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 327
    .line 328
    .line 329
    move-result-object v0

    .line 330
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 331
    .line 332
    .line 333
    move-result v1

    .line 334
    if-eqz v1, :cond_4

    .line 335
    .line 336
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v1

    .line 340
    check-cast v1, Ljava/util/Map$Entry;

    .line 341
    .line 342
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v2

    .line 346
    check-cast v2, Ljava/lang/String;

    .line 347
    .line 348
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v1

    .line 352
    check-cast v1, Ljava/lang/Number;

    .line 353
    .line 354
    invoke-virtual {v1}, Ljava/lang/Number;->doubleValue()D

    .line 355
    .line 356
    .line 357
    move-result-wide v3

    .line 358
    invoke-static {v2}, Lio/opentelemetry/api/common/AttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 359
    .line 360
    .line 361
    move-result-object v1

    .line 362
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 363
    .line 364
    .line 365
    move-result-object v2

    .line 366
    invoke-interface {p1, v1, v2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 367
    .line 368
    .line 369
    goto :goto_4

    .line 370
    :cond_4
    iget-object v0, p0, Lc91/c;->e:Ljava/util/Map;

    .line 371
    .line 372
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 373
    .line 374
    .line 375
    move-result-object v0

    .line 376
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 381
    .line 382
    .line 383
    move-result v1

    .line 384
    if-eqz v1, :cond_5

    .line 385
    .line 386
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v1

    .line 390
    check-cast v1, Ljava/util/Map$Entry;

    .line 391
    .line 392
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    move-result-object v2

    .line 396
    check-cast v2, Ljava/lang/String;

    .line 397
    .line 398
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 399
    .line 400
    .line 401
    move-result-object v1

    .line 402
    check-cast v1, Ljava/util/List;

    .line 403
    .line 404
    invoke-static {v2}, Lio/opentelemetry/api/common/AttributeKey;->stringArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 405
    .line 406
    .line 407
    move-result-object v2

    .line 408
    invoke-interface {p1, v2, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 409
    .line 410
    .line 411
    goto :goto_5

    .line 412
    :cond_5
    iget-object v0, p0, Lc91/c;->f:Ljava/util/Map;

    .line 413
    .line 414
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 415
    .line 416
    .line 417
    move-result-object v0

    .line 418
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 419
    .line 420
    .line 421
    move-result-object v0

    .line 422
    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 423
    .line 424
    .line 425
    move-result v1

    .line 426
    if-eqz v1, :cond_6

    .line 427
    .line 428
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v1

    .line 432
    check-cast v1, Ljava/util/Map$Entry;

    .line 433
    .line 434
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    move-result-object v2

    .line 438
    check-cast v2, Ljava/lang/String;

    .line 439
    .line 440
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 441
    .line 442
    .line 443
    move-result-object v1

    .line 444
    check-cast v1, Ljava/util/List;

    .line 445
    .line 446
    invoke-static {v2}, Lio/opentelemetry/api/common/AttributeKey;->booleanArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 447
    .line 448
    .line 449
    move-result-object v2

    .line 450
    invoke-interface {p1, v2, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 451
    .line 452
    .line 453
    goto :goto_6

    .line 454
    :cond_6
    iget-object v0, p0, Lc91/c;->g:Ljava/util/Map;

    .line 455
    .line 456
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 457
    .line 458
    .line 459
    move-result-object v0

    .line 460
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 461
    .line 462
    .line 463
    move-result-object v0

    .line 464
    :goto_7
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 465
    .line 466
    .line 467
    move-result v1

    .line 468
    if-eqz v1, :cond_7

    .line 469
    .line 470
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 471
    .line 472
    .line 473
    move-result-object v1

    .line 474
    check-cast v1, Ljava/util/Map$Entry;

    .line 475
    .line 476
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 477
    .line 478
    .line 479
    move-result-object v2

    .line 480
    check-cast v2, Ljava/lang/String;

    .line 481
    .line 482
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 483
    .line 484
    .line 485
    move-result-object v1

    .line 486
    check-cast v1, Ljava/util/List;

    .line 487
    .line 488
    invoke-static {v2}, Lio/opentelemetry/api/common/AttributeKey;->longArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 489
    .line 490
    .line 491
    move-result-object v2

    .line 492
    invoke-interface {p1, v2, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 493
    .line 494
    .line 495
    goto :goto_7

    .line 496
    :cond_7
    iget-object p0, p0, Lc91/c;->h:Ljava/util/Map;

    .line 497
    .line 498
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 499
    .line 500
    .line 501
    move-result-object p0

    .line 502
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 503
    .line 504
    .line 505
    move-result-object p0

    .line 506
    :goto_8
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 507
    .line 508
    .line 509
    move-result v0

    .line 510
    if-eqz v0, :cond_8

    .line 511
    .line 512
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    move-result-object v0

    .line 516
    check-cast v0, Ljava/util/Map$Entry;

    .line 517
    .line 518
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object v1

    .line 522
    check-cast v1, Ljava/lang/String;

    .line 523
    .line 524
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 525
    .line 526
    .line 527
    move-result-object v0

    .line 528
    check-cast v0, Ljava/util/List;

    .line 529
    .line 530
    invoke-static {v1}, Lio/opentelemetry/api/common/AttributeKey;->doubleArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 531
    .line 532
    .line 533
    move-result-object v1

    .line 534
    invoke-interface {p1, v1, v0}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 535
    .line 536
    .line 537
    goto :goto_8

    .line 538
    :cond_8
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 539
    .line 540
    .line 541
    move-result-object p0

    .line 542
    const-string p1, "build(...)"

    .line 543
    .line 544
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 545
    .line 546
    .line 547
    return-object p0

    .line 548
    nop

    .line 549
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 1

    .line 1
    iget v0, p0, Lc91/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 7
    .line 8
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v0, "io.opentelemetry.sdk.trace.data.SpanData"

    .line 13
    .line 14
    invoke-static {v0, p0}, Lkp/x8;->b(Ljava/lang/String;Lsz0/g;)Lsz0/m;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 20
    .line 21
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string v0, "io.opentelemetry.api.trace.SpanContext"

    .line 26
    .line 27
    invoke-static {v0, p0}, Lkp/x8;->b(Ljava/lang/String;Lsz0/g;)Lsz0/m;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_1
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 33
    .line 34
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    const-string v0, "io.opentelemetry.sdk.logs.data.LogRecordData"

    .line 39
    .line 40
    invoke-static {v0, p0}, Lkp/x8;->b(Ljava/lang/String;Lsz0/g;)Lsz0/m;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :pswitch_2
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 46
    .line 47
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string v0, "io.opentelemetry.sdk.trace.data.LinkData"

    .line 52
    .line 53
    invoke-static {v0, p0}, Lkp/x8;->b(Ljava/lang/String;Lsz0/g;)Lsz0/m;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :pswitch_3
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 59
    .line 60
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    const-string v0, "io.opentelemetry.sdk.trace.data.EventData"

    .line 65
    .line 66
    invoke-static {v0, p0}, Lkp/x8;->b(Ljava/lang/String;Lsz0/g;)Lsz0/m;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :pswitch_4
    iget-object p0, p0, Lc91/e;->b:Lqz0/a;

    .line 72
    .line 73
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    const-string v0, "io.opentelemetry.api.common.Attributes"

    .line 78
    .line 79
    invoke-static {v0, p0}, Lkp/x8;->b(Ljava/lang/String;Lsz0/g;)Lsz0/m;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Lc91/e;->a:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v2, p2

    .line 11
    .line 12
    check-cast v2, Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 13
    .line 14
    const-string v3, "value"

    .line 15
    .line 16
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, v0, Lc91/e;->b:Lqz0/a;

    .line 20
    .line 21
    check-cast v0, Lqz0/a;

    .line 22
    .line 23
    new-instance v3, Lc91/g0;

    .line 24
    .line 25
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getName()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    const-string v5, "getName(...)"

    .line 30
    .line 31
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getKind()Lio/opentelemetry/api/trace/SpanKind;

    .line 35
    .line 36
    .line 37
    move-result-object v6

    .line 38
    const-string v7, "getKind(...)"

    .line 39
    .line 40
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    move-object v7, v6

    .line 44
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    const-string v8, "getSpanContext(...)"

    .line 49
    .line 50
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    move-object v8, v7

    .line 54
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 55
    .line 56
    .line 57
    move-result-object v7

    .line 58
    const-string v9, "getParentSpanContext(...)"

    .line 59
    .line 60
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 64
    .line 65
    .line 66
    move-result-object v9

    .line 67
    invoke-interface {v9}, Lio/opentelemetry/sdk/trace/data/StatusData;->getDescription()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v9

    .line 71
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 72
    .line 73
    .line 74
    move-result-object v10

    .line 75
    invoke-interface {v10}, Lio/opentelemetry/sdk/trace/data/StatusData;->getStatusCode()Lio/opentelemetry/api/trace/StatusCode;

    .line 76
    .line 77
    .line 78
    move-result-object v10

    .line 79
    const-string v11, "getStatusCode(...)"

    .line 80
    .line 81
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    move-object v12, v8

    .line 85
    move-object v8, v9

    .line 86
    move-object v9, v10

    .line 87
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStartEpochNanos()J

    .line 88
    .line 89
    .line 90
    move-result-wide v10

    .line 91
    move-object v13, v12

    .line 92
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 93
    .line 94
    .line 95
    move-result-object v12

    .line 96
    const-string v14, "getAttributes(...)"

    .line 97
    .line 98
    invoke-static {v12, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    move-object v15, v13

    .line 102
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEvents()Ljava/util/List;

    .line 103
    .line 104
    .line 105
    move-result-object v13

    .line 106
    move-object/from16 p2, v2

    .line 107
    .line 108
    const-string v2, "getEvents(...)"

    .line 109
    .line 110
    invoke-static {v13, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getLinks()Ljava/util/List;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    move-object/from16 p0, v3

    .line 118
    .line 119
    const-string v3, "getLinks(...)"

    .line 120
    .line 121
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    move-object v3, v15

    .line 125
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEndEpochNanos()J

    .line 126
    .line 127
    .line 128
    move-result-wide v15

    .line 129
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->hasEnded()Z

    .line 130
    .line 131
    .line 132
    move-result v17

    .line 133
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedEvents()I

    .line 134
    .line 135
    .line 136
    move-result v18

    .line 137
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedLinks()I

    .line 138
    .line 139
    .line 140
    move-result v19

    .line 141
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalAttributeCount()I

    .line 142
    .line 143
    .line 144
    move-result v20

    .line 145
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 146
    .line 147
    .line 148
    move-result-object v21

    .line 149
    move-object/from16 v22, v2

    .line 150
    .line 151
    invoke-virtual/range {v21 .. v21}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getName()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v2

    .line 155
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 159
    .line 160
    .line 161
    move-result-object v5

    .line 162
    invoke-virtual {v5}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getVersion()Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v5

    .line 166
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 167
    .line 168
    .line 169
    move-result-object v21

    .line 170
    invoke-virtual/range {v21 .. v21}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getSchemaUrl()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v23

    .line 174
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 175
    .line 176
    .line 177
    move-result-object v21

    .line 178
    move-object/from16 v24, v2

    .line 179
    .line 180
    invoke-virtual/range {v21 .. v21}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 188
    .line 189
    .line 190
    move-result-object v21

    .line 191
    move-object/from16 v25, v2

    .line 192
    .line 193
    invoke-virtual/range {v21 .. v21}, Lio/opentelemetry/sdk/resources/Resource;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 201
    .line 202
    .line 203
    move-result-object v14

    .line 204
    invoke-virtual {v14}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v26

    .line 208
    move-object/from16 v14, v22

    .line 209
    .line 210
    move-object/from16 v21, v24

    .line 211
    .line 212
    move-object/from16 v24, v25

    .line 213
    .line 214
    move-object/from16 v25, v2

    .line 215
    .line 216
    move-object/from16 v22, v5

    .line 217
    .line 218
    move-object v5, v3

    .line 219
    move-object/from16 v3, p0

    .line 220
    .line 221
    invoke-direct/range {v3 .. v26}, Lc91/g0;-><init>(Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/trace/SpanContext;Ljava/lang/String;Lio/opentelemetry/api/trace/StatusCode;JLio/opentelemetry/api/common/Attributes;Ljava/util/List;Ljava/util/List;JZIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    invoke-interface {v1, v0, v3}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    return-void

    .line 228
    :pswitch_0
    move-object/from16 v2, p2

    .line 229
    .line 230
    check-cast v2, Lio/opentelemetry/api/trace/SpanContext;

    .line 231
    .line 232
    const-string v3, "value"

    .line 233
    .line 234
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    iget-object v0, v0, Lc91/e;->b:Lqz0/a;

    .line 238
    .line 239
    check-cast v0, Lqz0/a;

    .line 240
    .line 241
    new-instance v3, Lc91/d0;

    .line 242
    .line 243
    invoke-interface {v2}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object v4

    .line 247
    const-string v5, "getTraceId(...)"

    .line 248
    .line 249
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    invoke-interface {v2}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v5

    .line 256
    const-string v6, "getSpanId(...)"

    .line 257
    .line 258
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    invoke-interface {v2}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    .line 262
    .line 263
    .line 264
    move-result-object v6

    .line 265
    invoke-interface {v6}, Lio/opentelemetry/api/trace/TraceFlags;->asHex()Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v6

    .line 269
    const-string v7, "asHex(...)"

    .line 270
    .line 271
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    invoke-interface {v2}, Lio/opentelemetry/api/trace/SpanContext;->getTraceState()Lio/opentelemetry/api/trace/TraceState;

    .line 275
    .line 276
    .line 277
    move-result-object v2

    .line 278
    invoke-interface {v2}, Lio/opentelemetry/api/trace/TraceState;->asMap()Ljava/util/Map;

    .line 279
    .line 280
    .line 281
    move-result-object v2

    .line 282
    const-string v7, "asMap(...)"

    .line 283
    .line 284
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    invoke-direct {v3, v4, v5, v6, v2}, Lc91/d0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;)V

    .line 288
    .line 289
    .line 290
    invoke-interface {v1, v0, v3}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    return-void

    .line 294
    :pswitch_1
    move-object/from16 v2, p2

    .line 295
    .line 296
    check-cast v2, Lio/opentelemetry/sdk/logs/data/LogRecordData;

    .line 297
    .line 298
    const-string v3, "value"

    .line 299
    .line 300
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    iget-object v0, v0, Lc91/e;->b:Lqz0/a;

    .line 304
    .line 305
    check-cast v0, Lqz0/a;

    .line 306
    .line 307
    new-instance v3, Lc91/s;

    .line 308
    .line 309
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 310
    .line 311
    .line 312
    move-result-object v4

    .line 313
    const-string v5, "getSpanContext(...)"

    .line 314
    .line 315
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverity()Lio/opentelemetry/api/logs/Severity;

    .line 319
    .line 320
    .line 321
    move-result-object v5

    .line 322
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverityText()Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object v6

    .line 326
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getBody()Lio/opentelemetry/sdk/logs/data/Body;

    .line 327
    .line 328
    .line 329
    move-result-object v7

    .line 330
    const-string v8, "getBody(...)"

    .line 331
    .line 332
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 336
    .line 337
    .line 338
    move-result-object v8

    .line 339
    const-string v9, "getAttributes(...)"

    .line 340
    .line 341
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTotalAttributeCount()I

    .line 345
    .line 346
    .line 347
    move-result v10

    .line 348
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 349
    .line 350
    .line 351
    move-result-object v11

    .line 352
    invoke-virtual {v11}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getName()Ljava/lang/String;

    .line 353
    .line 354
    .line 355
    move-result-object v11

    .line 356
    const-string v12, "getName(...)"

    .line 357
    .line 358
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 362
    .line 363
    .line 364
    move-result-object v12

    .line 365
    invoke-virtual {v12}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getVersion()Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v12

    .line 369
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 370
    .line 371
    .line 372
    move-result-object v13

    .line 373
    invoke-virtual {v13}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getSchemaUrl()Ljava/lang/String;

    .line 374
    .line 375
    .line 376
    move-result-object v13

    .line 377
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 378
    .line 379
    .line 380
    move-result-object v14

    .line 381
    invoke-virtual {v14}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 382
    .line 383
    .line 384
    move-result-object v14

    .line 385
    invoke-static {v14, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    move/from16 v16, v10

    .line 389
    .line 390
    move-object v10, v11

    .line 391
    move-object v11, v12

    .line 392
    move-object v12, v13

    .line 393
    move-object v13, v14

    .line 394
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTimestampEpochNanos()J

    .line 395
    .line 396
    .line 397
    move-result-wide v14

    .line 398
    move/from16 v18, v16

    .line 399
    .line 400
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getObservedTimestampEpochNanos()J

    .line 401
    .line 402
    .line 403
    move-result-wide v16

    .line 404
    invoke-interface {v2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 405
    .line 406
    .line 407
    move-result-object v19

    .line 408
    move-object/from16 p2, v2

    .line 409
    .line 410
    invoke-virtual/range {v19 .. v19}, Lio/opentelemetry/sdk/resources/Resource;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 411
    .line 412
    .line 413
    move-result-object v2

    .line 414
    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    invoke-interface/range {p2 .. p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 418
    .line 419
    .line 420
    move-result-object v9

    .line 421
    invoke-virtual {v9}, Lio/opentelemetry/sdk/resources/Resource;->getSchemaUrl()Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    move-result-object v19

    .line 425
    move/from16 v9, v18

    .line 426
    .line 427
    move-object/from16 v18, v2

    .line 428
    .line 429
    invoke-direct/range {v3 .. v19}, Lc91/s;-><init>(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/sdk/logs/data/Body;Lio/opentelemetry/api/common/Attributes;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JJLio/opentelemetry/api/common/Attributes;Ljava/lang/String;)V

    .line 430
    .line 431
    .line 432
    invoke-interface {v1, v0, v3}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 433
    .line 434
    .line 435
    return-void

    .line 436
    :pswitch_2
    move-object/from16 v2, p2

    .line 437
    .line 438
    check-cast v2, Lio/opentelemetry/sdk/trace/data/LinkData;

    .line 439
    .line 440
    const-string v3, "value"

    .line 441
    .line 442
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 443
    .line 444
    .line 445
    iget-object v0, v0, Lc91/e;->b:Lqz0/a;

    .line 446
    .line 447
    check-cast v0, Lqz0/a;

    .line 448
    .line 449
    new-instance v3, Lc91/p;

    .line 450
    .line 451
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 452
    .line 453
    .line 454
    move-result-object v4

    .line 455
    const-string v5, "getSpanContext(...)"

    .line 456
    .line 457
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 458
    .line 459
    .line 460
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 461
    .line 462
    .line 463
    move-result-object v5

    .line 464
    const-string v6, "getAttributes(...)"

    .line 465
    .line 466
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 467
    .line 468
    .line 469
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getTotalAttributeCount()I

    .line 470
    .line 471
    .line 472
    move-result v2

    .line 473
    invoke-direct {v3, v4, v5, v2}, Lc91/p;-><init>(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;I)V

    .line 474
    .line 475
    .line 476
    invoke-interface {v1, v0, v3}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 477
    .line 478
    .line 479
    return-void

    .line 480
    :pswitch_3
    move-object/from16 v2, p2

    .line 481
    .line 482
    check-cast v2, Lio/opentelemetry/sdk/trace/data/EventData;

    .line 483
    .line 484
    const-string v3, "value"

    .line 485
    .line 486
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 487
    .line 488
    .line 489
    iget-object v0, v0, Lc91/e;->b:Lqz0/a;

    .line 490
    .line 491
    check-cast v0, Lqz0/a;

    .line 492
    .line 493
    new-instance v3, Lc91/j;

    .line 494
    .line 495
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/EventData;->getEpochNanos()J

    .line 496
    .line 497
    .line 498
    move-result-wide v4

    .line 499
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/EventData;->getName()Ljava/lang/String;

    .line 500
    .line 501
    .line 502
    move-result-object v6

    .line 503
    const-string v7, "getName(...)"

    .line 504
    .line 505
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 506
    .line 507
    .line 508
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/EventData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 509
    .line 510
    .line 511
    move-result-object v7

    .line 512
    const-string v8, "getAttributes(...)"

    .line 513
    .line 514
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 515
    .line 516
    .line 517
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/data/EventData;->getTotalAttributeCount()I

    .line 518
    .line 519
    .line 520
    move-result v8

    .line 521
    invoke-direct/range {v3 .. v8}, Lc91/j;-><init>(JLjava/lang/String;Lio/opentelemetry/api/common/Attributes;I)V

    .line 522
    .line 523
    .line 524
    invoke-interface {v1, v0, v3}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 525
    .line 526
    .line 527
    return-void

    .line 528
    :pswitch_4
    move-object/from16 v2, p2

    .line 529
    .line 530
    check-cast v2, Lio/opentelemetry/api/common/Attributes;

    .line 531
    .line 532
    const-string v3, "value"

    .line 533
    .line 534
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 535
    .line 536
    .line 537
    iget-object v0, v0, Lc91/e;->b:Lqz0/a;

    .line 538
    .line 539
    check-cast v0, Lqz0/a;

    .line 540
    .line 541
    new-instance v3, Lc91/c;

    .line 542
    .line 543
    new-instance v4, Ljava/util/LinkedHashMap;

    .line 544
    .line 545
    invoke-direct {v4}, Ljava/util/LinkedHashMap;-><init>()V

    .line 546
    .line 547
    .line 548
    new-instance v5, Ljava/util/LinkedHashMap;

    .line 549
    .line 550
    invoke-direct {v5}, Ljava/util/LinkedHashMap;-><init>()V

    .line 551
    .line 552
    .line 553
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 554
    .line 555
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 556
    .line 557
    .line 558
    new-instance v7, Ljava/util/LinkedHashMap;

    .line 559
    .line 560
    invoke-direct {v7}, Ljava/util/LinkedHashMap;-><init>()V

    .line 561
    .line 562
    .line 563
    new-instance v8, Ljava/util/LinkedHashMap;

    .line 564
    .line 565
    invoke-direct {v8}, Ljava/util/LinkedHashMap;-><init>()V

    .line 566
    .line 567
    .line 568
    new-instance v9, Ljava/util/LinkedHashMap;

    .line 569
    .line 570
    invoke-direct {v9}, Ljava/util/LinkedHashMap;-><init>()V

    .line 571
    .line 572
    .line 573
    new-instance v10, Ljava/util/LinkedHashMap;

    .line 574
    .line 575
    invoke-direct {v10}, Ljava/util/LinkedHashMap;-><init>()V

    .line 576
    .line 577
    .line 578
    new-instance v11, Ljava/util/LinkedHashMap;

    .line 579
    .line 580
    invoke-direct {v11}, Ljava/util/LinkedHashMap;-><init>()V

    .line 581
    .line 582
    .line 583
    invoke-direct/range {v3 .. v11}, Lc91/c;-><init>(Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;)V

    .line 584
    .line 585
    .line 586
    invoke-interface {v2}, Lio/opentelemetry/api/common/Attributes;->asMap()Ljava/util/Map;

    .line 587
    .line 588
    .line 589
    move-result-object v2

    .line 590
    const-string v4, "asMap(...)"

    .line 591
    .line 592
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    invoke-interface {v2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 596
    .line 597
    .line 598
    move-result-object v2

    .line 599
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 600
    .line 601
    .line 602
    move-result-object v2

    .line 603
    :goto_0
    :pswitch_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 604
    .line 605
    .line 606
    move-result v4

    .line 607
    if-eqz v4, :cond_1

    .line 608
    .line 609
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 610
    .line 611
    .line 612
    move-result-object v4

    .line 613
    check-cast v4, Ljava/util/Map$Entry;

    .line 614
    .line 615
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 616
    .line 617
    .line 618
    move-result-object v5

    .line 619
    check-cast v5, Lio/opentelemetry/api/common/AttributeKey;

    .line 620
    .line 621
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 622
    .line 623
    .line 624
    move-result-object v4

    .line 625
    invoke-interface {v5}, Lio/opentelemetry/api/common/AttributeKey;->getType()Lio/opentelemetry/api/common/AttributeType;

    .line 626
    .line 627
    .line 628
    move-result-object v6

    .line 629
    if-nez v6, :cond_0

    .line 630
    .line 631
    const/4 v6, -0x1

    .line 632
    goto :goto_1

    .line 633
    :cond_0
    sget-object v7, Lc91/d;->a:[I

    .line 634
    .line 635
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 636
    .line 637
    .line 638
    move-result v6

    .line 639
    aget v6, v7, v6

    .line 640
    .line 641
    :goto_1
    packed-switch v6, :pswitch_data_1

    .line 642
    .line 643
    .line 644
    :pswitch_6
    new-instance v0, La8/r0;

    .line 645
    .line 646
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 647
    .line 648
    .line 649
    throw v0

    .line 650
    :pswitch_7
    invoke-interface {v5}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 651
    .line 652
    .line 653
    move-result-object v5

    .line 654
    const-string v6, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Double>"

    .line 655
    .line 656
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 657
    .line 658
    .line 659
    check-cast v4, Ljava/util/List;

    .line 660
    .line 661
    iget-object v6, v3, Lc91/c;->h:Ljava/util/Map;

    .line 662
    .line 663
    invoke-interface {v6, v5, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 664
    .line 665
    .line 666
    goto :goto_0

    .line 667
    :pswitch_8
    invoke-interface {v5}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 668
    .line 669
    .line 670
    move-result-object v5

    .line 671
    const-string v6, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Long>"

    .line 672
    .line 673
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 674
    .line 675
    .line 676
    check-cast v4, Ljava/util/List;

    .line 677
    .line 678
    iget-object v6, v3, Lc91/c;->g:Ljava/util/Map;

    .line 679
    .line 680
    invoke-interface {v6, v5, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 681
    .line 682
    .line 683
    goto :goto_0

    .line 684
    :pswitch_9
    invoke-interface {v5}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 685
    .line 686
    .line 687
    move-result-object v5

    .line 688
    const-string v6, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Boolean>"

    .line 689
    .line 690
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 691
    .line 692
    .line 693
    check-cast v4, Ljava/util/List;

    .line 694
    .line 695
    iget-object v6, v3, Lc91/c;->f:Ljava/util/Map;

    .line 696
    .line 697
    invoke-interface {v6, v5, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 698
    .line 699
    .line 700
    goto :goto_0

    .line 701
    :pswitch_a
    invoke-interface {v5}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 702
    .line 703
    .line 704
    move-result-object v5

    .line 705
    const-string v6, "null cannot be cast to non-null type kotlin.collections.List<kotlin.String>"

    .line 706
    .line 707
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 708
    .line 709
    .line 710
    check-cast v4, Ljava/util/List;

    .line 711
    .line 712
    iget-object v6, v3, Lc91/c;->e:Ljava/util/Map;

    .line 713
    .line 714
    invoke-interface {v6, v5, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 715
    .line 716
    .line 717
    goto :goto_0

    .line 718
    :pswitch_b
    invoke-interface {v5}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 719
    .line 720
    .line 721
    move-result-object v5

    .line 722
    const-string v6, "null cannot be cast to non-null type kotlin.Double"

    .line 723
    .line 724
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 725
    .line 726
    .line 727
    check-cast v4, Ljava/lang/Double;

    .line 728
    .line 729
    iget-object v6, v3, Lc91/c;->d:Ljava/util/Map;

    .line 730
    .line 731
    invoke-interface {v6, v5, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 732
    .line 733
    .line 734
    goto/16 :goto_0

    .line 735
    .line 736
    :pswitch_c
    invoke-interface {v5}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 737
    .line 738
    .line 739
    move-result-object v5

    .line 740
    const-string v6, "null cannot be cast to non-null type kotlin.Long"

    .line 741
    .line 742
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 743
    .line 744
    .line 745
    check-cast v4, Ljava/lang/Long;

    .line 746
    .line 747
    iget-object v6, v3, Lc91/c;->c:Ljava/util/Map;

    .line 748
    .line 749
    invoke-interface {v6, v5, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 750
    .line 751
    .line 752
    goto/16 :goto_0

    .line 753
    .line 754
    :pswitch_d
    invoke-interface {v5}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 755
    .line 756
    .line 757
    move-result-object v5

    .line 758
    const-string v6, "null cannot be cast to non-null type kotlin.Boolean"

    .line 759
    .line 760
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 761
    .line 762
    .line 763
    check-cast v4, Ljava/lang/Boolean;

    .line 764
    .line 765
    iget-object v6, v3, Lc91/c;->b:Ljava/util/Map;

    .line 766
    .line 767
    invoke-interface {v6, v5, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 768
    .line 769
    .line 770
    goto/16 :goto_0

    .line 771
    .line 772
    :pswitch_e
    invoke-interface {v5}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 773
    .line 774
    .line 775
    move-result-object v5

    .line 776
    const-string v6, "null cannot be cast to non-null type kotlin.String"

    .line 777
    .line 778
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 779
    .line 780
    .line 781
    check-cast v4, Ljava/lang/String;

    .line 782
    .line 783
    iget-object v6, v3, Lc91/c;->a:Ljava/util/Map;

    .line 784
    .line 785
    invoke-interface {v6, v5, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    goto/16 :goto_0

    .line 789
    .line 790
    :cond_1
    invoke-interface {v1, v0, v3}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 791
    .line 792
    .line 793
    return-void

    .line 794
    nop

    .line 795
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 796
    .line 797
    .line 798
    .line 799
    .line 800
    .line 801
    .line 802
    .line 803
    .line 804
    .line 805
    .line 806
    .line 807
    .line 808
    .line 809
    :pswitch_data_1
    .packed-switch -0x1
        :pswitch_5
        :pswitch_6
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
    .end packed-switch
.end method
