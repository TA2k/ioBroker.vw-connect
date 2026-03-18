.class Lcom/salesforce/marketingcloud/analytics/stats/c$h;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/http/b;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/http/b;

.field final synthetic d:Lcom/salesforce/marketingcloud/analytics/stats/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/http/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->c:Lcom/salesforce/marketingcloud/http/b;

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 10

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->c:Lcom/salesforce/marketingcloud/http/b;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->s:Lcom/salesforce/marketingcloud/http/b;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eq v0, v1, :cond_0

    .line 7
    .line 8
    sget-object v3, Lcom/salesforce/marketingcloud/http/b;->r:Lcom/salesforce/marketingcloud/http/b;

    .line 9
    .line 10
    if-ne v0, v3, :cond_2

    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 13
    .line 14
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 15
    .line 16
    invoke-static {v0}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/storage/h;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_2

    .line 21
    .line 22
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 23
    .line 24
    new-array v2, v2, [Ljava/lang/Object;

    .line 25
    .line 26
    const-string v3, "No subscriber token found ignore sendStats request"

    .line 27
    .line 28
    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 32
    .line 33
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 34
    .line 35
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->c:Lcom/salesforce/marketingcloud/http/b;

    .line 36
    .line 37
    if-ne p0, v1, :cond_1

    .line 38
    .line 39
    sget-object p0, Lcom/salesforce/marketingcloud/alarms/a$a;->k:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    sget-object p0, Lcom/salesforce/marketingcloud/alarms/a$a;->j:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 43
    .line 44
    :goto_0
    filled-new-array {p0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->c:Lcom/salesforce/marketingcloud/http/b;

    .line 53
    .line 54
    sget-object v3, Lcom/salesforce/marketingcloud/http/b;->r:Lcom/salesforce/marketingcloud/http/b;

    .line 55
    .line 56
    if-ne v0, v3, :cond_3

    .line 57
    .line 58
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 59
    .line 60
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 61
    .line 62
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 67
    .line 68
    iget-object v4, v4, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 69
    .line 70
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    invoke-interface {v0, v4}, Lcom/salesforce/marketingcloud/storage/c;->j(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    goto :goto_1

    .line 79
    :cond_3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 80
    .line 81
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 82
    .line 83
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 88
    .line 89
    iget-object v4, v4, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 90
    .line 91
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    invoke-interface {v0, v4}, Lcom/salesforce/marketingcloud/storage/c;->n(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    :goto_1
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 100
    .line 101
    .line 102
    move-result v4

    .line 103
    if-nez v4, :cond_6

    .line 104
    .line 105
    sget-object v3, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 106
    .line 107
    new-array v4, v2, [Ljava/lang/Object;

    .line 108
    .line 109
    const-string v5, "Preparing payload for device statistics."

    .line 110
    .line 111
    invoke-static {v3, v5, v4}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    :try_start_0
    new-instance v3, Lorg/json/JSONObject;

    .line 115
    .line 116
    invoke-direct {v3}, Lorg/json/JSONObject;-><init>()V

    .line 117
    .line 118
    .line 119
    const-string v4, "applicationId"

    .line 120
    .line 121
    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 122
    .line 123
    iget-object v5, v5, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 124
    .line 125
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v5

    .line 129
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 130
    .line 131
    .line 132
    const-string v4, "deviceId"

    .line 133
    .line 134
    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 135
    .line 136
    iget-object v5, v5, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;

    .line 137
    .line 138
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 139
    .line 140
    .line 141
    new-instance v4, Lorg/json/JSONArray;

    .line 142
    .line 143
    invoke-direct {v4}, Lorg/json/JSONArray;-><init>()V

    .line 144
    .line 145
    .line 146
    new-instance v5, Lorg/json/JSONObject;

    .line 147
    .line 148
    invoke-direct {v5}, Lorg/json/JSONObject;-><init>()V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v4, v5}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;

    .line 152
    .line 153
    .line 154
    const-string v6, "nodes"

    .line 155
    .line 156
    invoke-virtual {v3, v6, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 157
    .line 158
    .line 159
    const-string v4, "version"

    .line 160
    .line 161
    const/4 v6, 0x1

    .line 162
    invoke-virtual {v5, v4, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 163
    .line 164
    .line 165
    const-string v4, "name"

    .line 166
    .line 167
    const-string v6, "event"

    .line 168
    .line 169
    invoke-virtual {v5, v4, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 170
    .line 171
    .line 172
    const/16 v4, 0x3e7

    .line 173
    .line 174
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 175
    .line 176
    .line 177
    move-result-object v4

    .line 178
    iget-object v6, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->c:Lcom/salesforce/marketingcloud/http/b;

    .line 179
    .line 180
    const/4 v7, 0x0

    .line 181
    if-ne v6, v1, :cond_5

    .line 182
    .line 183
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    if-eqz v1, :cond_4

    .line 188
    .line 189
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    iget-object v6, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 194
    .line 195
    iget-object v6, v6, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 196
    .line 197
    sget-object v8, Lcom/salesforce/marketingcloud/config/b$b;->b:Lcom/salesforce/marketingcloud/config/b$b;

    .line 198
    .line 199
    invoke-virtual {v8}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v8

    .line 203
    invoke-virtual {v1, v6, v8}, Lcom/salesforce/marketingcloud/config/a;->a(Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;)Lcom/salesforce/marketingcloud/config/b;

    .line 204
    .line 205
    .line 206
    move-result-object v1

    .line 207
    goto :goto_2

    .line 208
    :catch_0
    move-exception p0

    .line 209
    goto :goto_4

    .line 210
    :cond_4
    move-object v1, v7

    .line 211
    :goto_2
    if-eqz v1, :cond_5

    .line 212
    .line 213
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/config/b;->f()Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v7

    .line 217
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/config/b;->e()Ljava/lang/Integer;

    .line 218
    .line 219
    .line 220
    move-result-object v6

    .line 221
    if-eqz v6, :cond_5

    .line 222
    .line 223
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/config/b;->e()Ljava/lang/Integer;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 228
    .line 229
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 230
    .line 231
    .line 232
    move-result v4

    .line 233
    invoke-virtual {v1, v0, v4}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Ljava/util/List;I)Ljava/util/Map;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 246
    .line 247
    .line 248
    move-result v1

    .line 249
    if-eqz v1, :cond_8

    .line 250
    .line 251
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v1

    .line 255
    check-cast v1, Ljava/util/Map$Entry;

    .line 256
    .line 257
    const-string v4, "items"

    .line 258
    .line 259
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v6

    .line 263
    invoke-virtual {v5, v4, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 264
    .line 265
    .line 266
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->c:Lcom/salesforce/marketingcloud/http/b;

    .line 267
    .line 268
    iget-object v6, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 269
    .line 270
    iget-object v8, v6, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 271
    .line 272
    iget-object v6, v6, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 273
    .line 274
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 275
    .line 276
    .line 277
    move-result-object v6

    .line 278
    invoke-virtual {v3}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v9

    .line 282
    invoke-virtual {v4, v8, v6, v9, v7}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c;

    .line 283
    .line 284
    .line 285
    move-result-object v4

    .line 286
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v1

    .line 290
    check-cast v1, Ljava/lang/String;

    .line 291
    .line 292
    invoke-virtual {v4, v1}, Lcom/salesforce/marketingcloud/http/c;->a(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 296
    .line 297
    iget-object v1, v1, Lcom/salesforce/marketingcloud/analytics/stats/c;->h:Lcom/salesforce/marketingcloud/http/e;

    .line 298
    .line 299
    invoke-virtual {v1, v4}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/c;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 300
    .line 301
    .line 302
    goto :goto_3

    .line 303
    :goto_4
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 304
    .line 305
    new-array v1, v2, [Ljava/lang/Object;

    .line 306
    .line 307
    const-string v2, "Failed to start sync events request."

    .line 308
    .line 309
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    return-void

    .line 313
    :cond_6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->c:Lcom/salesforce/marketingcloud/http/b;

    .line 314
    .line 315
    if-ne v0, v3, :cond_7

    .line 316
    .line 317
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 318
    .line 319
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 320
    .line 321
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->j:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 322
    .line 323
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 324
    .line 325
    .line 326
    move-result-object v0

    .line 327
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 328
    .line 329
    .line 330
    return-void

    .line 331
    :cond_7
    if-ne v0, v1, :cond_8

    .line 332
    .line 333
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$h;->d:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 334
    .line 335
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 336
    .line 337
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->k:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 338
    .line 339
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 340
    .line 341
    .line 342
    move-result-object v0

    .line 343
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 344
    .line 345
    .line 346
    :cond_8
    return-void
.end method
