.class Lcom/salesforce/marketingcloud/analytics/stats/c$f;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/analytics/e;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

.field final synthetic d:Ljava/util/Date;

.field final synthetic e:Lcom/salesforce/marketingcloud/analytics/e;

.field final synthetic f:Lcom/salesforce/marketingcloud/analytics/stats/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/stats/c;Ljava/lang/String;[Ljava/lang/Object;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;Ljava/util/Date;Lcom/salesforce/marketingcloud/analytics/e;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->f:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->c:[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 4
    .line 5
    iput-object p5, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->d:Ljava/util/Date;

    .line 6
    .line 7
    iput-object p6, p0, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->e:Lcom/salesforce/marketingcloud/analytics/e;

    .line 8
    .line 9
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public a()V
    .locals 25

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->g()Lcom/salesforce/marketingcloud/config/a;

    .line 4
    .line 5
    .line 6
    move-result-object v2

    .line 7
    if-nez v2, :cond_0

    .line 8
    .line 9
    goto/16 :goto_6

    .line 10
    .line 11
    :cond_0
    iget-object v3, v1, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->c:[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 12
    .line 13
    array-length v4, v3

    .line 14
    const/4 v0, 0x0

    .line 15
    const/4 v5, 0x0

    .line 16
    move-object v6, v0

    .line 17
    move-object v7, v6

    .line 18
    move-object v8, v7

    .line 19
    move v9, v5

    .line 20
    move-object v5, v8

    .line 21
    :goto_0
    if-ge v9, v4, :cond_b

    .line 22
    .line 23
    aget-object v0, v3, v9

    .line 24
    .line 25
    :try_start_0
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->name()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v10

    .line 29
    invoke-virtual {v2, v10}, Lcom/salesforce/marketingcloud/config/a;->b(Ljava/lang/String;)Z

    .line 30
    .line 31
    .line 32
    move-result v10

    .line 33
    if-nez v10, :cond_1

    .line 34
    .line 35
    :goto_1
    move-object/from16 v24, v3

    .line 36
    .line 37
    goto/16 :goto_5

    .line 38
    .line 39
    :cond_1
    sget-object v10, Lcom/salesforce/marketingcloud/analytics/stats/c$i;->a:[I

    .line 40
    .line 41
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->getCategory()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    .line 42
    .line 43
    .line 44
    move-result-object v11

    .line 45
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 46
    .line 47
    .line 48
    move-result v11

    .line 49
    aget v10, v10, v11

    .line 50
    .line 51
    const/4 v11, 0x1

    .line 52
    if-eq v10, v11, :cond_8

    .line 53
    .line 54
    const/4 v12, 0x2

    .line 55
    if-eq v10, v12, :cond_6

    .line 56
    .line 57
    const/4 v12, 0x3

    .line 58
    if-eq v10, v12, :cond_4

    .line 59
    .line 60
    const/4 v12, 0x4

    .line 61
    if-eq v10, v12, :cond_2

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_2
    if-nez v8, :cond_3

    .line 65
    .line 66
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/config/a;->m()Z

    .line 67
    .line 68
    .line 69
    move-result v10

    .line 70
    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 71
    .line 72
    .line 73
    move-result-object v8

    .line 74
    goto :goto_2

    .line 75
    :catch_0
    move-exception v0

    .line 76
    move-object/from16 v24, v3

    .line 77
    .line 78
    goto/16 :goto_4

    .line 79
    .line 80
    :cond_3
    :goto_2
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 81
    .line 82
    .line 83
    move-result v10

    .line 84
    if-nez v10, :cond_a

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_4
    if-nez v7, :cond_5

    .line 88
    .line 89
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/config/a;->l()Z

    .line 90
    .line 91
    .line 92
    move-result v10

    .line 93
    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    :cond_5
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 98
    .line 99
    .line 100
    move-result v10

    .line 101
    if-nez v10, :cond_a

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_6
    if-nez v6, :cond_7

    .line 105
    .line 106
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/config/a;->k()Z

    .line 107
    .line 108
    .line 109
    move-result v10

    .line 110
    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 111
    .line 112
    .line 113
    move-result-object v6

    .line 114
    :cond_7
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 115
    .line 116
    .line 117
    move-result v10

    .line 118
    if-nez v10, :cond_a

    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_8
    if-nez v5, :cond_9

    .line 122
    .line 123
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/config/a;->i()Z

    .line 124
    .line 125
    .line 126
    move-result v10

    .line 127
    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 128
    .line 129
    .line 130
    move-result-object v5

    .line 131
    :cond_9
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 132
    .line 133
    .line 134
    move-result v10

    .line 135
    if-nez v10, :cond_a

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_a
    :goto_3
    sget-object v10, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 139
    .line 140
    const-string v12, "Event tracked %s( %s ) with Attributes: %s"

    .line 141
    .line 142
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    move-result-object v13

    .line 146
    invoke-virtual {v13}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v13

    .line 150
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->name()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v14

    .line 154
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->attributes()Ljava/util/Map;

    .line 155
    .line 156
    .line 157
    move-result-object v15

    .line 158
    filled-new-array {v13, v14, v15}, [Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v13

    .line 162
    invoke-static {v10, v12, v13}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    iget-object v10, v1, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->f:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 166
    .line 167
    iget-object v10, v10, Lcom/salesforce/marketingcloud/analytics/stats/c;->e:Lcom/salesforce/marketingcloud/internal/n;

    .line 168
    .line 169
    invoke-virtual {v10}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 170
    .line 171
    .line 172
    move-result-object v10

    .line 173
    new-instance v12, Lcom/salesforce/marketingcloud/analytics/stats/a;

    .line 174
    .line 175
    iget-object v13, v1, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->f:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 176
    .line 177
    iget-object v13, v13, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 178
    .line 179
    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/storage/h;->i()Lcom/salesforce/marketingcloud/storage/c;

    .line 180
    .line 181
    .line 182
    move-result-object v13

    .line 183
    iget-object v14, v1, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->f:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 184
    .line 185
    iget-object v14, v14, Lcom/salesforce/marketingcloud/analytics/stats/c;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 186
    .line 187
    invoke-virtual {v14}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 188
    .line 189
    .line 190
    move-result-object v14

    .line 191
    iget-object v15, v1, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->d:Ljava/util/Date;

    .line 192
    .line 193
    iget-object v11, v1, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->f:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 194
    .line 195
    iget-object v11, v11, Lcom/salesforce/marketingcloud/analytics/stats/c;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 196
    .line 197
    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v16

    .line 201
    iget-object v11, v1, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->f:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 202
    .line 203
    iget-object v11, v11, Lcom/salesforce/marketingcloud/analytics/stats/c;->f:Ljava/lang/String;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 204
    .line 205
    move-object/from16 v24, v3

    .line 206
    .line 207
    :try_start_1
    iget-object v3, v1, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->d:Ljava/util/Date;

    .line 208
    .line 209
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->name()Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v19

    .line 213
    move-object/from16 v18, v3

    .line 214
    .line 215
    iget-object v3, v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->id:Ljava/lang/String;

    .line 216
    .line 217
    move-object/from16 v17, v0

    .line 218
    .line 219
    invoke-virtual/range {v17 .. v17}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->toJson()Lorg/json/JSONObject;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    move-object/from16 v20, v3

    .line 224
    .line 225
    const-string v3, "attributes"

    .line 226
    .line 227
    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 228
    .line 229
    .line 230
    move-result-object v21

    .line 231
    iget-object v0, v1, Lcom/salesforce/marketingcloud/analytics/stats/c$f;->e:Lcom/salesforce/marketingcloud/analytics/e;

    .line 232
    .line 233
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/analytics/e;->e()Lorg/json/JSONObject;

    .line 234
    .line 235
    .line 236
    move-result-object v22

    .line 237
    invoke-virtual/range {v17 .. v17}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->name()Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    invoke-virtual {v2, v0}, Lcom/salesforce/marketingcloud/config/a;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v23

    .line 245
    move-object/from16 v17, v11

    .line 246
    .line 247
    invoke-static/range {v16 .. v23}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Lorg/json/JSONObject;Lorg/json/JSONObject;Ljava/lang/String;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    .line 248
    .line 249
    .line 250
    move-result-object v0

    .line 251
    const/16 v3, 0x69

    .line 252
    .line 253
    const/4 v11, 0x1

    .line 254
    invoke-static {v3, v15, v0, v11}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    invoke-direct {v12, v13, v14, v0}, Lcom/salesforce/marketingcloud/analytics/stats/a;-><init>(Lcom/salesforce/marketingcloud/storage/c;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/stats/b;)V

    .line 259
    .line 260
    .line 261
    invoke-interface {v10, v12}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 262
    .line 263
    .line 264
    goto :goto_5

    .line 265
    :catch_1
    move-exception v0

    .line 266
    :goto_4
    sget-object v3, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    .line 267
    .line 268
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    const-string v10, "Failed to record event in devstats"

    .line 273
    .line 274
    invoke-static {v3, v10, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 275
    .line 276
    .line 277
    :goto_5
    add-int/lit8 v9, v9, 0x1

    .line 278
    .line 279
    move-object/from16 v3, v24

    .line 280
    .line 281
    goto/16 :goto_0

    .line 282
    .line 283
    :cond_b
    :goto_6
    return-void
.end method
