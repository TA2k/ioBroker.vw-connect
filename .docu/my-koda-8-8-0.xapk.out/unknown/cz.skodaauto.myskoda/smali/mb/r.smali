.class public final Lmb/r;
.super Llp/df;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(Lua/c;Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p2, Lmb/o;

    .line 2
    .line 3
    const-string p0, "statement"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Lmb/o;->a:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-interface {p1, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object v1, p2, Lmb/o;->b:Leb/h0;

    .line 15
    .line 16
    invoke-static {v1}, Ljp/z0;->l(Leb/h0;)I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    const/4 v2, 0x2

    .line 21
    int-to-long v3, v1

    .line 22
    invoke-interface {p1, v2, v3, v4}, Lua/c;->bindLong(IJ)V

    .line 23
    .line 24
    .line 25
    const/4 v1, 0x3

    .line 26
    iget-object v2, p2, Lmb/o;->c:Ljava/lang/String;

    .line 27
    .line 28
    invoke-interface {p1, v1, v2}, Lua/c;->w(ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const/4 v1, 0x4

    .line 32
    iget-object v2, p2, Lmb/o;->d:Ljava/lang/String;

    .line 33
    .line 34
    invoke-interface {p1, v1, v2}, Lua/c;->w(ILjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    sget-object v1, Leb/h;->b:Leb/h;

    .line 38
    .line 39
    iget-object v1, p2, Lmb/o;->e:Leb/h;

    .line 40
    .line 41
    invoke-static {v1}, Lkp/b6;->d(Leb/h;)[B

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    const/4 v2, 0x5

    .line 46
    invoke-interface {p1, v2, v1}, Lua/c;->bindBlob(I[B)V

    .line 47
    .line 48
    .line 49
    iget-object v1, p2, Lmb/o;->f:Leb/h;

    .line 50
    .line 51
    invoke-static {v1}, Lkp/b6;->d(Leb/h;)[B

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    const/4 v2, 0x6

    .line 56
    invoke-interface {p1, v2, v1}, Lua/c;->bindBlob(I[B)V

    .line 57
    .line 58
    .line 59
    const/4 v1, 0x7

    .line 60
    iget-wide v2, p2, Lmb/o;->g:J

    .line 61
    .line 62
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 63
    .line 64
    .line 65
    const/16 v1, 0x8

    .line 66
    .line 67
    iget-wide v2, p2, Lmb/o;->h:J

    .line 68
    .line 69
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 70
    .line 71
    .line 72
    const/16 v1, 0x9

    .line 73
    .line 74
    iget-wide v2, p2, Lmb/o;->i:J

    .line 75
    .line 76
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 77
    .line 78
    .line 79
    iget v1, p2, Lmb/o;->k:I

    .line 80
    .line 81
    int-to-long v1, v1

    .line 82
    const/16 v3, 0xa

    .line 83
    .line 84
    invoke-interface {p1, v3, v1, v2}, Lua/c;->bindLong(IJ)V

    .line 85
    .line 86
    .line 87
    iget-object v1, p2, Lmb/o;->l:Leb/a;

    .line 88
    .line 89
    const-string v2, "backoffPolicy"

    .line 90
    .line 91
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    const/4 v2, 0x0

    .line 99
    if-eqz v1, :cond_1

    .line 100
    .line 101
    if-ne v1, v0, :cond_0

    .line 102
    .line 103
    move v1, v0

    .line 104
    goto :goto_0

    .line 105
    :cond_0
    new-instance p0, La8/r0;

    .line 106
    .line 107
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_1
    move v1, v2

    .line 112
    :goto_0
    const/16 v3, 0xb

    .line 113
    .line 114
    int-to-long v4, v1

    .line 115
    invoke-interface {p1, v3, v4, v5}, Lua/c;->bindLong(IJ)V

    .line 116
    .line 117
    .line 118
    const/16 v1, 0xc

    .line 119
    .line 120
    iget-wide v3, p2, Lmb/o;->m:J

    .line 121
    .line 122
    invoke-interface {p1, v1, v3, v4}, Lua/c;->bindLong(IJ)V

    .line 123
    .line 124
    .line 125
    const/16 v1, 0xd

    .line 126
    .line 127
    iget-wide v3, p2, Lmb/o;->n:J

    .line 128
    .line 129
    invoke-interface {p1, v1, v3, v4}, Lua/c;->bindLong(IJ)V

    .line 130
    .line 131
    .line 132
    const/16 v1, 0xe

    .line 133
    .line 134
    iget-wide v3, p2, Lmb/o;->o:J

    .line 135
    .line 136
    invoke-interface {p1, v1, v3, v4}, Lua/c;->bindLong(IJ)V

    .line 137
    .line 138
    .line 139
    const/16 v1, 0xf

    .line 140
    .line 141
    iget-wide v3, p2, Lmb/o;->p:J

    .line 142
    .line 143
    invoke-interface {p1, v1, v3, v4}, Lua/c;->bindLong(IJ)V

    .line 144
    .line 145
    .line 146
    iget-boolean v1, p2, Lmb/o;->q:Z

    .line 147
    .line 148
    const/16 v3, 0x10

    .line 149
    .line 150
    int-to-long v4, v1

    .line 151
    invoke-interface {p1, v3, v4, v5}, Lua/c;->bindLong(IJ)V

    .line 152
    .line 153
    .line 154
    iget-object v1, p2, Lmb/o;->r:Leb/e0;

    .line 155
    .line 156
    const-string v3, "policy"

    .line 157
    .line 158
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    if-eqz v1, :cond_3

    .line 166
    .line 167
    if-ne v1, v0, :cond_2

    .line 168
    .line 169
    goto :goto_1

    .line 170
    :cond_2
    new-instance p0, La8/r0;

    .line 171
    .line 172
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 173
    .line 174
    .line 175
    throw p0

    .line 176
    :cond_3
    move v0, v2

    .line 177
    :goto_1
    const/16 v1, 0x11

    .line 178
    .line 179
    int-to-long v2, v0

    .line 180
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 181
    .line 182
    .line 183
    iget v0, p2, Lmb/o;->s:I

    .line 184
    .line 185
    int-to-long v0, v0

    .line 186
    const/16 v2, 0x12

    .line 187
    .line 188
    invoke-interface {p1, v2, v0, v1}, Lua/c;->bindLong(IJ)V

    .line 189
    .line 190
    .line 191
    iget v0, p2, Lmb/o;->t:I

    .line 192
    .line 193
    int-to-long v0, v0

    .line 194
    const/16 v2, 0x13

    .line 195
    .line 196
    invoke-interface {p1, v2, v0, v1}, Lua/c;->bindLong(IJ)V

    .line 197
    .line 198
    .line 199
    const/16 v0, 0x14

    .line 200
    .line 201
    iget-wide v1, p2, Lmb/o;->u:J

    .line 202
    .line 203
    invoke-interface {p1, v0, v1, v2}, Lua/c;->bindLong(IJ)V

    .line 204
    .line 205
    .line 206
    iget v0, p2, Lmb/o;->v:I

    .line 207
    .line 208
    int-to-long v0, v0

    .line 209
    const/16 v2, 0x15

    .line 210
    .line 211
    invoke-interface {p1, v2, v0, v1}, Lua/c;->bindLong(IJ)V

    .line 212
    .line 213
    .line 214
    iget v0, p2, Lmb/o;->w:I

    .line 215
    .line 216
    int-to-long v0, v0

    .line 217
    const/16 v2, 0x16

    .line 218
    .line 219
    invoke-interface {p1, v2, v0, v1}, Lua/c;->bindLong(IJ)V

    .line 220
    .line 221
    .line 222
    iget-object v0, p2, Lmb/o;->x:Ljava/lang/String;

    .line 223
    .line 224
    const/16 v1, 0x17

    .line 225
    .line 226
    if-nez v0, :cond_4

    .line 227
    .line 228
    invoke-interface {p1, v1}, Lua/c;->bindNull(I)V

    .line 229
    .line 230
    .line 231
    goto :goto_2

    .line 232
    :cond_4
    invoke-interface {p1, v1, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 233
    .line 234
    .line 235
    :goto_2
    iget-object v0, p2, Lmb/o;->y:Ljava/lang/Boolean;

    .line 236
    .line 237
    if-eqz v0, :cond_5

    .line 238
    .line 239
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 240
    .line 241
    .line 242
    move-result v0

    .line 243
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    goto :goto_3

    .line 248
    :cond_5
    const/4 v0, 0x0

    .line 249
    :goto_3
    const/16 v1, 0x18

    .line 250
    .line 251
    if-nez v0, :cond_6

    .line 252
    .line 253
    invoke-interface {p1, v1}, Lua/c;->bindNull(I)V

    .line 254
    .line 255
    .line 256
    goto :goto_4

    .line 257
    :cond_6
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 258
    .line 259
    .line 260
    move-result v0

    .line 261
    int-to-long v2, v0

    .line 262
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 263
    .line 264
    .line 265
    :goto_4
    iget-object p2, p2, Lmb/o;->j:Leb/e;

    .line 266
    .line 267
    iget-object v0, p2, Leb/e;->a:Leb/x;

    .line 268
    .line 269
    invoke-static {v0}, Ljp/z0;->j(Leb/x;)I

    .line 270
    .line 271
    .line 272
    move-result v0

    .line 273
    const/16 v1, 0x19

    .line 274
    .line 275
    int-to-long v2, v0

    .line 276
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 277
    .line 278
    .line 279
    iget-object v0, p2, Leb/e;->b:Lnb/d;

    .line 280
    .line 281
    invoke-static {v0}, Ljp/z0;->c(Lnb/d;)[B

    .line 282
    .line 283
    .line 284
    move-result-object v0

    .line 285
    const/16 v1, 0x1a

    .line 286
    .line 287
    invoke-interface {p1, v1, v0}, Lua/c;->bindBlob(I[B)V

    .line 288
    .line 289
    .line 290
    iget-boolean v0, p2, Leb/e;->c:Z

    .line 291
    .line 292
    const/16 v1, 0x1b

    .line 293
    .line 294
    int-to-long v2, v0

    .line 295
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 296
    .line 297
    .line 298
    iget-boolean v0, p2, Leb/e;->d:Z

    .line 299
    .line 300
    const/16 v1, 0x1c

    .line 301
    .line 302
    int-to-long v2, v0

    .line 303
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 304
    .line 305
    .line 306
    iget-boolean v0, p2, Leb/e;->e:Z

    .line 307
    .line 308
    const/16 v1, 0x1d

    .line 309
    .line 310
    int-to-long v2, v0

    .line 311
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 312
    .line 313
    .line 314
    iget-boolean v0, p2, Leb/e;->f:Z

    .line 315
    .line 316
    const/16 v1, 0x1e

    .line 317
    .line 318
    int-to-long v2, v0

    .line 319
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 320
    .line 321
    .line 322
    const/16 v0, 0x1f

    .line 323
    .line 324
    iget-wide v1, p2, Leb/e;->g:J

    .line 325
    .line 326
    invoke-interface {p1, v0, v1, v2}, Lua/c;->bindLong(IJ)V

    .line 327
    .line 328
    .line 329
    const/16 v0, 0x20

    .line 330
    .line 331
    iget-wide v1, p2, Leb/e;->h:J

    .line 332
    .line 333
    invoke-interface {p1, v0, v1, v2}, Lua/c;->bindLong(IJ)V

    .line 334
    .line 335
    .line 336
    iget-object p2, p2, Leb/e;->i:Ljava/util/Set;

    .line 337
    .line 338
    invoke-static {p2}, Ljp/z0;->k(Ljava/util/Set;)[B

    .line 339
    .line 340
    .line 341
    move-result-object p2

    .line 342
    const/16 v0, 0x21

    .line 343
    .line 344
    invoke-interface {p1, v0, p2}, Lua/c;->bindBlob(I[B)V

    .line 345
    .line 346
    .line 347
    const/16 p2, 0x22

    .line 348
    .line 349
    invoke-interface {p1, p2, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 350
    .line 351
    .line 352
    return-void
.end method

.method public final d()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "UPDATE OR ABORT `WorkSpec` SET `id` = ?,`state` = ?,`worker_class_name` = ?,`input_merger_class_name` = ?,`input` = ?,`output` = ?,`initial_delay` = ?,`interval_duration` = ?,`flex_duration` = ?,`run_attempt_count` = ?,`backoff_policy` = ?,`backoff_delay_duration` = ?,`last_enqueue_time` = ?,`minimum_retention_duration` = ?,`schedule_requested_at` = ?,`run_in_foreground` = ?,`out_of_quota_policy` = ?,`period_count` = ?,`generation` = ?,`next_schedule_time_override` = ?,`next_schedule_time_override_generation` = ?,`stop_reason` = ?,`trace_tag` = ?,`backoff_on_system_interruptions` = ?,`required_network_type` = ?,`required_network_request` = ?,`requires_charging` = ?,`requires_device_idle` = ?,`requires_battery_not_low` = ?,`requires_storage_not_low` = ?,`trigger_content_update_delay` = ?,`trigger_max_content_delay` = ?,`content_uri_triggers` = ? WHERE `id` = ?"

    .line 2
    .line 3
    return-object p0
.end method
