.class public final synthetic Lod0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p2, p0, Lod0/d;->d:I

    iput-object p1, p0, Lod0/d;->e:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ILjava/lang/Object;)V
    .locals 0

    .line 2
    iput p2, p0, Lod0/d;->d:I

    iput-object p1, p0, Lod0/d;->e:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private final a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lod0/d;->e:Ljava/lang/String;

    .line 2
    .line 3
    check-cast p1, Lua/a;

    .line 4
    .line 5
    const-string v0, "_connection"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "SELECT * FROM vehicle_backups_notice WHERE vin = ?"

    .line 11
    .line 12
    invoke-interface {p1, v0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const/4 v0, 0x1

    .line 17
    :try_start_0
    invoke-interface {p1, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const-string p0, "vin"

    .line 21
    .line 22
    invoke-static {p1, p0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-interface {p1}, Lua/c;->s0()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    invoke-interface {p1, p0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    new-instance v0, Lus0/i;

    .line 37
    .line 38
    invoke-direct {v0, p0}, Lus0/i;-><init>(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception p0

    .line 43
    goto :goto_1

    .line 44
    :cond_0
    const/4 v0, 0x0

    .line 45
    :goto_0
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 46
    .line 47
    .line 48
    return-object v0

    .line 49
    :goto_1
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 50
    .line 51
    .line 52
    throw p0
.end method

.method private final b(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 2
    .line 3
    const-string v0, "$this$registrationManagerEditor"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lod0/d;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;->setContactKey(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private final c(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lod0/d;->e:Ljava/lang/String;

    .line 2
    .line 3
    check-cast p1, Lzb/u0;

    .line 4
    .line 5
    const-string v0, "$this$wthReferences"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    iget-object p1, p1, Lzb/u0;->b:Landroid/content/Context;

    .line 11
    .line 12
    new-instance v0, Landroid/content/Intent;

    .line 13
    .line 14
    const-string v1, "android.intent.action.VIEW"

    .line 15
    .line 16
    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-static {p0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {v0, p0}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const-string v0, "setData(...)"

    .line 28
    .line 29
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1, p0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :catchall_0
    move-exception p0

    .line 37
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 38
    .line 39
    .line 40
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0
.end method

.method private final d(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lzb/u0;

    .line 2
    .line 3
    const-string v0, "$this$wthReferences"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p1, p1, Lzb/u0;->d:Lw3/d1;

    .line 9
    .line 10
    new-instance v0, Lg4/g;

    .line 11
    .line 12
    iget-object p0, p0, Lod0/d;->e:Ljava/lang/String;

    .line 13
    .line 14
    invoke-direct {v0, p0}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    check-cast p1, Lw3/i;

    .line 18
    .line 19
    invoke-virtual {p1, v0}, Lw3/i;->a(Lg4/g;)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lod0/d;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lgi/c;

    .line 11
    .line 12
    const-string v1, "Opening webview with \'"

    .line 13
    .line 14
    const-string v2, "\'"

    .line 15
    .line 16
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v1, v0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    return-object v0

    .line 23
    :pswitch_0
    invoke-direct/range {p0 .. p1}, Lod0/d;->d(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    return-object v0

    .line 28
    :pswitch_1
    invoke-direct/range {p0 .. p1}, Lod0/d;->c(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    return-object v0

    .line 33
    :pswitch_2
    invoke-direct/range {p0 .. p1}, Lod0/d;->b(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    return-object v0

    .line 38
    :pswitch_3
    move-object/from16 v1, p1

    .line 39
    .line 40
    check-cast v1, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 41
    .line 42
    const-string v2, "$this$pushManager"

    .line 43
    .line 44
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 48
    .line 49
    invoke-virtual {v1, v0}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->setPushToken(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    return-object v0

    .line 55
    :pswitch_4
    invoke-direct/range {p0 .. p1}, Lod0/d;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    return-object v0

    .line 60
    :pswitch_5
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 61
    .line 62
    move-object/from16 v1, p1

    .line 63
    .line 64
    check-cast v1, Lua/a;

    .line 65
    .line 66
    const-string v2, "_connection"

    .line 67
    .line 68
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const-string v2, "DELETE FROM vehicle_backups_notice WHERE vin = ?"

    .line 72
    .line 73
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    const/4 v2, 0x1

    .line 78
    :try_start_0
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 82
    .line 83
    .line 84
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 85
    .line 86
    .line 87
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object v0

    .line 90
    :catchall_0
    move-exception v0

    .line 91
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 92
    .line 93
    .line 94
    throw v0

    .line 95
    :pswitch_6
    move-object/from16 v1, p1

    .line 96
    .line 97
    check-cast v1, Lgi/c;

    .line 98
    .line 99
    const-string v1, "Loading power curve for recordId: "

    .line 100
    .line 101
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 102
    .line 103
    invoke-static {v1, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    return-object v0

    .line 108
    :pswitch_7
    move-object/from16 v1, p1

    .line 109
    .line 110
    check-cast v1, Lgi/c;

    .line 111
    .line 112
    const-string v2, "$this$log"

    .line 113
    .line 114
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    new-instance v1, Ljava/lang/StringBuilder;

    .line 118
    .line 119
    const-string v2, "Unknown link "

    .line 120
    .line 121
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 125
    .line 126
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    return-object v0

    .line 134
    :pswitch_8
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 135
    .line 136
    move-object/from16 v1, p1

    .line 137
    .line 138
    check-cast v1, Lua/a;

    .line 139
    .line 140
    const-string v2, "_connection"

    .line 141
    .line 142
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    const-string v2, "SELECT * FROM vehicle_status WHERE vin = ? LIMIT 1"

    .line 146
    .line 147
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    const/4 v2, 0x1

    .line 152
    :try_start_1
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 153
    .line 154
    .line 155
    const-string v0, "vin"

    .line 156
    .line 157
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 158
    .line 159
    .line 160
    move-result v0

    .line 161
    const-string v2, "car_captured_timestamp"

    .line 162
    .line 163
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    const-string v3, "overall_status_doors"

    .line 168
    .line 169
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 170
    .line 171
    .line 172
    move-result v3

    .line 173
    const-string v4, "overall_status_windows"

    .line 174
    .line 175
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 176
    .line 177
    .line 178
    move-result v4

    .line 179
    const-string v5, "overall_status_locked"

    .line 180
    .line 181
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 182
    .line 183
    .line 184
    move-result v5

    .line 185
    const-string v6, "overall_status_lights"

    .line 186
    .line 187
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 188
    .line 189
    .line 190
    move-result v6

    .line 191
    const-string v7, "overall_status_doors_locked"

    .line 192
    .line 193
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 194
    .line 195
    .line 196
    move-result v7

    .line 197
    const-string v8, "overall_status_doors_open"

    .line 198
    .line 199
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 200
    .line 201
    .line 202
    move-result v8

    .line 203
    const-string v9, "overall_status_lock_status"

    .line 204
    .line 205
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 206
    .line 207
    .line 208
    move-result v9

    .line 209
    const-string v10, "detail_status_sun_roof_status"

    .line 210
    .line 211
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 212
    .line 213
    .line 214
    move-result v10

    .line 215
    const-string v11, "detail_status_trunk_status"

    .line 216
    .line 217
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 218
    .line 219
    .line 220
    move-result v11

    .line 221
    const-string v12, "detail_status_bonnet_status"

    .line 222
    .line 223
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 224
    .line 225
    .line 226
    move-result v12

    .line 227
    const-string v13, "render_light_mode_one_x"

    .line 228
    .line 229
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 230
    .line 231
    .line 232
    move-result v13

    .line 233
    const-string v14, "render_light_mode_one_and_half_x"

    .line 234
    .line 235
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 236
    .line 237
    .line 238
    move-result v14

    .line 239
    const-string v15, "render_light_mode_two_x"

    .line 240
    .line 241
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 242
    .line 243
    .line 244
    move-result v15

    .line 245
    move/from16 p0, v15

    .line 246
    .line 247
    const-string v15, "render_light_mode_three_x"

    .line 248
    .line 249
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 250
    .line 251
    .line 252
    move-result v15

    .line 253
    move/from16 p1, v15

    .line 254
    .line 255
    const-string v15, "render_dark_mode_one_x"

    .line 256
    .line 257
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 258
    .line 259
    .line 260
    move-result v15

    .line 261
    move/from16 v16, v15

    .line 262
    .line 263
    const-string v15, "render_dark_mode_one_and_half_x"

    .line 264
    .line 265
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 266
    .line 267
    .line 268
    move-result v15

    .line 269
    move/from16 v17, v15

    .line 270
    .line 271
    const-string v15, "render_dark_mode_two_x"

    .line 272
    .line 273
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 274
    .line 275
    .line 276
    move-result v15

    .line 277
    move/from16 v18, v15

    .line 278
    .line 279
    const-string v15, "render_dark_mode_three_x"

    .line 280
    .line 281
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 282
    .line 283
    .line 284
    move-result v15

    .line 285
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 286
    .line 287
    .line 288
    move-result v19

    .line 289
    const/16 v20, 0x0

    .line 290
    .line 291
    if-eqz v19, :cond_9

    .line 292
    .line 293
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object v22

    .line 297
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 298
    .line 299
    .line 300
    move-result v0

    .line 301
    if-eqz v0, :cond_0

    .line 302
    .line 303
    move-object/from16 v0, v20

    .line 304
    .line 305
    goto :goto_0

    .line 306
    :cond_0
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    :goto_0
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 311
    .line 312
    .line 313
    move-result-object v26

    .line 314
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object v28

    .line 318
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 319
    .line 320
    .line 321
    move-result-object v29

    .line 322
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object v30

    .line 326
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object v31

    .line 330
    invoke-interface {v1, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 331
    .line 332
    .line 333
    move-result-object v32

    .line 334
    invoke-interface {v1, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 335
    .line 336
    .line 337
    move-result-object v33

    .line 338
    invoke-interface {v1, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 339
    .line 340
    .line 341
    move-result-object v34

    .line 342
    new-instance v23, Lpt0/p;

    .line 343
    .line 344
    move-object/from16 v27, v23

    .line 345
    .line 346
    invoke-direct/range {v27 .. v34}, Lpt0/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    move-object/from16 v23, v27

    .line 350
    .line 351
    invoke-interface {v1, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    invoke-interface {v1, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 356
    .line 357
    .line 358
    move-result-object v2

    .line 359
    invoke-interface {v1, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object v3

    .line 363
    new-instance v4, Lpt0/m;

    .line 364
    .line 365
    invoke-direct {v4, v0, v2, v3}, Lpt0/m;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    invoke-interface {v1, v13}, Lua/c;->isNull(I)Z

    .line 369
    .line 370
    .line 371
    move-result v0

    .line 372
    if-eqz v0, :cond_1

    .line 373
    .line 374
    move-object/from16 v6, v20

    .line 375
    .line 376
    goto :goto_1

    .line 377
    :cond_1
    invoke-interface {v1, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object v0

    .line 381
    move-object v6, v0

    .line 382
    :goto_1
    invoke-interface {v1, v14}, Lua/c;->isNull(I)Z

    .line 383
    .line 384
    .line 385
    move-result v0

    .line 386
    if-eqz v0, :cond_2

    .line 387
    .line 388
    move-object/from16 v7, v20

    .line 389
    .line 390
    :goto_2
    move/from16 v0, p0

    .line 391
    .line 392
    goto :goto_3

    .line 393
    :cond_2
    invoke-interface {v1, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 394
    .line 395
    .line 396
    move-result-object v0

    .line 397
    move-object v7, v0

    .line 398
    goto :goto_2

    .line 399
    :goto_3
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 400
    .line 401
    .line 402
    move-result v2

    .line 403
    if-eqz v2, :cond_3

    .line 404
    .line 405
    move-object/from16 v8, v20

    .line 406
    .line 407
    :goto_4
    move/from16 v0, p1

    .line 408
    .line 409
    goto :goto_5

    .line 410
    :cond_3
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 411
    .line 412
    .line 413
    move-result-object v0

    .line 414
    move-object v8, v0

    .line 415
    goto :goto_4

    .line 416
    :goto_5
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 417
    .line 418
    .line 419
    move-result v2

    .line 420
    if-eqz v2, :cond_4

    .line 421
    .line 422
    move-object/from16 v9, v20

    .line 423
    .line 424
    :goto_6
    move/from16 v0, v16

    .line 425
    .line 426
    goto :goto_7

    .line 427
    :cond_4
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 428
    .line 429
    .line 430
    move-result-object v0

    .line 431
    move-object v9, v0

    .line 432
    goto :goto_6

    .line 433
    :goto_7
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 434
    .line 435
    .line 436
    move-result v2

    .line 437
    if-eqz v2, :cond_5

    .line 438
    .line 439
    move-object/from16 v10, v20

    .line 440
    .line 441
    :goto_8
    move/from16 v0, v17

    .line 442
    .line 443
    goto :goto_9

    .line 444
    :cond_5
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 445
    .line 446
    .line 447
    move-result-object v0

    .line 448
    move-object v10, v0

    .line 449
    goto :goto_8

    .line 450
    :goto_9
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 451
    .line 452
    .line 453
    move-result v2

    .line 454
    if-eqz v2, :cond_6

    .line 455
    .line 456
    move-object/from16 v11, v20

    .line 457
    .line 458
    :goto_a
    move/from16 v0, v18

    .line 459
    .line 460
    goto :goto_b

    .line 461
    :cond_6
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 462
    .line 463
    .line 464
    move-result-object v0

    .line 465
    move-object v11, v0

    .line 466
    goto :goto_a

    .line 467
    :goto_b
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 468
    .line 469
    .line 470
    move-result v2

    .line 471
    if-eqz v2, :cond_7

    .line 472
    .line 473
    move-object/from16 v12, v20

    .line 474
    .line 475
    goto :goto_c

    .line 476
    :cond_7
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    move-object v12, v0

    .line 481
    :goto_c
    invoke-interface {v1, v15}, Lua/c;->isNull(I)Z

    .line 482
    .line 483
    .line 484
    move-result v0

    .line 485
    if-eqz v0, :cond_8

    .line 486
    .line 487
    :goto_d
    move-object/from16 v13, v20

    .line 488
    .line 489
    goto :goto_e

    .line 490
    :cond_8
    invoke-interface {v1, v15}, Lua/c;->g0(I)Ljava/lang/String;

    .line 491
    .line 492
    .line 493
    move-result-object v20

    .line 494
    goto :goto_d

    .line 495
    :goto_e
    new-instance v5, Lpt0/q;

    .line 496
    .line 497
    invoke-direct/range {v5 .. v13}, Lpt0/q;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    new-instance v21, Lpt0/o;

    .line 501
    .line 502
    move-object/from16 v24, v4

    .line 503
    .line 504
    move-object/from16 v25, v5

    .line 505
    .line 506
    invoke-direct/range {v21 .. v26}, Lpt0/o;-><init>(Ljava/lang/String;Lpt0/p;Lpt0/m;Lpt0/q;Ljava/time/OffsetDateTime;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 507
    .line 508
    .line 509
    move-object/from16 v20, v21

    .line 510
    .line 511
    goto :goto_f

    .line 512
    :catchall_1
    move-exception v0

    .line 513
    goto :goto_10

    .line 514
    :cond_9
    :goto_f
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 515
    .line 516
    .line 517
    return-object v20

    .line 518
    :goto_10
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 519
    .line 520
    .line 521
    throw v0

    .line 522
    :pswitch_9
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 523
    .line 524
    move-object/from16 v1, p1

    .line 525
    .line 526
    check-cast v1, Lua/a;

    .line 527
    .line 528
    const-string v2, "_connection"

    .line 529
    .line 530
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    const-string v2, "SELECT * FROM vehicle_status WHERE vin = ? LIMIT 1"

    .line 534
    .line 535
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 536
    .line 537
    .line 538
    move-result-object v1

    .line 539
    const/4 v2, 0x1

    .line 540
    :try_start_2
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 541
    .line 542
    .line 543
    const-string v0, "vin"

    .line 544
    .line 545
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 546
    .line 547
    .line 548
    move-result v0

    .line 549
    const-string v2, "car_captured_timestamp"

    .line 550
    .line 551
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 552
    .line 553
    .line 554
    move-result v2

    .line 555
    const-string v3, "overall_status_doors"

    .line 556
    .line 557
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 558
    .line 559
    .line 560
    move-result v3

    .line 561
    const-string v4, "overall_status_windows"

    .line 562
    .line 563
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 564
    .line 565
    .line 566
    move-result v4

    .line 567
    const-string v5, "overall_status_locked"

    .line 568
    .line 569
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 570
    .line 571
    .line 572
    move-result v5

    .line 573
    const-string v6, "overall_status_lights"

    .line 574
    .line 575
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 576
    .line 577
    .line 578
    move-result v6

    .line 579
    const-string v7, "overall_status_doors_locked"

    .line 580
    .line 581
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 582
    .line 583
    .line 584
    move-result v7

    .line 585
    const-string v8, "overall_status_doors_open"

    .line 586
    .line 587
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 588
    .line 589
    .line 590
    move-result v8

    .line 591
    const-string v9, "overall_status_lock_status"

    .line 592
    .line 593
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 594
    .line 595
    .line 596
    move-result v9

    .line 597
    const-string v10, "detail_status_sun_roof_status"

    .line 598
    .line 599
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 600
    .line 601
    .line 602
    move-result v10

    .line 603
    const-string v11, "detail_status_trunk_status"

    .line 604
    .line 605
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 606
    .line 607
    .line 608
    move-result v11

    .line 609
    const-string v12, "detail_status_bonnet_status"

    .line 610
    .line 611
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 612
    .line 613
    .line 614
    move-result v12

    .line 615
    const-string v13, "render_light_mode_one_x"

    .line 616
    .line 617
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 618
    .line 619
    .line 620
    move-result v13

    .line 621
    const-string v14, "render_light_mode_one_and_half_x"

    .line 622
    .line 623
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 624
    .line 625
    .line 626
    move-result v14

    .line 627
    const-string v15, "render_light_mode_two_x"

    .line 628
    .line 629
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 630
    .line 631
    .line 632
    move-result v15

    .line 633
    move/from16 p0, v15

    .line 634
    .line 635
    const-string v15, "render_light_mode_three_x"

    .line 636
    .line 637
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 638
    .line 639
    .line 640
    move-result v15

    .line 641
    move/from16 p1, v15

    .line 642
    .line 643
    const-string v15, "render_dark_mode_one_x"

    .line 644
    .line 645
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 646
    .line 647
    .line 648
    move-result v15

    .line 649
    move/from16 v16, v15

    .line 650
    .line 651
    const-string v15, "render_dark_mode_one_and_half_x"

    .line 652
    .line 653
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 654
    .line 655
    .line 656
    move-result v15

    .line 657
    move/from16 v17, v15

    .line 658
    .line 659
    const-string v15, "render_dark_mode_two_x"

    .line 660
    .line 661
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 662
    .line 663
    .line 664
    move-result v15

    .line 665
    move/from16 v18, v15

    .line 666
    .line 667
    const-string v15, "render_dark_mode_three_x"

    .line 668
    .line 669
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 670
    .line 671
    .line 672
    move-result v15

    .line 673
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 674
    .line 675
    .line 676
    move-result v19

    .line 677
    const/16 v20, 0x0

    .line 678
    .line 679
    if-eqz v19, :cond_13

    .line 680
    .line 681
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 682
    .line 683
    .line 684
    move-result-object v22

    .line 685
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 686
    .line 687
    .line 688
    move-result v0

    .line 689
    if-eqz v0, :cond_a

    .line 690
    .line 691
    move-object/from16 v0, v20

    .line 692
    .line 693
    goto :goto_11

    .line 694
    :cond_a
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 695
    .line 696
    .line 697
    move-result-object v0

    .line 698
    :goto_11
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 699
    .line 700
    .line 701
    move-result-object v26

    .line 702
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 703
    .line 704
    .line 705
    move-result-object v28

    .line 706
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 707
    .line 708
    .line 709
    move-result-object v29

    .line 710
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 711
    .line 712
    .line 713
    move-result-object v30

    .line 714
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 715
    .line 716
    .line 717
    move-result-object v31

    .line 718
    invoke-interface {v1, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 719
    .line 720
    .line 721
    move-result-object v32

    .line 722
    invoke-interface {v1, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 723
    .line 724
    .line 725
    move-result-object v33

    .line 726
    invoke-interface {v1, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 727
    .line 728
    .line 729
    move-result-object v34

    .line 730
    new-instance v23, Lpt0/p;

    .line 731
    .line 732
    move-object/from16 v27, v23

    .line 733
    .line 734
    invoke-direct/range {v27 .. v34}, Lpt0/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 735
    .line 736
    .line 737
    move-object/from16 v23, v27

    .line 738
    .line 739
    invoke-interface {v1, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 740
    .line 741
    .line 742
    move-result-object v0

    .line 743
    invoke-interface {v1, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 744
    .line 745
    .line 746
    move-result-object v2

    .line 747
    invoke-interface {v1, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 748
    .line 749
    .line 750
    move-result-object v3

    .line 751
    new-instance v4, Lpt0/m;

    .line 752
    .line 753
    invoke-direct {v4, v0, v2, v3}, Lpt0/m;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 754
    .line 755
    .line 756
    invoke-interface {v1, v13}, Lua/c;->isNull(I)Z

    .line 757
    .line 758
    .line 759
    move-result v0

    .line 760
    if-eqz v0, :cond_b

    .line 761
    .line 762
    move-object/from16 v6, v20

    .line 763
    .line 764
    goto :goto_12

    .line 765
    :cond_b
    invoke-interface {v1, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 766
    .line 767
    .line 768
    move-result-object v0

    .line 769
    move-object v6, v0

    .line 770
    :goto_12
    invoke-interface {v1, v14}, Lua/c;->isNull(I)Z

    .line 771
    .line 772
    .line 773
    move-result v0

    .line 774
    if-eqz v0, :cond_c

    .line 775
    .line 776
    move-object/from16 v7, v20

    .line 777
    .line 778
    :goto_13
    move/from16 v0, p0

    .line 779
    .line 780
    goto :goto_14

    .line 781
    :cond_c
    invoke-interface {v1, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 782
    .line 783
    .line 784
    move-result-object v0

    .line 785
    move-object v7, v0

    .line 786
    goto :goto_13

    .line 787
    :goto_14
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 788
    .line 789
    .line 790
    move-result v2

    .line 791
    if-eqz v2, :cond_d

    .line 792
    .line 793
    move-object/from16 v8, v20

    .line 794
    .line 795
    :goto_15
    move/from16 v0, p1

    .line 796
    .line 797
    goto :goto_16

    .line 798
    :cond_d
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 799
    .line 800
    .line 801
    move-result-object v0

    .line 802
    move-object v8, v0

    .line 803
    goto :goto_15

    .line 804
    :goto_16
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 805
    .line 806
    .line 807
    move-result v2

    .line 808
    if-eqz v2, :cond_e

    .line 809
    .line 810
    move-object/from16 v9, v20

    .line 811
    .line 812
    :goto_17
    move/from16 v0, v16

    .line 813
    .line 814
    goto :goto_18

    .line 815
    :cond_e
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 816
    .line 817
    .line 818
    move-result-object v0

    .line 819
    move-object v9, v0

    .line 820
    goto :goto_17

    .line 821
    :goto_18
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 822
    .line 823
    .line 824
    move-result v2

    .line 825
    if-eqz v2, :cond_f

    .line 826
    .line 827
    move-object/from16 v10, v20

    .line 828
    .line 829
    :goto_19
    move/from16 v0, v17

    .line 830
    .line 831
    goto :goto_1a

    .line 832
    :cond_f
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 833
    .line 834
    .line 835
    move-result-object v0

    .line 836
    move-object v10, v0

    .line 837
    goto :goto_19

    .line 838
    :goto_1a
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 839
    .line 840
    .line 841
    move-result v2

    .line 842
    if-eqz v2, :cond_10

    .line 843
    .line 844
    move-object/from16 v11, v20

    .line 845
    .line 846
    :goto_1b
    move/from16 v0, v18

    .line 847
    .line 848
    goto :goto_1c

    .line 849
    :cond_10
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 850
    .line 851
    .line 852
    move-result-object v0

    .line 853
    move-object v11, v0

    .line 854
    goto :goto_1b

    .line 855
    :goto_1c
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 856
    .line 857
    .line 858
    move-result v2

    .line 859
    if-eqz v2, :cond_11

    .line 860
    .line 861
    move-object/from16 v12, v20

    .line 862
    .line 863
    goto :goto_1d

    .line 864
    :cond_11
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 865
    .line 866
    .line 867
    move-result-object v0

    .line 868
    move-object v12, v0

    .line 869
    :goto_1d
    invoke-interface {v1, v15}, Lua/c;->isNull(I)Z

    .line 870
    .line 871
    .line 872
    move-result v0

    .line 873
    if-eqz v0, :cond_12

    .line 874
    .line 875
    :goto_1e
    move-object/from16 v13, v20

    .line 876
    .line 877
    goto :goto_1f

    .line 878
    :cond_12
    invoke-interface {v1, v15}, Lua/c;->g0(I)Ljava/lang/String;

    .line 879
    .line 880
    .line 881
    move-result-object v20

    .line 882
    goto :goto_1e

    .line 883
    :goto_1f
    new-instance v5, Lpt0/q;

    .line 884
    .line 885
    invoke-direct/range {v5 .. v13}, Lpt0/q;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 886
    .line 887
    .line 888
    new-instance v21, Lpt0/o;

    .line 889
    .line 890
    move-object/from16 v24, v4

    .line 891
    .line 892
    move-object/from16 v25, v5

    .line 893
    .line 894
    invoke-direct/range {v21 .. v26}, Lpt0/o;-><init>(Ljava/lang/String;Lpt0/p;Lpt0/m;Lpt0/q;Ljava/time/OffsetDateTime;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 895
    .line 896
    .line 897
    move-object/from16 v20, v21

    .line 898
    .line 899
    goto :goto_20

    .line 900
    :catchall_2
    move-exception v0

    .line 901
    goto :goto_21

    .line 902
    :cond_13
    :goto_20
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 903
    .line 904
    .line 905
    return-object v20

    .line 906
    :goto_21
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 907
    .line 908
    .line 909
    throw v0

    .line 910
    :pswitch_a
    move-object/from16 v1, p1

    .line 911
    .line 912
    check-cast v1, Lgi/c;

    .line 913
    .line 914
    const-string v2, "$this$log"

    .line 915
    .line 916
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 917
    .line 918
    .line 919
    new-instance v1, Ljava/lang/StringBuilder;

    .line 920
    .line 921
    const-string v2, "Successfully loaded charging service provider name/logo for "

    .line 922
    .line 923
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 924
    .line 925
    .line 926
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 927
    .line 928
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 929
    .line 930
    .line 931
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 932
    .line 933
    .line 934
    move-result-object v0

    .line 935
    return-object v0

    .line 936
    :pswitch_b
    move-object/from16 v1, p1

    .line 937
    .line 938
    check-cast v1, Lhi/a;

    .line 939
    .line 940
    const-string v2, "$this$sdkViewModel"

    .line 941
    .line 942
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 943
    .line 944
    .line 945
    const-class v2, Ldh/u;

    .line 946
    .line 947
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 948
    .line 949
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 950
    .line 951
    .line 952
    move-result-object v2

    .line 953
    check-cast v1, Lii/a;

    .line 954
    .line 955
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 956
    .line 957
    .line 958
    move-result-object v1

    .line 959
    check-cast v1, Ldh/u;

    .line 960
    .line 961
    new-instance v2, Lph/i;

    .line 962
    .line 963
    new-instance v3, Ljh/b;

    .line 964
    .line 965
    const/4 v4, 0x0

    .line 966
    const/4 v5, 0x3

    .line 967
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 968
    .line 969
    invoke-direct {v3, v1, v0, v4, v5}, Ljh/b;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 970
    .line 971
    .line 972
    invoke-direct {v2, v3}, Lph/i;-><init>(Ljh/b;)V

    .line 973
    .line 974
    .line 975
    return-object v2

    .line 976
    :pswitch_c
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 977
    .line 978
    move-object/from16 v1, p1

    .line 979
    .line 980
    check-cast v1, Lua/a;

    .line 981
    .line 982
    const-string v2, "_connection"

    .line 983
    .line 984
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 985
    .line 986
    .line 987
    const-string v2, "SELECT * FROM charging_profiles WHERE vin = ? LIMIT 1"

    .line 988
    .line 989
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 990
    .line 991
    .line 992
    move-result-object v1

    .line 993
    const/4 v2, 0x1

    .line 994
    :try_start_3
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 995
    .line 996
    .line 997
    const-string v0, "vin"

    .line 998
    .line 999
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1000
    .line 1001
    .line 1002
    move-result v0

    .line 1003
    const-string v2, "current_profile_id"

    .line 1004
    .line 1005
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1006
    .line 1007
    .line 1008
    move-result v2

    .line 1009
    const-string v3, "next_timer_time"

    .line 1010
    .line 1011
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1012
    .line 1013
    .line 1014
    move-result v3

    .line 1015
    const-string v4, "car_captured_timestamp"

    .line 1016
    .line 1017
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1018
    .line 1019
    .line 1020
    move-result v4

    .line 1021
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1022
    .line 1023
    .line 1024
    move-result v5

    .line 1025
    const/4 v6, 0x0

    .line 1026
    if-eqz v5, :cond_17

    .line 1027
    .line 1028
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1029
    .line 1030
    .line 1031
    move-result-object v0

    .line 1032
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 1033
    .line 1034
    .line 1035
    move-result v5

    .line 1036
    if-eqz v5, :cond_14

    .line 1037
    .line 1038
    move-object v2, v6

    .line 1039
    goto :goto_22

    .line 1040
    :cond_14
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1041
    .line 1042
    .line 1043
    move-result-wide v7

    .line 1044
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v2

    .line 1048
    :goto_22
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 1049
    .line 1050
    .line 1051
    move-result v5

    .line 1052
    if-eqz v5, :cond_15

    .line 1053
    .line 1054
    move-object v3, v6

    .line 1055
    goto :goto_23

    .line 1056
    :cond_15
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1057
    .line 1058
    .line 1059
    move-result-object v3

    .line 1060
    :goto_23
    invoke-static {v3}, Lwq/f;->m(Ljava/lang/String;)Ljava/time/LocalTime;

    .line 1061
    .line 1062
    .line 1063
    move-result-object v3

    .line 1064
    invoke-interface {v1, v4}, Lua/c;->isNull(I)Z

    .line 1065
    .line 1066
    .line 1067
    move-result v5

    .line 1068
    if-eqz v5, :cond_16

    .line 1069
    .line 1070
    goto :goto_24

    .line 1071
    :cond_16
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1072
    .line 1073
    .line 1074
    move-result-object v6

    .line 1075
    :goto_24
    invoke-static {v6}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 1076
    .line 1077
    .line 1078
    move-result-object v4

    .line 1079
    new-instance v6, Lod0/r;

    .line 1080
    .line 1081
    invoke-direct {v6, v0, v2, v3, v4}, Lod0/r;-><init>(Ljava/lang/String;Ljava/lang/Long;Ljava/time/LocalTime;Ljava/time/OffsetDateTime;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 1082
    .line 1083
    .line 1084
    goto :goto_25

    .line 1085
    :catchall_3
    move-exception v0

    .line 1086
    goto :goto_26

    .line 1087
    :cond_17
    :goto_25
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1088
    .line 1089
    .line 1090
    return-object v6

    .line 1091
    :goto_26
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1092
    .line 1093
    .line 1094
    throw v0

    .line 1095
    :pswitch_d
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 1096
    .line 1097
    move-object/from16 v1, p1

    .line 1098
    .line 1099
    check-cast v1, Lua/a;

    .line 1100
    .line 1101
    const-string v2, "_connection"

    .line 1102
    .line 1103
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1104
    .line 1105
    .line 1106
    const-string v2, "DELETE FROM charging_profiles WHERE vin = ?"

    .line 1107
    .line 1108
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1109
    .line 1110
    .line 1111
    move-result-object v1

    .line 1112
    const/4 v2, 0x1

    .line 1113
    :try_start_4
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 1114
    .line 1115
    .line 1116
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 1117
    .line 1118
    .line 1119
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1120
    .line 1121
    .line 1122
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1123
    .line 1124
    return-object v0

    .line 1125
    :catchall_4
    move-exception v0

    .line 1126
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1127
    .line 1128
    .line 1129
    throw v0

    .line 1130
    :pswitch_e
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 1131
    .line 1132
    move-object/from16 v1, p1

    .line 1133
    .line 1134
    check-cast v1, Lua/a;

    .line 1135
    .line 1136
    const-string v2, "_connection"

    .line 1137
    .line 1138
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1139
    .line 1140
    .line 1141
    const-string v2, "SELECT * FROM charging_profiles WHERE vin = ? LIMIT 1"

    .line 1142
    .line 1143
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1144
    .line 1145
    .line 1146
    move-result-object v1

    .line 1147
    const/4 v2, 0x1

    .line 1148
    :try_start_5
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 1149
    .line 1150
    .line 1151
    const-string v0, "vin"

    .line 1152
    .line 1153
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1154
    .line 1155
    .line 1156
    move-result v0

    .line 1157
    const-string v2, "current_profile_id"

    .line 1158
    .line 1159
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1160
    .line 1161
    .line 1162
    move-result v2

    .line 1163
    const-string v3, "next_timer_time"

    .line 1164
    .line 1165
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1166
    .line 1167
    .line 1168
    move-result v3

    .line 1169
    const-string v4, "car_captured_timestamp"

    .line 1170
    .line 1171
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1172
    .line 1173
    .line 1174
    move-result v4

    .line 1175
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1176
    .line 1177
    .line 1178
    move-result v5

    .line 1179
    const/4 v6, 0x0

    .line 1180
    if-eqz v5, :cond_1b

    .line 1181
    .line 1182
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v0

    .line 1186
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 1187
    .line 1188
    .line 1189
    move-result v5

    .line 1190
    if-eqz v5, :cond_18

    .line 1191
    .line 1192
    move-object v2, v6

    .line 1193
    goto :goto_27

    .line 1194
    :cond_18
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 1195
    .line 1196
    .line 1197
    move-result-wide v7

    .line 1198
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1199
    .line 1200
    .line 1201
    move-result-object v2

    .line 1202
    :goto_27
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 1203
    .line 1204
    .line 1205
    move-result v5

    .line 1206
    if-eqz v5, :cond_19

    .line 1207
    .line 1208
    move-object v3, v6

    .line 1209
    goto :goto_28

    .line 1210
    :cond_19
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1211
    .line 1212
    .line 1213
    move-result-object v3

    .line 1214
    :goto_28
    invoke-static {v3}, Lwq/f;->m(Ljava/lang/String;)Ljava/time/LocalTime;

    .line 1215
    .line 1216
    .line 1217
    move-result-object v3

    .line 1218
    invoke-interface {v1, v4}, Lua/c;->isNull(I)Z

    .line 1219
    .line 1220
    .line 1221
    move-result v5

    .line 1222
    if-eqz v5, :cond_1a

    .line 1223
    .line 1224
    goto :goto_29

    .line 1225
    :cond_1a
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v6

    .line 1229
    :goto_29
    invoke-static {v6}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 1230
    .line 1231
    .line 1232
    move-result-object v4

    .line 1233
    new-instance v6, Lod0/r;

    .line 1234
    .line 1235
    invoke-direct {v6, v0, v2, v3, v4}, Lod0/r;-><init>(Ljava/lang/String;Ljava/lang/Long;Ljava/time/LocalTime;Ljava/time/OffsetDateTime;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 1236
    .line 1237
    .line 1238
    goto :goto_2a

    .line 1239
    :catchall_5
    move-exception v0

    .line 1240
    goto :goto_2b

    .line 1241
    :cond_1b
    :goto_2a
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1242
    .line 1243
    .line 1244
    return-object v6

    .line 1245
    :goto_2b
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1246
    .line 1247
    .line 1248
    throw v0

    .line 1249
    :pswitch_f
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 1250
    .line 1251
    move-object/from16 v1, p1

    .line 1252
    .line 1253
    check-cast v1, Lua/a;

    .line 1254
    .line 1255
    const-string v2, "_connection"

    .line 1256
    .line 1257
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1258
    .line 1259
    .line 1260
    const-string v2, "SELECT * FROM charging_profile WHERE vin = ?"

    .line 1261
    .line 1262
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1263
    .line 1264
    .line 1265
    move-result-object v1

    .line 1266
    const/4 v2, 0x1

    .line 1267
    :try_start_6
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 1268
    .line 1269
    .line 1270
    const-string v0, "id"

    .line 1271
    .line 1272
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1273
    .line 1274
    .line 1275
    move-result v0

    .line 1276
    const-string v3, "profile_id"

    .line 1277
    .line 1278
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1279
    .line 1280
    .line 1281
    move-result v3

    .line 1282
    const-string v4, "vin"

    .line 1283
    .line 1284
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1285
    .line 1286
    .line 1287
    move-result v4

    .line 1288
    const-string v5, "name"

    .line 1289
    .line 1290
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1291
    .line 1292
    .line 1293
    move-result v5

    .line 1294
    const-string v6, "location_lat"

    .line 1295
    .line 1296
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1297
    .line 1298
    .line 1299
    move-result v6

    .line 1300
    const-string v7, "location_lng"

    .line 1301
    .line 1302
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1303
    .line 1304
    .line 1305
    move-result v7

    .line 1306
    const-string v8, "settings_min_battery_charged_state"

    .line 1307
    .line 1308
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1309
    .line 1310
    .line 1311
    move-result v8

    .line 1312
    const-string v9, "settings_target_charged_state"

    .line 1313
    .line 1314
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1315
    .line 1316
    .line 1317
    move-result v9

    .line 1318
    const-string v10, "settings_reduced_current_active"

    .line 1319
    .line 1320
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1321
    .line 1322
    .line 1323
    move-result v10

    .line 1324
    const-string v11, "settings_cable_lock_active"

    .line 1325
    .line 1326
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1327
    .line 1328
    .line 1329
    move-result v11

    .line 1330
    new-instance v12, Ljava/util/ArrayList;

    .line 1331
    .line 1332
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 1333
    .line 1334
    .line 1335
    :goto_2c
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1336
    .line 1337
    .line 1338
    move-result v13

    .line 1339
    if-eqz v13, :cond_26

    .line 1340
    .line 1341
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1342
    .line 1343
    .line 1344
    move-result-wide v15

    .line 1345
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 1346
    .line 1347
    .line 1348
    move-result-wide v17

    .line 1349
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1350
    .line 1351
    .line 1352
    move-result-object v19

    .line 1353
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1354
    .line 1355
    .line 1356
    move-result-object v20

    .line 1357
    invoke-interface {v1, v6}, Lua/c;->isNull(I)Z

    .line 1358
    .line 1359
    .line 1360
    move-result v13

    .line 1361
    if-eqz v13, :cond_1c

    .line 1362
    .line 1363
    invoke-interface {v1, v7}, Lua/c;->isNull(I)Z

    .line 1364
    .line 1365
    .line 1366
    move-result v13

    .line 1367
    if-nez v13, :cond_1d

    .line 1368
    .line 1369
    :cond_1c
    move/from16 p1, v3

    .line 1370
    .line 1371
    goto :goto_2d

    .line 1372
    :cond_1d
    move/from16 p1, v3

    .line 1373
    .line 1374
    move-wide/from16 v21, v15

    .line 1375
    .line 1376
    const/4 v13, 0x0

    .line 1377
    goto :goto_2e

    .line 1378
    :catchall_6
    move-exception v0

    .line 1379
    goto/16 :goto_36

    .line 1380
    .line 1381
    :goto_2d
    invoke-interface {v1, v6}, Lua/c;->getDouble(I)D

    .line 1382
    .line 1383
    .line 1384
    move-result-wide v2

    .line 1385
    move-wide/from16 v21, v15

    .line 1386
    .line 1387
    invoke-interface {v1, v7}, Lua/c;->getDouble(I)D

    .line 1388
    .line 1389
    .line 1390
    move-result-wide v14

    .line 1391
    new-instance v13, Lrd0/p;

    .line 1392
    .line 1393
    invoke-direct {v13, v2, v3, v14, v15}, Lrd0/p;-><init>(DD)V

    .line 1394
    .line 1395
    .line 1396
    :goto_2e
    invoke-interface {v1, v8}, Lua/c;->isNull(I)Z

    .line 1397
    .line 1398
    .line 1399
    move-result v2

    .line 1400
    if-eqz v2, :cond_1e

    .line 1401
    .line 1402
    const/4 v2, 0x0

    .line 1403
    goto :goto_2f

    .line 1404
    :cond_1e
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 1405
    .line 1406
    .line 1407
    move-result-wide v2

    .line 1408
    long-to-int v2, v2

    .line 1409
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1410
    .line 1411
    .line 1412
    move-result-object v2

    .line 1413
    :goto_2f
    invoke-interface {v1, v9}, Lua/c;->isNull(I)Z

    .line 1414
    .line 1415
    .line 1416
    move-result v3

    .line 1417
    if-eqz v3, :cond_1f

    .line 1418
    .line 1419
    const/4 v3, 0x0

    .line 1420
    goto :goto_30

    .line 1421
    :cond_1f
    invoke-interface {v1, v9}, Lua/c;->getLong(I)J

    .line 1422
    .line 1423
    .line 1424
    move-result-wide v14

    .line 1425
    long-to-int v3, v14

    .line 1426
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1427
    .line 1428
    .line 1429
    move-result-object v3

    .line 1430
    :goto_30
    invoke-interface {v1, v10}, Lua/c;->isNull(I)Z

    .line 1431
    .line 1432
    .line 1433
    move-result v14

    .line 1434
    if-eqz v14, :cond_20

    .line 1435
    .line 1436
    const/4 v14, 0x0

    .line 1437
    goto :goto_31

    .line 1438
    :cond_20
    invoke-interface {v1, v10}, Lua/c;->getLong(I)J

    .line 1439
    .line 1440
    .line 1441
    move-result-wide v14

    .line 1442
    long-to-int v14, v14

    .line 1443
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1444
    .line 1445
    .line 1446
    move-result-object v14

    .line 1447
    :goto_31
    const/4 v15, 0x0

    .line 1448
    if-eqz v14, :cond_22

    .line 1449
    .line 1450
    invoke-virtual {v14}, Ljava/lang/Number;->intValue()I

    .line 1451
    .line 1452
    .line 1453
    move-result v14

    .line 1454
    if-eqz v14, :cond_21

    .line 1455
    .line 1456
    const/4 v14, 0x1

    .line 1457
    goto :goto_32

    .line 1458
    :cond_21
    move v14, v15

    .line 1459
    :goto_32
    invoke-static {v14}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1460
    .line 1461
    .line 1462
    move-result-object v14

    .line 1463
    goto :goto_33

    .line 1464
    :cond_22
    const/4 v14, 0x0

    .line 1465
    :goto_33
    invoke-interface {v1, v11}, Lua/c;->isNull(I)Z

    .line 1466
    .line 1467
    .line 1468
    move-result v23

    .line 1469
    if-eqz v23, :cond_23

    .line 1470
    .line 1471
    move/from16 v23, v4

    .line 1472
    .line 1473
    move/from16 v24, v5

    .line 1474
    .line 1475
    const/4 v4, 0x0

    .line 1476
    goto :goto_34

    .line 1477
    :cond_23
    move/from16 v23, v4

    .line 1478
    .line 1479
    move/from16 v24, v5

    .line 1480
    .line 1481
    invoke-interface {v1, v11}, Lua/c;->getLong(I)J

    .line 1482
    .line 1483
    .line 1484
    move-result-wide v4

    .line 1485
    long-to-int v4, v4

    .line 1486
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1487
    .line 1488
    .line 1489
    move-result-object v4

    .line 1490
    :goto_34
    if-eqz v4, :cond_25

    .line 1491
    .line 1492
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 1493
    .line 1494
    .line 1495
    move-result v4

    .line 1496
    if-eqz v4, :cond_24

    .line 1497
    .line 1498
    const/4 v15, 0x1

    .line 1499
    :cond_24
    invoke-static {v15}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1500
    .line 1501
    .line 1502
    move-result-object v4

    .line 1503
    goto :goto_35

    .line 1504
    :cond_25
    const/4 v4, 0x0

    .line 1505
    :goto_35
    new-instance v5, Lod0/m;

    .line 1506
    .line 1507
    invoke-direct {v5, v2, v3, v14, v4}, Lod0/m;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 1508
    .line 1509
    .line 1510
    new-instance v14, Lod0/l;

    .line 1511
    .line 1512
    move-wide/from16 v15, v21

    .line 1513
    .line 1514
    move-object/from16 v22, v5

    .line 1515
    .line 1516
    move-object/from16 v21, v13

    .line 1517
    .line 1518
    invoke-direct/range {v14 .. v22}, Lod0/l;-><init>(JJLjava/lang/String;Ljava/lang/String;Lrd0/p;Lod0/m;)V

    .line 1519
    .line 1520
    .line 1521
    invoke-virtual {v12, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 1522
    .line 1523
    .line 1524
    move/from16 v3, p1

    .line 1525
    .line 1526
    move/from16 v4, v23

    .line 1527
    .line 1528
    move/from16 v5, v24

    .line 1529
    .line 1530
    const/4 v2, 0x1

    .line 1531
    goto/16 :goto_2c

    .line 1532
    .line 1533
    :cond_26
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1534
    .line 1535
    .line 1536
    return-object v12

    .line 1537
    :goto_36
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1538
    .line 1539
    .line 1540
    throw v0

    .line 1541
    :pswitch_10
    iget-object v0, v0, Lod0/d;->e:Ljava/lang/String;

    .line 1542
    .line 1543
    move-object/from16 v1, p1

    .line 1544
    .line 1545
    check-cast v1, Lua/a;

    .line 1546
    .line 1547
    const-string v2, "_connection"

    .line 1548
    .line 1549
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1550
    .line 1551
    .line 1552
    const-string v2, "SELECT * FROM charging WHERE vin = ? LIMIT 1"

    .line 1553
    .line 1554
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1555
    .line 1556
    .line 1557
    move-result-object v1

    .line 1558
    const/4 v2, 0x1

    .line 1559
    :try_start_7
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 1560
    .line 1561
    .line 1562
    const-string v0, "vin"

    .line 1563
    .line 1564
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1565
    .line 1566
    .line 1567
    move-result v0

    .line 1568
    const-string v3, "battery_care_mode"

    .line 1569
    .line 1570
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1571
    .line 1572
    .line 1573
    move-result v3

    .line 1574
    const-string v4, "in_saved_location"

    .line 1575
    .line 1576
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1577
    .line 1578
    .line 1579
    move-result v4

    .line 1580
    const-string v5, "charging_errors"

    .line 1581
    .line 1582
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1583
    .line 1584
    .line 1585
    move-result v5

    .line 1586
    const-string v6, "car_captured_timestamp"

    .line 1587
    .line 1588
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1589
    .line 1590
    .line 1591
    move-result v6

    .line 1592
    const-string v7, "battery_statuscurrent_charged_state"

    .line 1593
    .line 1594
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1595
    .line 1596
    .line 1597
    move-result v7

    .line 1598
    const-string v8, "battery_statuscruising_range_electric"

    .line 1599
    .line 1600
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1601
    .line 1602
    .line 1603
    move-result v8

    .line 1604
    const-string v9, "charging_settings_charge_current"

    .line 1605
    .line 1606
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1607
    .line 1608
    .line 1609
    move-result v9

    .line 1610
    const-string v10, "charging_settings_max_charge_current"

    .line 1611
    .line 1612
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1613
    .line 1614
    .line 1615
    move-result v10

    .line 1616
    const-string v11, "charging_settings_plug_unlock"

    .line 1617
    .line 1618
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1619
    .line 1620
    .line 1621
    move-result v11

    .line 1622
    const-string v12, "charging_settings_target_charged_state"

    .line 1623
    .line 1624
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1625
    .line 1626
    .line 1627
    move-result v12

    .line 1628
    const-string v13, "charging_settings_battery_care_mode_target_value"

    .line 1629
    .line 1630
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1631
    .line 1632
    .line 1633
    move-result v13

    .line 1634
    const-string v14, "charging_status_charging_state"

    .line 1635
    .line 1636
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1637
    .line 1638
    .line 1639
    move-result v14

    .line 1640
    const-string v15, "charging_status_charging_type"

    .line 1641
    .line 1642
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1643
    .line 1644
    .line 1645
    move-result v15

    .line 1646
    const-string v2, "charging_status_charge_power"

    .line 1647
    .line 1648
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1649
    .line 1650
    .line 1651
    move-result v2

    .line 1652
    move/from16 p1, v2

    .line 1653
    .line 1654
    const-string v2, "charging_status_remaining_time_to_complete"

    .line 1655
    .line 1656
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1657
    .line 1658
    .line 1659
    move-result v2

    .line 1660
    move/from16 v16, v2

    .line 1661
    .line 1662
    const-string v2, "charging_status_charging_rate_in_kilometers_per_hour"

    .line 1663
    .line 1664
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1665
    .line 1666
    .line 1667
    move-result v2

    .line 1668
    move/from16 v17, v2

    .line 1669
    .line 1670
    const-string v2, "charge_mode_settings_available_charge_modes"

    .line 1671
    .line 1672
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1673
    .line 1674
    .line 1675
    move-result v2

    .line 1676
    move/from16 v18, v2

    .line 1677
    .line 1678
    const-string v2, "charge_mode_settings_preferred_charge_mode"

    .line 1679
    .line 1680
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1681
    .line 1682
    .line 1683
    move-result v2

    .line 1684
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1685
    .line 1686
    .line 1687
    move-result v19

    .line 1688
    const/16 v20, 0x0

    .line 1689
    .line 1690
    if-eqz v19, :cond_43

    .line 1691
    .line 1692
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1693
    .line 1694
    .line 1695
    move-result-object v22

    .line 1696
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 1697
    .line 1698
    .line 1699
    move-result v0

    .line 1700
    if-eqz v0, :cond_27

    .line 1701
    .line 1702
    move-object/from16 v23, v20

    .line 1703
    .line 1704
    goto :goto_37

    .line 1705
    :cond_27
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1706
    .line 1707
    .line 1708
    move-result-object v0

    .line 1709
    move-object/from16 v23, v0

    .line 1710
    .line 1711
    :goto_37
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 1712
    .line 1713
    .line 1714
    move-result-wide v3

    .line 1715
    long-to-int v0, v3

    .line 1716
    if-eqz v0, :cond_28

    .line 1717
    .line 1718
    const/16 v24, 0x1

    .line 1719
    .line 1720
    goto :goto_38

    .line 1721
    :cond_28
    const/4 v0, 0x0

    .line 1722
    move/from16 v24, v0

    .line 1723
    .line 1724
    :goto_38
    invoke-interface {v1, v5}, Lua/c;->isNull(I)Z

    .line 1725
    .line 1726
    .line 1727
    move-result v0

    .line 1728
    if-eqz v0, :cond_29

    .line 1729
    .line 1730
    move-object/from16 v25, v20

    .line 1731
    .line 1732
    goto :goto_39

    .line 1733
    :cond_29
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1734
    .line 1735
    .line 1736
    move-result-object v0

    .line 1737
    move-object/from16 v25, v0

    .line 1738
    .line 1739
    :goto_39
    invoke-interface {v1, v6}, Lua/c;->isNull(I)Z

    .line 1740
    .line 1741
    .line 1742
    move-result v0

    .line 1743
    if-eqz v0, :cond_2a

    .line 1744
    .line 1745
    move-object/from16 v0, v20

    .line 1746
    .line 1747
    goto :goto_3a

    .line 1748
    :cond_2a
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1749
    .line 1750
    .line 1751
    move-result-object v0

    .line 1752
    :goto_3a
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 1753
    .line 1754
    .line 1755
    move-result-object v30

    .line 1756
    invoke-interface {v1, v7}, Lua/c;->isNull(I)Z

    .line 1757
    .line 1758
    .line 1759
    move-result v0

    .line 1760
    if-eqz v0, :cond_2c

    .line 1761
    .line 1762
    invoke-interface {v1, v8}, Lua/c;->isNull(I)Z

    .line 1763
    .line 1764
    .line 1765
    move-result v0

    .line 1766
    if-nez v0, :cond_2b

    .line 1767
    .line 1768
    goto :goto_3b

    .line 1769
    :cond_2b
    move-object/from16 v26, v20

    .line 1770
    .line 1771
    goto :goto_3e

    .line 1772
    :catchall_7
    move-exception v0

    .line 1773
    goto/16 :goto_55

    .line 1774
    .line 1775
    :cond_2c
    :goto_3b
    invoke-interface {v1, v7}, Lua/c;->isNull(I)Z

    .line 1776
    .line 1777
    .line 1778
    move-result v0

    .line 1779
    if-eqz v0, :cond_2d

    .line 1780
    .line 1781
    move-object/from16 v0, v20

    .line 1782
    .line 1783
    goto :goto_3c

    .line 1784
    :cond_2d
    invoke-interface {v1, v7}, Lua/c;->getLong(I)J

    .line 1785
    .line 1786
    .line 1787
    move-result-wide v3

    .line 1788
    long-to-int v0, v3

    .line 1789
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1790
    .line 1791
    .line 1792
    move-result-object v0

    .line 1793
    :goto_3c
    invoke-interface {v1, v8}, Lua/c;->isNull(I)Z

    .line 1794
    .line 1795
    .line 1796
    move-result v3

    .line 1797
    if-eqz v3, :cond_2e

    .line 1798
    .line 1799
    move-object/from16 v3, v20

    .line 1800
    .line 1801
    goto :goto_3d

    .line 1802
    :cond_2e
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 1803
    .line 1804
    .line 1805
    move-result-wide v3

    .line 1806
    long-to-int v3, v3

    .line 1807
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1808
    .line 1809
    .line 1810
    move-result-object v3

    .line 1811
    :goto_3d
    new-instance v4, Lod0/c;

    .line 1812
    .line 1813
    invoke-direct {v4, v0, v3}, Lod0/c;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 1814
    .line 1815
    .line 1816
    move-object/from16 v26, v4

    .line 1817
    .line 1818
    :goto_3e
    invoke-interface {v1, v9}, Lua/c;->isNull(I)Z

    .line 1819
    .line 1820
    .line 1821
    move-result v0

    .line 1822
    if-eqz v0, :cond_30

    .line 1823
    .line 1824
    invoke-interface {v1, v10}, Lua/c;->isNull(I)Z

    .line 1825
    .line 1826
    .line 1827
    move-result v0

    .line 1828
    if-eqz v0, :cond_30

    .line 1829
    .line 1830
    invoke-interface {v1, v11}, Lua/c;->isNull(I)Z

    .line 1831
    .line 1832
    .line 1833
    move-result v0

    .line 1834
    if-eqz v0, :cond_30

    .line 1835
    .line 1836
    invoke-interface {v1, v12}, Lua/c;->isNull(I)Z

    .line 1837
    .line 1838
    .line 1839
    move-result v0

    .line 1840
    if-eqz v0, :cond_30

    .line 1841
    .line 1842
    invoke-interface {v1, v13}, Lua/c;->isNull(I)Z

    .line 1843
    .line 1844
    .line 1845
    move-result v0

    .line 1846
    if-nez v0, :cond_2f

    .line 1847
    .line 1848
    goto :goto_3f

    .line 1849
    :cond_2f
    move-object/from16 v27, v20

    .line 1850
    .line 1851
    goto :goto_45

    .line 1852
    :cond_30
    :goto_3f
    invoke-interface {v1, v9}, Lua/c;->isNull(I)Z

    .line 1853
    .line 1854
    .line 1855
    move-result v0

    .line 1856
    if-eqz v0, :cond_31

    .line 1857
    .line 1858
    move-object/from16 v7, v20

    .line 1859
    .line 1860
    goto :goto_40

    .line 1861
    :cond_31
    invoke-interface {v1, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1862
    .line 1863
    .line 1864
    move-result-object v0

    .line 1865
    move-object v7, v0

    .line 1866
    :goto_40
    invoke-interface {v1, v10}, Lua/c;->isNull(I)Z

    .line 1867
    .line 1868
    .line 1869
    move-result v0

    .line 1870
    if-eqz v0, :cond_32

    .line 1871
    .line 1872
    move-object/from16 v4, v20

    .line 1873
    .line 1874
    goto :goto_41

    .line 1875
    :cond_32
    invoke-interface {v1, v10}, Lua/c;->getLong(I)J

    .line 1876
    .line 1877
    .line 1878
    move-result-wide v3

    .line 1879
    long-to-int v0, v3

    .line 1880
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1881
    .line 1882
    .line 1883
    move-result-object v0

    .line 1884
    move-object v4, v0

    .line 1885
    :goto_41
    invoke-interface {v1, v11}, Lua/c;->isNull(I)Z

    .line 1886
    .line 1887
    .line 1888
    move-result v0

    .line 1889
    if-eqz v0, :cond_33

    .line 1890
    .line 1891
    move-object/from16 v8, v20

    .line 1892
    .line 1893
    goto :goto_42

    .line 1894
    :cond_33
    invoke-interface {v1, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1895
    .line 1896
    .line 1897
    move-result-object v0

    .line 1898
    move-object v8, v0

    .line 1899
    :goto_42
    invoke-interface {v1, v12}, Lua/c;->isNull(I)Z

    .line 1900
    .line 1901
    .line 1902
    move-result v0

    .line 1903
    if-eqz v0, :cond_34

    .line 1904
    .line 1905
    move-object/from16 v5, v20

    .line 1906
    .line 1907
    goto :goto_43

    .line 1908
    :cond_34
    invoke-interface {v1, v12}, Lua/c;->getLong(I)J

    .line 1909
    .line 1910
    .line 1911
    move-result-wide v5

    .line 1912
    long-to-int v0, v5

    .line 1913
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1914
    .line 1915
    .line 1916
    move-result-object v0

    .line 1917
    move-object v5, v0

    .line 1918
    :goto_43
    invoke-interface {v1, v13}, Lua/c;->isNull(I)Z

    .line 1919
    .line 1920
    .line 1921
    move-result v0

    .line 1922
    if-eqz v0, :cond_35

    .line 1923
    .line 1924
    move-object/from16 v6, v20

    .line 1925
    .line 1926
    goto :goto_44

    .line 1927
    :cond_35
    invoke-interface {v1, v13}, Lua/c;->getLong(I)J

    .line 1928
    .line 1929
    .line 1930
    move-result-wide v9

    .line 1931
    long-to-int v0, v9

    .line 1932
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1933
    .line 1934
    .line 1935
    move-result-object v0

    .line 1936
    move-object v6, v0

    .line 1937
    :goto_44
    new-instance v3, Lod0/s;

    .line 1938
    .line 1939
    invoke-direct/range {v3 .. v8}, Lod0/s;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;)V

    .line 1940
    .line 1941
    .line 1942
    move-object/from16 v27, v3

    .line 1943
    .line 1944
    :goto_45
    invoke-interface {v1, v14}, Lua/c;->isNull(I)Z

    .line 1945
    .line 1946
    .line 1947
    move-result v0

    .line 1948
    if-eqz v0, :cond_39

    .line 1949
    .line 1950
    invoke-interface {v1, v15}, Lua/c;->isNull(I)Z

    .line 1951
    .line 1952
    .line 1953
    move-result v0

    .line 1954
    if-eqz v0, :cond_39

    .line 1955
    .line 1956
    move/from16 v0, p1

    .line 1957
    .line 1958
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 1959
    .line 1960
    .line 1961
    move-result v3

    .line 1962
    if-eqz v3, :cond_38

    .line 1963
    .line 1964
    move/from16 v3, v16

    .line 1965
    .line 1966
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 1967
    .line 1968
    .line 1969
    move-result v4

    .line 1970
    if-eqz v4, :cond_37

    .line 1971
    .line 1972
    move/from16 v4, v17

    .line 1973
    .line 1974
    invoke-interface {v1, v4}, Lua/c;->isNull(I)Z

    .line 1975
    .line 1976
    .line 1977
    move-result v5

    .line 1978
    if-nez v5, :cond_36

    .line 1979
    .line 1980
    goto :goto_49

    .line 1981
    :cond_36
    move-object/from16 v28, v20

    .line 1982
    .line 1983
    :goto_46
    move/from16 v0, v18

    .line 1984
    .line 1985
    goto/16 :goto_4f

    .line 1986
    .line 1987
    :cond_37
    :goto_47
    move/from16 v4, v17

    .line 1988
    .line 1989
    goto :goto_49

    .line 1990
    :cond_38
    :goto_48
    move/from16 v3, v16

    .line 1991
    .line 1992
    goto :goto_47

    .line 1993
    :cond_39
    move/from16 v0, p1

    .line 1994
    .line 1995
    goto :goto_48

    .line 1996
    :goto_49
    invoke-interface {v1, v14}, Lua/c;->isNull(I)Z

    .line 1997
    .line 1998
    .line 1999
    move-result v5

    .line 2000
    if-eqz v5, :cond_3a

    .line 2001
    .line 2002
    move-object/from16 v7, v20

    .line 2003
    .line 2004
    goto :goto_4a

    .line 2005
    :cond_3a
    invoke-interface {v1, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2006
    .line 2007
    .line 2008
    move-result-object v5

    .line 2009
    move-object v7, v5

    .line 2010
    :goto_4a
    invoke-interface {v1, v15}, Lua/c;->isNull(I)Z

    .line 2011
    .line 2012
    .line 2013
    move-result v5

    .line 2014
    if-eqz v5, :cond_3b

    .line 2015
    .line 2016
    move-object/from16 v8, v20

    .line 2017
    .line 2018
    goto :goto_4b

    .line 2019
    :cond_3b
    invoke-interface {v1, v15}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2020
    .line 2021
    .line 2022
    move-result-object v5

    .line 2023
    move-object v8, v5

    .line 2024
    :goto_4b
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 2025
    .line 2026
    .line 2027
    move-result v5

    .line 2028
    if-eqz v5, :cond_3c

    .line 2029
    .line 2030
    move-object/from16 v9, v20

    .line 2031
    .line 2032
    goto :goto_4c

    .line 2033
    :cond_3c
    invoke-interface {v1, v0}, Lua/c;->getDouble(I)D

    .line 2034
    .line 2035
    .line 2036
    move-result-wide v5

    .line 2037
    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2038
    .line 2039
    .line 2040
    move-result-object v0

    .line 2041
    move-object v9, v0

    .line 2042
    :goto_4c
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 2043
    .line 2044
    .line 2045
    move-result v0

    .line 2046
    if-eqz v0, :cond_3d

    .line 2047
    .line 2048
    move-object/from16 v10, v20

    .line 2049
    .line 2050
    goto :goto_4d

    .line 2051
    :cond_3d
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 2052
    .line 2053
    .line 2054
    move-result-wide v5

    .line 2055
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2056
    .line 2057
    .line 2058
    move-result-object v0

    .line 2059
    move-object v10, v0

    .line 2060
    :goto_4d
    invoke-interface {v1, v4}, Lua/c;->isNull(I)Z

    .line 2061
    .line 2062
    .line 2063
    move-result v0

    .line 2064
    if-eqz v0, :cond_3e

    .line 2065
    .line 2066
    move-object/from16 v11, v20

    .line 2067
    .line 2068
    goto :goto_4e

    .line 2069
    :cond_3e
    invoke-interface {v1, v4}, Lua/c;->getDouble(I)D

    .line 2070
    .line 2071
    .line 2072
    move-result-wide v3

    .line 2073
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2074
    .line 2075
    .line 2076
    move-result-object v0

    .line 2077
    move-object v11, v0

    .line 2078
    :goto_4e
    new-instance v6, Lod0/t;

    .line 2079
    .line 2080
    invoke-direct/range {v6 .. v11}, Lod0/t;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Long;Ljava/lang/Double;)V

    .line 2081
    .line 2082
    .line 2083
    move-object/from16 v28, v6

    .line 2084
    .line 2085
    goto :goto_46

    .line 2086
    :goto_4f
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 2087
    .line 2088
    .line 2089
    move-result v3

    .line 2090
    if-eqz v3, :cond_40

    .line 2091
    .line 2092
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 2093
    .line 2094
    .line 2095
    move-result v3

    .line 2096
    if-nez v3, :cond_3f

    .line 2097
    .line 2098
    goto :goto_50

    .line 2099
    :cond_3f
    move-object/from16 v29, v20

    .line 2100
    .line 2101
    goto :goto_54

    .line 2102
    :cond_40
    :goto_50
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 2103
    .line 2104
    .line 2105
    move-result v3

    .line 2106
    if-eqz v3, :cond_41

    .line 2107
    .line 2108
    move-object/from16 v0, v20

    .line 2109
    .line 2110
    goto :goto_51

    .line 2111
    :cond_41
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2112
    .line 2113
    .line 2114
    move-result-object v0

    .line 2115
    :goto_51
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 2116
    .line 2117
    .line 2118
    move-result v3

    .line 2119
    if-eqz v3, :cond_42

    .line 2120
    .line 2121
    :goto_52
    move-object/from16 v2, v20

    .line 2122
    .line 2123
    goto :goto_53

    .line 2124
    :cond_42
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2125
    .line 2126
    .line 2127
    move-result-object v20

    .line 2128
    goto :goto_52

    .line 2129
    :goto_53
    new-instance v3, Lod0/b;

    .line 2130
    .line 2131
    invoke-direct {v3, v0, v2}, Lod0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 2132
    .line 2133
    .line 2134
    move-object/from16 v29, v3

    .line 2135
    .line 2136
    :goto_54
    new-instance v21, Lod0/f;

    .line 2137
    .line 2138
    invoke-direct/range {v21 .. v30}, Lod0/f;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Lod0/c;Lod0/s;Lod0/t;Lod0/b;Ljava/time/OffsetDateTime;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_7

    .line 2139
    .line 2140
    .line 2141
    move-object/from16 v20, v21

    .line 2142
    .line 2143
    :cond_43
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2144
    .line 2145
    .line 2146
    return-object v20

    .line 2147
    :goto_55
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2148
    .line 2149
    .line 2150
    throw v0

    .line 2151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
