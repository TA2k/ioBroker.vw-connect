.class public abstract Ljp/fg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcn0/c;Lij0/a;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lcn0/c;->c:Ljava/lang/String;

    .line 12
    .line 13
    if-eqz p0, :cond_17

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    sparse-switch v0, :sswitch_data_0

    .line 20
    .line 21
    .line 22
    goto/16 :goto_0

    .line 23
    .line 24
    :sswitch_0
    const-string v0, "fail_ignition_on"

    .line 25
    .line 26
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-nez p0, :cond_0

    .line 31
    .line 32
    goto/16 :goto_0

    .line 33
    .line 34
    :cond_0
    const p0, 0x7f120d54

    .line 35
    .line 36
    .line 37
    goto/16 :goto_1

    .line 38
    .line 39
    :sswitch_1
    const-string v0, "fail_battery_conditioning_priority"

    .line 40
    .line 41
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-nez p0, :cond_1

    .line 46
    .line 47
    goto/16 :goto_0

    .line 48
    .line 49
    :cond_1
    const p0, 0x7f120d49

    .line 50
    .line 51
    .line 52
    goto/16 :goto_1

    .line 53
    .line 54
    :sswitch_2
    const-string v0, "fail_fuel_low"

    .line 55
    .line 56
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-nez p0, :cond_2

    .line 61
    .line 62
    goto/16 :goto_0

    .line 63
    .line 64
    :cond_2
    const p0, 0x7f120d52

    .line 65
    .line 66
    .line 67
    goto/16 :goto_1

    .line 68
    .line 69
    :sswitch_3
    const-string v0, "fail_not_parked_correctly"

    .line 70
    .line 71
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    if-nez p0, :cond_3

    .line 76
    .line 77
    goto/16 :goto_0

    .line 78
    .line 79
    :cond_3
    const p0, 0x7f120d58

    .line 80
    .line 81
    .line 82
    goto/16 :goto_1

    .line 83
    .line 84
    :sswitch_4
    const-string v0, "fail_apply_backup"

    .line 85
    .line 86
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    if-nez p0, :cond_4

    .line 91
    .line 92
    goto/16 :goto_0

    .line 93
    .line 94
    :cond_4
    const p0, 0x7f120d48

    .line 95
    .line 96
    .line 97
    goto/16 :goto_1

    .line 98
    .line 99
    :sswitch_5
    const-string v0, "fail_central_locking_problem"

    .line 100
    .line 101
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    if-nez p0, :cond_5

    .line 106
    .line 107
    goto/16 :goto_0

    .line 108
    .line 109
    :cond_5
    const p0, 0x7f120d4b

    .line 110
    .line 111
    .line 112
    goto/16 :goto_1

    .line 113
    .line 114
    :sswitch_6
    const-string v0, "fail_timer_charging_active"

    .line 115
    .line 116
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    if-nez p0, :cond_6

    .line 121
    .line 122
    goto/16 :goto_0

    .line 123
    .line 124
    :cond_6
    const p0, 0x7f120d5e

    .line 125
    .line 126
    .line 127
    goto/16 :goto_1

    .line 128
    .line 129
    :sswitch_7
    const-string v0, "fail_external_power_supply"

    .line 130
    .line 131
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    if-nez p0, :cond_7

    .line 136
    .line 137
    goto/16 :goto_0

    .line 138
    .line 139
    :cond_7
    const p0, 0x7f120d51

    .line 140
    .line 141
    .line 142
    goto/16 :goto_1

    .line 143
    .line 144
    :sswitch_8
    const-string v0, "fail_overtemp_socket"

    .line 145
    .line 146
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    if-nez p0, :cond_8

    .line 151
    .line 152
    goto/16 :goto_0

    .line 153
    .line 154
    :cond_8
    const p0, 0x7f120d59

    .line 155
    .line 156
    .line 157
    goto/16 :goto_1

    .line 158
    .line 159
    :sswitch_9
    const-string v0, "fail_vehicle_is_offline"

    .line 160
    .line 161
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    if-nez p0, :cond_9

    .line 166
    .line 167
    goto/16 :goto_0

    .line 168
    .line 169
    :cond_9
    const p0, 0x7f120d5f

    .line 170
    .line 171
    .line 172
    goto/16 :goto_1

    .line 173
    .line 174
    :sswitch_a
    const-string v0, "fail_key_inside_vehicle"

    .line 175
    .line 176
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result p0

    .line 180
    if-nez p0, :cond_a

    .line 181
    .line 182
    goto/16 :goto_0

    .line 183
    .line 184
    :cond_a
    const p0, 0x7f120d55

    .line 185
    .line 186
    .line 187
    goto/16 :goto_1

    .line 188
    .line 189
    :sswitch_b
    const-string v0, "fail_full_privacy_mode"

    .line 190
    .line 191
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result p0

    .line 195
    if-nez p0, :cond_b

    .line 196
    .line 197
    goto/16 :goto_0

    .line 198
    .line 199
    :cond_b
    const p0, 0x7f120d53

    .line 200
    .line 201
    .line 202
    goto/16 :goto_1

    .line 203
    .line 204
    :sswitch_c
    const-string v0, "fail_no_external_power"

    .line 205
    .line 206
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result p0

    .line 210
    if-nez p0, :cond_c

    .line 211
    .line 212
    goto/16 :goto_0

    .line 213
    .line 214
    :cond_c
    const p0, 0x7f120d57

    .line 215
    .line 216
    .line 217
    goto/16 :goto_1

    .line 218
    .line 219
    :sswitch_d
    const-string v0, "fail_conservation_charging"

    .line 220
    .line 221
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result p0

    .line 225
    if-nez p0, :cond_d

    .line 226
    .line 227
    goto/16 :goto_0

    .line 228
    .line 229
    :cond_d
    const p0, 0x7f120d4f

    .line 230
    .line 231
    .line 232
    goto/16 :goto_1

    .line 233
    .line 234
    :sswitch_e
    const-string v0, "fail_plug_autolock_error"

    .line 235
    .line 236
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result p0

    .line 240
    if-nez p0, :cond_e

    .line 241
    .line 242
    goto/16 :goto_0

    .line 243
    .line 244
    :cond_e
    const p0, 0x7f120d5b

    .line 245
    .line 246
    .line 247
    goto/16 :goto_1

    .line 248
    .line 249
    :sswitch_f
    const-string v0, "fail_charge_plug_not_connected"

    .line 250
    .line 251
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result p0

    .line 255
    if-nez p0, :cond_f

    .line 256
    .line 257
    goto/16 :goto_0

    .line 258
    .line 259
    :cond_f
    const p0, 0x7f120d4d

    .line 260
    .line 261
    .line 262
    goto/16 :goto_1

    .line 263
    .line 264
    :sswitch_10
    const-string v0, "fail_charge_infrastructure"

    .line 265
    .line 266
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result p0

    .line 270
    if-nez p0, :cond_10

    .line 271
    .line 272
    goto/16 :goto_0

    .line 273
    .line 274
    :cond_10
    const p0, 0x7f120d4c

    .line 275
    .line 276
    .line 277
    goto/16 :goto_1

    .line 278
    .line 279
    :sswitch_11
    const-string v0, "fail_parking_break_not_engaged"

    .line 280
    .line 281
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result p0

    .line 285
    if-nez p0, :cond_11

    .line 286
    .line 287
    goto :goto_0

    .line 288
    :cond_11
    const p0, 0x7f120d5a

    .line 289
    .line 290
    .line 291
    goto :goto_1

    .line 292
    :sswitch_12
    const-string v0, "fail_charging_priority"

    .line 293
    .line 294
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    move-result p0

    .line 298
    if-nez p0, :cond_12

    .line 299
    .line 300
    goto :goto_0

    .line 301
    :cond_12
    const p0, 0x7f120d4e

    .line 302
    .line 303
    .line 304
    goto :goto_1

    .line 305
    :sswitch_13
    const-string v0, "fail_plug_disconnected"

    .line 306
    .line 307
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 308
    .line 309
    .line 310
    move-result p0

    .line 311
    if-nez p0, :cond_13

    .line 312
    .line 313
    goto :goto_0

    .line 314
    :cond_13
    const p0, 0x7f120d5c

    .line 315
    .line 316
    .line 317
    goto :goto_1

    .line 318
    :sswitch_14
    const-string v0, "fail_door_open"

    .line 319
    .line 320
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 321
    .line 322
    .line 323
    move-result p0

    .line 324
    if-eqz p0, :cond_17

    .line 325
    .line 326
    const p0, 0x7f120d50

    .line 327
    .line 328
    .line 329
    goto :goto_1

    .line 330
    :sswitch_15
    const-string v0, "fail_misuse_protection"

    .line 331
    .line 332
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 333
    .line 334
    .line 335
    move-result p0

    .line 336
    if-nez p0, :cond_14

    .line 337
    .line 338
    goto :goto_0

    .line 339
    :cond_14
    const p0, 0x7f120d56

    .line 340
    .line 341
    .line 342
    goto :goto_1

    .line 343
    :sswitch_16
    const-string v0, "fail_plug_error"

    .line 344
    .line 345
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 346
    .line 347
    .line 348
    move-result p0

    .line 349
    if-nez p0, :cond_15

    .line 350
    .line 351
    goto :goto_0

    .line 352
    :cond_15
    const p0, 0x7f120d5d

    .line 353
    .line 354
    .line 355
    goto :goto_1

    .line 356
    :sswitch_17
    const-string v0, "fail_battery_low"

    .line 357
    .line 358
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 359
    .line 360
    .line 361
    move-result p0

    .line 362
    if-nez p0, :cond_16

    .line 363
    .line 364
    goto :goto_0

    .line 365
    :cond_16
    const p0, 0x7f120d4a

    .line 366
    .line 367
    .line 368
    goto :goto_1

    .line 369
    :cond_17
    :goto_0
    const p0, 0x7f120d60

    .line 370
    .line 371
    .line 372
    :goto_1
    const/4 v0, 0x0

    .line 373
    new-array v0, v0, [Ljava/lang/Object;

    .line 374
    .line 375
    check-cast p1, Ljj0/f;

    .line 376
    .line 377
    invoke-virtual {p1, p0, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object p0

    .line 381
    return-object p0

    .line 382
    nop

    .line 383
    :sswitch_data_0
    .sparse-switch
        -0x7cf4d57f -> :sswitch_17
        -0x728fa028 -> :sswitch_16
        -0x69e48839 -> :sswitch_15
        -0x553a23a6 -> :sswitch_14
        -0x53b60995 -> :sswitch_13
        -0x5130132f -> :sswitch_12
        -0x4c556a31 -> :sswitch_11
        -0x45d91fd3 -> :sswitch_10
        -0x3fa67eca -> :sswitch_f
        -0x3ce506ed -> :sswitch_e
        -0x39c17f4e -> :sswitch_d
        -0x21057912 -> :sswitch_c
        -0x1ec59f37 -> :sswitch_b
        -0x1c752176 -> :sswitch_a
        -0x16b1067e -> :sswitch_9
        0x61009c9 -> :sswitch_8
        0xc5072fc -> :sswitch_7
        0x151da939 -> :sswitch_6
        0x1db07c4c -> :sswitch_5
        0x261f6b34 -> :sswitch_4
        0x4bf8ff2e -> :sswitch_3
        0x5c1ba54c -> :sswitch_2
        0x67a463e9 -> :sswitch_1
        0x6858bdd0 -> :sswitch_0
    .end sparse-switch
.end method

.method public static final b(Lcn0/c;Lij0/a;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lcn0/c;->e:Lcn0/a;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    packed-switch p0, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    new-instance p0, La8/r0;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :pswitch_0
    const p0, 0x7f120d67

    .line 27
    .line 28
    .line 29
    goto/16 :goto_0

    .line 30
    .line 31
    :pswitch_1
    const p0, 0x7f120d84

    .line 32
    .line 33
    .line 34
    goto/16 :goto_0

    .line 35
    .line 36
    :pswitch_2
    const p0, 0x7f120d61

    .line 37
    .line 38
    .line 39
    goto/16 :goto_0

    .line 40
    .line 41
    :pswitch_3
    const p0, 0x7f120d65

    .line 42
    .line 43
    .line 44
    goto/16 :goto_0

    .line 45
    .line 46
    :pswitch_4
    const p0, 0x7f120d83

    .line 47
    .line 48
    .line 49
    goto/16 :goto_0

    .line 50
    .line 51
    :pswitch_5
    const p0, 0x7f120d82

    .line 52
    .line 53
    .line 54
    goto/16 :goto_0

    .line 55
    .line 56
    :pswitch_6
    const p0, 0x7f120d81

    .line 57
    .line 58
    .line 59
    goto/16 :goto_0

    .line 60
    .line 61
    :pswitch_7
    const p0, 0x7f120d7d

    .line 62
    .line 63
    .line 64
    goto/16 :goto_0

    .line 65
    .line 66
    :pswitch_8
    const p0, 0x7f120d80

    .line 67
    .line 68
    .line 69
    goto/16 :goto_0

    .line 70
    .line 71
    :pswitch_9
    const p0, 0x7f120d7f

    .line 72
    .line 73
    .line 74
    goto/16 :goto_0

    .line 75
    .line 76
    :pswitch_a
    const p0, 0x7f120d78

    .line 77
    .line 78
    .line 79
    goto/16 :goto_0

    .line 80
    .line 81
    :pswitch_b
    const p0, 0x7f120d7a

    .line 82
    .line 83
    .line 84
    goto/16 :goto_0

    .line 85
    .line 86
    :pswitch_c
    const p0, 0x7f120d7e

    .line 87
    .line 88
    .line 89
    goto/16 :goto_0

    .line 90
    .line 91
    :pswitch_d
    const p0, 0x7f120d63

    .line 92
    .line 93
    .line 94
    goto/16 :goto_0

    .line 95
    .line 96
    :pswitch_e
    const p0, 0x7f120d62

    .line 97
    .line 98
    .line 99
    goto/16 :goto_0

    .line 100
    .line 101
    :pswitch_f
    const p0, 0x7f120d7b

    .line 102
    .line 103
    .line 104
    goto :goto_0

    .line 105
    :pswitch_10
    const p0, 0x7f120d7c

    .line 106
    .line 107
    .line 108
    goto :goto_0

    .line 109
    :pswitch_11
    const p0, 0x7f120d79

    .line 110
    .line 111
    .line 112
    goto :goto_0

    .line 113
    :pswitch_12
    const p0, 0x7f120d6d

    .line 114
    .line 115
    .line 116
    goto :goto_0

    .line 117
    :pswitch_13
    const p0, 0x7f120d73

    .line 118
    .line 119
    .line 120
    goto :goto_0

    .line 121
    :pswitch_14
    const p0, 0x7f120d6e

    .line 122
    .line 123
    .line 124
    goto :goto_0

    .line 125
    :pswitch_15
    const p0, 0x7f120d75

    .line 126
    .line 127
    .line 128
    goto :goto_0

    .line 129
    :pswitch_16
    const p0, 0x7f120d70

    .line 130
    .line 131
    .line 132
    goto :goto_0

    .line 133
    :pswitch_17
    const p0, 0x7f120d76

    .line 134
    .line 135
    .line 136
    goto :goto_0

    .line 137
    :pswitch_18
    const p0, 0x7f120d66

    .line 138
    .line 139
    .line 140
    goto :goto_0

    .line 141
    :pswitch_19
    const p0, 0x7f120d64

    .line 142
    .line 143
    .line 144
    goto :goto_0

    .line 145
    :pswitch_1a
    const p0, 0x7f120d71

    .line 146
    .line 147
    .line 148
    goto :goto_0

    .line 149
    :pswitch_1b
    const p0, 0x7f120d6b

    .line 150
    .line 151
    .line 152
    goto :goto_0

    .line 153
    :pswitch_1c
    const p0, 0x7f120d69

    .line 154
    .line 155
    .line 156
    goto :goto_0

    .line 157
    :pswitch_1d
    const p0, 0x7f120d6c

    .line 158
    .line 159
    .line 160
    goto :goto_0

    .line 161
    :pswitch_1e
    const p0, 0x7f120d85

    .line 162
    .line 163
    .line 164
    goto :goto_0

    .line 165
    :pswitch_1f
    const p0, 0x7f120d68

    .line 166
    .line 167
    .line 168
    goto :goto_0

    .line 169
    :pswitch_20
    const p0, 0x7f120d6a

    .line 170
    .line 171
    .line 172
    goto :goto_0

    .line 173
    :pswitch_21
    const p0, 0x7f120d77

    .line 174
    .line 175
    .line 176
    goto :goto_0

    .line 177
    :pswitch_22
    const p0, 0x7f120d72

    .line 178
    .line 179
    .line 180
    goto :goto_0

    .line 181
    :pswitch_23
    const p0, 0x7f120d74

    .line 182
    .line 183
    .line 184
    goto :goto_0

    .line 185
    :pswitch_24
    const p0, 0x7f120d6f

    .line 186
    .line 187
    .line 188
    :goto_0
    const/4 v0, 0x0

    .line 189
    new-array v0, v0, [Ljava/lang/Object;

    .line 190
    .line 191
    check-cast p1, Ljj0/f;

    .line 192
    .line 193
    invoke-virtual {p1, p0, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    return-object p0

    .line 198
    nop

    .line 199
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
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

.method public static final e(Lcn0/c;Ljn0/c;Lij0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    new-instance v0, Lkn0/c;

    .line 2
    .line 3
    invoke-static {p0, p2}, Ljp/fg;->b(Lcn0/c;Lij0/a;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-static {p0, p2}, Ljp/fg;->a(Lcn0/c;Lij0/a;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    const/4 v3, 0x0

    .line 12
    new-array v3, v3, [Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p2, Ljj0/f;

    .line 15
    .line 16
    const v4, 0x7f12038c

    .line 17
    .line 18
    .line 19
    invoke-virtual {p2, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    new-instance v3, Lne0/c;

    .line 24
    .line 25
    new-instance v4, Ljava/lang/Exception;

    .line 26
    .line 27
    iget-object p0, p0, Lcn0/c;->c:Ljava/lang/String;

    .line 28
    .line 29
    invoke-direct {v4, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const/4 v7, 0x0

    .line 33
    const/16 v8, 0x1e

    .line 34
    .line 35
    const/4 v5, 0x0

    .line 36
    const/4 v6, 0x0

    .line 37
    invoke-direct/range {v3 .. v8}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 38
    .line 39
    .line 40
    invoke-direct {v0, v1, v2, p2, v3}, Lkn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lne0/c;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, v0, p3}, Ljn0/c;->b(Lkn0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 48
    .line 49
    if-ne p0, p1, :cond_0

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    return-object p0
.end method

.method public static f(Lcn0/c;Lrq0/f;Ljn0/c;Lyt0/b;Lij0/a;Lvy0/b0;Lay0/a;Lay0/k;Lay0/a;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v4, p4

    .line 4
    .line 5
    move-object/from16 v0, p9

    .line 6
    .line 7
    move/from16 v1, p10

    .line 8
    .line 9
    and-int/lit8 v2, v1, 0x20

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    new-instance v2, Lz81/g;

    .line 14
    .line 15
    const/4 v5, 0x2

    .line 16
    invoke-direct {v2, v5}, Lz81/g;-><init>(I)V

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move-object/from16 v2, p6

    .line 21
    .line 22
    :goto_0
    and-int/lit8 v5, v1, 0x40

    .line 23
    .line 24
    if-eqz v5, :cond_1

    .line 25
    .line 26
    new-instance v5, Lw81/d;

    .line 27
    .line 28
    const/16 v6, 0x8

    .line 29
    .line 30
    invoke-direct {v5, v6}, Lw81/d;-><init>(I)V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move-object/from16 v5, p7

    .line 35
    .line 36
    :goto_1
    and-int/lit16 v6, v1, 0x80

    .line 37
    .line 38
    const/4 v7, 0x1

    .line 39
    if-eqz v6, :cond_2

    .line 40
    .line 41
    const/4 v6, 0x0

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move v6, v7

    .line 44
    :goto_2
    and-int/lit16 v1, v1, 0x100

    .line 45
    .line 46
    if-eqz v1, :cond_3

    .line 47
    .line 48
    new-instance v1, Lz81/g;

    .line 49
    .line 50
    const/4 v8, 0x2

    .line 51
    invoke-direct {v1, v8}, Lz81/g;-><init>(I)V

    .line 52
    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_3
    move-object/from16 v1, p8

    .line 56
    .line 57
    :goto_3
    iget-object v8, v3, Lcn0/c;->b:Lcn0/b;

    .line 58
    .line 59
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 60
    .line 61
    .line 62
    move-result v8

    .line 63
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    if-eqz v8, :cond_9

    .line 66
    .line 67
    const/4 v10, 0x3

    .line 68
    if-eq v8, v7, :cond_6

    .line 69
    .line 70
    const/4 v2, 0x2

    .line 71
    if-eq v8, v2, :cond_5

    .line 72
    .line 73
    if-ne v8, v10, :cond_4

    .line 74
    .line 75
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 76
    .line 77
    invoke-interface {v5, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-object/from16 v1, p2

    .line 84
    .line 85
    invoke-static {v3, v1, v4, v0}, Ljp/fg;->e(Lcn0/c;Ljn0/c;Lij0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 90
    .line 91
    if-ne v0, v1, :cond_7

    .line 92
    .line 93
    return-object v0

    .line 94
    :cond_4
    new-instance v0, La8/r0;

    .line 95
    .line 96
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 97
    .line 98
    .line 99
    throw v0

    .line 100
    :cond_5
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 101
    .line 102
    invoke-interface {v5, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    new-instance v10, Lzt0/a;

    .line 106
    .line 107
    invoke-static {v3, v4}, Ljp/fg;->g(Lcn0/c;Lij0/a;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v11

    .line 111
    invoke-static {v3, v4}, Ljp/fg;->i(Lcn0/c;Lij0/a;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v13

    .line 115
    const/4 v15, 0x0

    .line 116
    const/16 v12, 0x3c

    .line 117
    .line 118
    const/4 v14, 0x0

    .line 119
    invoke-direct/range {v10 .. v15}, Lzt0/a;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    move-object/from16 v1, p3

    .line 123
    .line 124
    invoke-virtual {v1, v10, v0}, Lyt0/b;->b(Lzt0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 129
    .line 130
    if-ne v0, v1, :cond_7

    .line 131
    .line 132
    return-object v0

    .line 133
    :cond_6
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 134
    .line 135
    invoke-interface {v5, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    sget-object v0, Lcn0/a;->d:Lcn0/a;

    .line 139
    .line 140
    sget-object v1, Lcn0/a;->e:Lcn0/a;

    .line 141
    .line 142
    filled-new-array {v0, v1}, [Lcn0/a;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    iget-object v1, v3, Lcn0/c;->e:Lcn0/a;

    .line 151
    .line 152
    invoke-interface {v0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    if-eqz v0, :cond_8

    .line 157
    .line 158
    if-nez v6, :cond_8

    .line 159
    .line 160
    :cond_7
    return-object v9

    .line 161
    :cond_8
    new-instance v0, La7/o;

    .line 162
    .line 163
    const/16 v1, 0x1d

    .line 164
    .line 165
    const/4 v5, 0x0

    .line 166
    move-object/from16 v2, p1

    .line 167
    .line 168
    invoke-direct/range {v0 .. v5}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 169
    .line 170
    .line 171
    move-object v1, v0

    .line 172
    move-object/from16 v0, p5

    .line 173
    .line 174
    invoke-static {v0, v5, v5, v1, v10}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 175
    .line 176
    .line 177
    return-object v9

    .line 178
    :cond_9
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    return-object v9
.end method

.method public static final g(Lcn0/c;Lij0/a;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0}, Ljp/fg;->h(Lcn0/c;)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    const/4 v0, 0x0

    .line 16
    new-array v0, v0, [Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p1, Ljj0/f;

    .line 19
    .line 20
    invoke-virtual {p1, p0, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public static final h(Lcn0/c;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcn0/c;->e:Lcn0/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    packed-switch p0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    new-instance p0, La8/r0;

    .line 16
    .line 17
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 18
    .line 19
    .line 20
    throw p0

    .line 21
    :pswitch_0
    const p0, 0x7f120d8b

    .line 22
    .line 23
    .line 24
    return p0

    .line 25
    :pswitch_1
    const p0, 0x7f120da8

    .line 26
    .line 27
    .line 28
    return p0

    .line 29
    :pswitch_2
    const p0, 0x7f121558

    .line 30
    .line 31
    .line 32
    return p0

    .line 33
    :pswitch_3
    const p0, 0x7f120d89

    .line 34
    .line 35
    .line 36
    return p0

    .line 37
    :pswitch_4
    const p0, 0x7f120da7

    .line 38
    .line 39
    .line 40
    return p0

    .line 41
    :pswitch_5
    const p0, 0x7f120da6

    .line 42
    .line 43
    .line 44
    return p0

    .line 45
    :pswitch_6
    const p0, 0x7f120d9e

    .line 46
    .line 47
    .line 48
    return p0

    .line 49
    :pswitch_7
    const p0, 0x7f120da4

    .line 50
    .line 51
    .line 52
    return p0

    .line 53
    :pswitch_8
    const p0, 0x7f120d8a

    .line 54
    .line 55
    .line 56
    return p0

    .line 57
    :pswitch_9
    const p0, 0x7f120d88

    .line 58
    .line 59
    .line 60
    return p0

    .line 61
    :pswitch_a
    const p0, 0x7f120d9f

    .line 62
    .line 63
    .line 64
    return p0

    .line 65
    :pswitch_b
    const p0, 0x7f120da1

    .line 66
    .line 67
    .line 68
    return p0

    .line 69
    :pswitch_c
    const p0, 0x7f120da5

    .line 70
    .line 71
    .line 72
    return p0

    .line 73
    :pswitch_d
    const p0, 0x7f120d87

    .line 74
    .line 75
    .line 76
    return p0

    .line 77
    :pswitch_e
    const p0, 0x7f120d86

    .line 78
    .line 79
    .line 80
    return p0

    .line 81
    :pswitch_f
    const p0, 0x7f120da2

    .line 82
    .line 83
    .line 84
    return p0

    .line 85
    :pswitch_10
    const p0, 0x7f120da3

    .line 86
    .line 87
    .line 88
    return p0

    .line 89
    :pswitch_11
    const p0, 0x7f120da0

    .line 90
    .line 91
    .line 92
    return p0

    .line 93
    :pswitch_12
    const p0, 0x7f120d91

    .line 94
    .line 95
    .line 96
    return p0

    .line 97
    :pswitch_13
    const p0, 0x7f120d99

    .line 98
    .line 99
    .line 100
    return p0

    .line 101
    :pswitch_14
    const p0, 0x7f120d92

    .line 102
    .line 103
    .line 104
    return p0

    .line 105
    :pswitch_15
    const p0, 0x7f120d9b

    .line 106
    .line 107
    .line 108
    return p0

    .line 109
    :pswitch_16
    const p0, 0x7f120d94

    .line 110
    .line 111
    .line 112
    return p0

    .line 113
    :pswitch_17
    const p0, 0x7f120d9c

    .line 114
    .line 115
    .line 116
    return p0

    .line 117
    :pswitch_18
    const p0, 0x7f120d97

    .line 118
    .line 119
    .line 120
    return p0

    .line 121
    :pswitch_19
    const p0, 0x7f120d96

    .line 122
    .line 123
    .line 124
    return p0

    .line 125
    :pswitch_1a
    const p0, 0x7f120d95

    .line 126
    .line 127
    .line 128
    return p0

    .line 129
    :pswitch_1b
    const p0, 0x7f120d8f

    .line 130
    .line 131
    .line 132
    return p0

    .line 133
    :pswitch_1c
    const p0, 0x7f120d8d

    .line 134
    .line 135
    .line 136
    return p0

    .line 137
    :pswitch_1d
    const p0, 0x7f120d90

    .line 138
    .line 139
    .line 140
    return p0

    .line 141
    :pswitch_1e
    const p0, 0x7f120da9

    .line 142
    .line 143
    .line 144
    return p0

    .line 145
    :pswitch_1f
    const p0, 0x7f120d8c

    .line 146
    .line 147
    .line 148
    return p0

    .line 149
    :pswitch_20
    const p0, 0x7f120d8e

    .line 150
    .line 151
    .line 152
    return p0

    .line 153
    :pswitch_21
    const p0, 0x7f120d9d

    .line 154
    .line 155
    .line 156
    return p0

    .line 157
    :pswitch_22
    const p0, 0x7f120d98

    .line 158
    .line 159
    .line 160
    return p0

    .line 161
    :pswitch_23
    const p0, 0x7f120d9a

    .line 162
    .line 163
    .line 164
    return p0

    .line 165
    :pswitch_24
    const p0, 0x7f120d93

    .line 166
    .line 167
    .line 168
    return p0

    .line 169
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
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

.method public static final i(Lcn0/c;Lij0/a;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lcn0/c;->c:Ljava/lang/String;

    .line 12
    .line 13
    if-eqz p0, :cond_5

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const v1, -0x7cfca474

    .line 20
    .line 21
    .line 22
    if-eq v0, v1, :cond_4

    .line 23
    .line 24
    const v1, -0x41f94658

    .line 25
    .line 26
    .line 27
    if-eq v0, v1, :cond_2

    .line 28
    .line 29
    const v1, 0x7313c619

    .line 30
    .line 31
    .line 32
    if-eq v0, v1, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const-string v0, "warning_insufficient_battery_level"

    .line 36
    .line 37
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-nez p0, :cond_1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    const p0, 0x7f120dac

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    const-string v0, "warning_daily_power_budget"

    .line 49
    .line 50
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_3

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_3
    const p0, 0x7f120daa

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_4
    const-string v0, "warning_slow_charging"

    .line 62
    .line 63
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    if-eqz p0, :cond_5

    .line 68
    .line 69
    const p0, 0x7f120dad

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_5
    :goto_0
    const p0, 0x7f120dab

    .line 74
    .line 75
    .line 76
    :goto_1
    const/4 v0, 0x0

    .line 77
    new-array v0, v0, [Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p1, Ljj0/f;

    .line 80
    .line 81
    invoke-virtual {p1, p0, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0
.end method


# virtual methods
.method public c()Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public d()Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method
