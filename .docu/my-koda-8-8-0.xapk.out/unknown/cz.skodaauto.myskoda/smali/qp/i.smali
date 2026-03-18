.class public abstract Lqp/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Z = false

.field public static b:I = 0x1


# direct methods
.method public static final a(Lly/b;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const-string v0, "App start"

    .line 11
    .line 12
    const-string v1, "Charge limit"

    .line 13
    .line 14
    packed-switch p0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    new-instance p0, La8/r0;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :pswitch_0
    const-string p0, "Connectivity Sunset - profile"

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_1
    const-string p0, "Connectivity Sunset - home"

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_2
    const-string p0, "Online Remote Update - Overview"

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_3
    const-string p0, "Battery protection info"

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_4
    const-string p0, "App rating feedback"

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_5
    const-string p0, "AI Trip - Stopover Detail"

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_6
    const-string p0, "AI Trip - Journey"

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_7
    const-string p0, "AI Trip - Preferences"

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_8
    const-string p0, "AI Trip - Interests"

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_9
    const-string p0, "AI Trip - Route Planning"

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_a
    const-string p0, "AI Trip - Intro"

    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_b
    const-string p0, "Driving Score - Driving Tips"

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_c
    const-string p0, "Driving Score - Overview"

    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_d
    const-string p0, "Test drive - outro"

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_e
    const-string p0, "Test drive - summary"

    .line 66
    .line 67
    return-object p0

    .line 68
    :pswitch_f
    const-string p0, "Test drive - contact details"

    .line 69
    .line 70
    return-object p0

    .line 71
    :pswitch_10
    const-string p0, "Test drive - date and time selection"

    .line 72
    .line 73
    return-object p0

    .line 74
    :pswitch_11
    const-string p0, "Test drive - dealer selection"

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_12
    const-string p0, "Test drive - model selection"

    .line 78
    .line 79
    return-object p0

    .line 80
    :pswitch_13
    const-string p0, "Test drive - intro"

    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_14
    const-string p0, "Vehicle - Remote Park Assist - Where to find QR"

    .line 84
    .line 85
    return-object p0

    .line 86
    :pswitch_15
    const-string p0, "Vehicle - Remote Park Assist"

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_16
    const-string p0, "Loyalty program - Voucher - congratulations"

    .line 90
    .line 91
    return-object p0

    .line 92
    :pswitch_17
    const-string p0, "Loyalty program - Voucher - purchased detail"

    .line 93
    .line 94
    return-object p0

    .line 95
    :pswitch_18
    const-string p0, "Loyalty program - Voucher - confirmation"

    .line 96
    .line 97
    return-object p0

    .line 98
    :pswitch_19
    const-string p0, "Loyalty program - Voucher - detail"

    .line 99
    .line 100
    return-object p0

    .line 101
    :pswitch_1a
    const-string p0, "Loyalty program - Lucky Draw - you\'re in"

    .line 102
    .line 103
    return-object p0

    .line 104
    :pswitch_1b
    const-string p0, "Loyalty program - Lucky Draw - detail"

    .line 105
    .line 106
    return-object p0

    .line 107
    :pswitch_1c
    const-string p0, "Loyalty program - Lucky Draw - list"

    .line 108
    .line 109
    return-object p0

    .line 110
    :pswitch_1d
    const-string p0, "Loyalty program - Badges - detail"

    .line 111
    .line 112
    return-object p0

    .line 113
    :pswitch_1e
    const-string p0, "Loyalty program - Badges - list"

    .line 114
    .line 115
    return-object p0

    .line 116
    :pswitch_1f
    const-string p0, "Loyalty program - Badges - congratulations"

    .line 117
    .line 118
    return-object p0

    .line 119
    :pswitch_20
    const-string p0, "Loyalty program - Badges - intro"

    .line 120
    .line 121
    return-object p0

    .line 122
    :pswitch_21
    const-string p0, "Loyalty program - Challenge - failed"

    .line 123
    .line 124
    return-object p0

    .line 125
    :pswitch_22
    const-string p0, "Loyalty program - Reward - congratulations"

    .line 126
    .line 127
    return-object p0

    .line 128
    :pswitch_23
    const-string p0, "Loyalty program - Challenge - completed"

    .line 129
    .line 130
    return-object p0

    .line 131
    :pswitch_24
    const-string p0, "Loyalty program - Reward - pickup"

    .line 132
    .line 133
    return-object p0

    .line 134
    :pswitch_25
    const-string p0, "Loyalty program - Badges - collected"

    .line 135
    .line 136
    return-object p0

    .line 137
    :pswitch_26
    const-string p0, "Loyalty program - Reward - Service Partner - detail"

    .line 138
    .line 139
    return-object p0

    .line 140
    :pswitch_27
    const-string p0, "Loyalty program - Reward - confirmation"

    .line 141
    .line 142
    return-object p0

    .line 143
    :pswitch_28
    const-string p0, "Loyalty program - Overview - history"

    .line 144
    .line 145
    return-object p0

    .line 146
    :pswitch_29
    const-string p0, "Loyalty program - Welcome"

    .line 147
    .line 148
    return-object p0

    .line 149
    :pswitch_2a
    const-string p0, "Loyalty program - Reward - claimed detail"

    .line 150
    .line 151
    return-object p0

    .line 152
    :pswitch_2b
    const-string p0, "Loyalty program - Reward - detail"

    .line 153
    .line 154
    return-object p0

    .line 155
    :pswitch_2c
    const-string p0, "Loyalty program - Congratulations"

    .line 156
    .line 157
    return-object p0

    .line 158
    :pswitch_2d
    const-string p0, "Loyalty program - Challenge - detail"

    .line 159
    .line 160
    return-object p0

    .line 161
    :pswitch_2e
    const-string p0, "Loyalty program - Referral code"

    .line 162
    .line 163
    return-object p0

    .line 164
    :pswitch_2f
    const-string p0, "Loyalty program - Intro"

    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_30
    const-string p0, "Loyalty program"

    .line 168
    .line 169
    return-object p0

    .line 170
    :pswitch_31
    const-string p0, "Security - Root Check"

    .line 171
    .line 172
    return-object p0

    .line 173
    :pswitch_32
    const-string p0, "Vehicle - Trip Statistics - Trip history"

    .line 174
    .line 175
    return-object p0

    .line 176
    :pswitch_33
    const-string p0, "Vehicle - Trip Statistics - Trip history - detail"

    .line 177
    .line 178
    return-object p0

    .line 179
    :pswitch_34
    const-string p0, "Vehicle - Trip Statistics - Fuel Logbook - add price"

    .line 180
    .line 181
    return-object p0

    .line 182
    :pswitch_35
    const-string p0, "Vehicle - Trip Statistics - Fuel Logbook"

    .line 183
    .line 184
    return-object p0

    .line 185
    :pswitch_36
    const-string p0, "Vehicle - Trip Statistics"

    .line 186
    .line 187
    return-object p0

    .line 188
    :pswitch_37
    const-string p0, "Vehicle - Range ICE"

    .line 189
    .line 190
    return-object p0

    .line 191
    :pswitch_38
    const-string p0, "Vehicle - Wakeup"

    .line 192
    .line 193
    return-object p0

    .line 194
    :pswitch_39
    const-string p0, "Vehicle fleet info"

    .line 195
    .line 196
    return-object p0

    .line 197
    :pswitch_3a
    const-string p0, "Software update info"

    .line 198
    .line 199
    return-object p0

    .line 200
    :pswitch_3b
    const-string p0, "Vehicle connection status info"

    .line 201
    .line 202
    return-object p0

    .line 203
    :pswitch_3c
    const-string p0, "Vehicle - Car details - how to videos"

    .line 204
    .line 205
    return-object p0

    .line 206
    :pswitch_3d
    const-string p0, "Vehicle - How To - video"

    .line 207
    .line 208
    return-object p0

    .line 209
    :pswitch_3e
    const-string p0, "Vehicle - How To - videos list"

    .line 210
    .line 211
    return-object p0

    .line 212
    :pswitch_3f
    const-string p0, "Vehicle - To Do - detail"

    .line 213
    .line 214
    return-object p0

    .line 215
    :pswitch_40
    const-string p0, "Vehicle - Order - Detail"

    .line 216
    .line 217
    return-object p0

    .line 218
    :pswitch_41
    const-string p0, "Vehicle - Doors and Lights"

    .line 219
    .line 220
    return-object p0

    .line 221
    :pswitch_42
    const-string p0, "Vehicle Backups"

    .line 222
    .line 223
    return-object p0

    .line 224
    :pswitch_43
    const-string p0, "Images preview"

    .line 225
    .line 226
    return-object p0

    .line 227
    :pswitch_44
    const-string p0, "Vehicle - Order - Car details"

    .line 228
    .line 229
    return-object p0

    .line 230
    :pswitch_45
    const-string p0, "Vehicle - Car details"

    .line 231
    .line 232
    return-object p0

    .line 233
    :pswitch_46
    const-string p0, "Vehicle - Care & Insurance - consent"

    .line 234
    .line 235
    return-object p0

    .line 236
    :pswitch_47
    const-string p0, "Vehicle - Care & Insurance - detail"

    .line 237
    .line 238
    return-object p0

    .line 239
    :pswitch_48
    const-string p0, "Vehicle - Care & Insurance - legal information"

    .line 240
    .line 241
    return-object p0

    .line 242
    :pswitch_49
    const-string p0, "Vehicle - Paid Services - Data Plan Detail"

    .line 243
    .line 244
    return-object p0

    .line 245
    :pswitch_4a
    const-string p0, "Vehicle - Paid Services - Data Plan Intro"

    .line 246
    .line 247
    return-object p0

    .line 248
    :pswitch_4b
    const-string p0, "Vehicle - Paid Services - detail"

    .line 249
    .line 250
    return-object p0

    .line 251
    :pswitch_4c
    const-string p0, "Vehicle - Paid Services - Data services"

    .line 252
    .line 253
    return-object p0

    .line 254
    :pswitch_4d
    const-string p0, "Vehicle - Paid Services"

    .line 255
    .line 256
    return-object p0

    .line 257
    :pswitch_4e
    const-string p0, "Departure time"

    .line 258
    .line 259
    return-object p0

    .line 260
    :pswitch_4f
    const-string p0, "Preferred charging times"

    .line 261
    .line 262
    return-object p0

    .line 263
    :pswitch_50
    return-object v1

    .line 264
    :pswitch_51
    const-string p0, "Vehicle - Service Booking"

    .line 265
    .line 266
    return-object p0

    .line 267
    :pswitch_52
    const-string p0, "Vehicle - Service Partner - booking detail"

    .line 268
    .line 269
    return-object p0

    .line 270
    :pswitch_53
    const-string p0, "Vehicle - Service Partner - booking history"

    .line 271
    .line 272
    return-object p0

    .line 273
    :pswitch_54
    const-string p0, "Vehicle - Service Partner - detail"

    .line 274
    .line 275
    return-object p0

    .line 276
    :pswitch_55
    const-string p0, "Vehicle - Service Partner - booking appointment"

    .line 277
    .line 278
    return-object p0

    .line 279
    :pswitch_56
    const-string p0, "Vehicle - Service Partner - booking"

    .line 280
    .line 281
    return-object p0

    .line 282
    :pswitch_57
    const-string p0, "Vehicle - Service Partner - search"

    .line 283
    .line 284
    return-object p0

    .line 285
    :pswitch_58
    const-string p0, "Vehicle - Service Partner"

    .line 286
    .line 287
    return-object p0

    .line 288
    :pswitch_59
    const-string p0, "Vehicle - Order - Congratulations"

    .line 289
    .line 290
    return-object p0

    .line 291
    :pswitch_5a
    const-string p0, "Profile"

    .line 292
    .line 293
    return-object p0

    .line 294
    :pswitch_5b
    const-string p0, "Powerpass - Remote Authorization Flow"

    .line 295
    .line 296
    return-object p0

    .line 297
    :pswitch_5c
    const-string p0, "Powerpass - Wallboxes Flow"

    .line 298
    .line 299
    return-object p0

    .line 300
    :pswitch_5d
    const-string p0, "Powerpass - Subscribe Management Flow"

    .line 301
    .line 302
    return-object p0

    .line 303
    :pswitch_5e
    const-string p0, "Powerpass - Subscribe Flow"

    .line 304
    .line 305
    return-object p0

    .line 306
    :pswitch_5f
    const-string p0, "Powerpass - Plug and charge Flow"

    .line 307
    .line 308
    return-object p0

    .line 309
    :pswitch_60
    const-string p0, "Powerpass - Payment methods Flow"

    .line 310
    .line 311
    return-object p0

    .line 312
    :pswitch_61
    const-string p0, "Powerpass - Invoices Flow"

    .line 313
    .line 314
    return-object p0

    .line 315
    :pswitch_62
    const-string p0, "Powerpass - Flow screen"

    .line 316
    .line 317
    return-object p0

    .line 318
    :pswitch_63
    const-string p0, "Powerpass - Coupons Flow"

    .line 319
    .line 320
    return-object p0

    .line 321
    :pswitch_64
    const-string p0, "Powerpass - Consents Flow"

    .line 322
    .line 323
    return-object p0

    .line 324
    :pswitch_65
    const-string p0, "Powerpass - Charging statistics Flow"

    .line 325
    .line 326
    return-object p0

    .line 327
    :pswitch_66
    const-string p0, "Powerpass - Charging history Flow"

    .line 328
    .line 329
    return-object p0

    .line 330
    :pswitch_67
    const-string p0, "Powerpass - Charging card Flow"

    .line 331
    .line 332
    return-object p0

    .line 333
    :pswitch_68
    const-string p0, "PayToFuel - Summary Error"

    .line 334
    .line 335
    return-object p0

    .line 336
    :pswitch_69
    const-string p0, "PayToFuel - Summary"

    .line 337
    .line 338
    return-object p0

    .line 339
    :pswitch_6a
    const-string p0, "PayToFuel - Disclaimer"

    .line 340
    .line 341
    return-object p0

    .line 342
    :pswitch_6b
    const-string p0, "PayToFuel - Terms and Conditions"

    .line 343
    .line 344
    return-object p0

    .line 345
    :pswitch_6c
    const-string p0, "PayToFuel - Start Fuelling Session"

    .line 346
    .line 347
    return-object p0

    .line 348
    :pswitch_6d
    const-string p0, "Park-Fuel - Area Specific Message"

    .line 349
    .line 350
    return-object p0

    .line 351
    :pswitch_6e
    const-string p0, "Park-Fuel - Multiple choice"

    .line 352
    .line 353
    return-object p0

    .line 354
    :pswitch_6f
    const-string p0, "PayToPark - Start Session"

    .line 355
    .line 356
    return-object p0

    .line 357
    :pswitch_70
    const-string p0, "PayToPark - Session Detail"

    .line 358
    .line 359
    return-object p0

    .line 360
    :pswitch_71
    const-string p0, "Park-Fuel - History"

    .line 361
    .line 362
    return-object p0

    .line 363
    :pswitch_72
    const-string p0, "Park-Fuel - User Panel"

    .line 364
    .line 365
    return-object p0

    .line 366
    :pswitch_73
    const-string p0, "Park-Fuel - Services Coverage"

    .line 367
    .line 368
    return-object p0

    .line 369
    :pswitch_74
    const-string p0, "Park-Fuel - License Plate"

    .line 370
    .line 371
    return-object p0

    .line 372
    :pswitch_75
    const-string p0, "Park-Fuel - Consent"

    .line 373
    .line 374
    return-object p0

    .line 375
    :pswitch_76
    const-string p0, "Park-Fuel - Card enrollment"

    .line 376
    .line 377
    return-object p0

    .line 378
    :pswitch_77
    const-string p0, "Park-Fuel - Billing Address"

    .line 379
    .line 380
    return-object p0

    .line 381
    :pswitch_78
    const-string p0, "Park-Fuel - Account Details"

    .line 382
    .line 383
    return-object p0

    .line 384
    :pswitch_79
    const-string p0, "MDK - Detail"

    .line 385
    .line 386
    return-object p0

    .line 387
    :pswitch_7a
    const-string p0, "MDK - Service Card Deactivate Success"

    .line 388
    .line 389
    return-object p0

    .line 390
    :pswitch_7b
    const-string p0, "MDK - Service Card Deactivate"

    .line 391
    .line 392
    return-object p0

    .line 393
    :pswitch_7c
    const-string p0, "MDK - Service Card Info"

    .line 394
    .line 395
    return-object p0

    .line 396
    :pswitch_7d
    const-string p0, "MDK - How To"

    .line 397
    .line 398
    return-object p0

    .line 399
    :pswitch_7e
    const-string p0, "MDK - Missing Device"

    .line 400
    .line 401
    return-object p0

    .line 402
    :pswitch_7f
    const-string p0, "MDK - Pairing Success"

    .line 403
    .line 404
    return-object p0

    .line 405
    :pswitch_80
    const-string p0, "MDK - Unpairing Success"

    .line 406
    .line 407
    return-object p0

    .line 408
    :pswitch_81
    const-string p0, "MDK - Unpairing"

    .line 409
    .line 410
    return-object p0

    .line 411
    :pswitch_82
    const-string p0, "MDK - Pairing"

    .line 412
    .line 413
    return-object p0

    .line 414
    :pswitch_83
    const-string p0, "MDK - Home"

    .line 415
    .line 416
    return-object p0

    .line 417
    :pswitch_84
    const-string p0, "Vehicle - Notifications - Settings"

    .line 418
    .line 419
    return-object p0

    .line 420
    :pswitch_85
    const-string p0, "Vehicle - Message center - Messages - detail"

    .line 421
    .line 422
    return-object p0

    .line 423
    :pswitch_86
    const-string p0, "Vehicle - Message center - Messages - list"

    .line 424
    .line 425
    return-object p0

    .line 426
    :pswitch_87
    const-string p0, "Maps - Active route"

    .line 427
    .line 428
    return-object p0

    .line 429
    :pswitch_88
    const-string p0, "Maps - Laura route edit"

    .line 430
    .line 431
    return-object p0

    .line 432
    :pswitch_89
    const-string p0, "Maps - Offer - Detail"

    .line 433
    .line 434
    return-object p0

    .line 435
    :pswitch_8a
    const-string p0, "Maps - Select stop"

    .line 436
    .line 437
    return-object p0

    .line 438
    :pswitch_8b
    const-string p0, "Maps - Search - Parking"

    .line 439
    .line 440
    return-object p0

    .line 441
    :pswitch_8c
    const-string p0, "Maps - Search - Gas stations"

    .line 442
    .line 443
    return-object p0

    .line 444
    :pswitch_8d
    const-string p0, "Maps - Search - Chargers"

    .line 445
    .line 446
    return-object p0

    .line 447
    :pswitch_8e
    const-string p0, "Maps - Search - Detail"

    .line 448
    .line 449
    return-object p0

    .line 450
    :pswitch_8f
    const-string p0, "Maps - Search - History"

    .line 451
    .line 452
    return-object p0

    .line 453
    :pswitch_90
    const-string p0, "Maps - Search"

    .line 454
    .line 455
    return-object p0

    .line 456
    :pswitch_91
    const-string p0, "Maps - Route settings"

    .line 457
    .line 458
    return-object p0

    .line 459
    :pswitch_92
    const-string p0, "Maps - Battery levels"

    .line 460
    .line 461
    return-object p0

    .line 462
    :pswitch_93
    const-string p0, "Maps - Route edit"

    .line 463
    .line 464
    return-object p0

    .line 465
    :pswitch_94
    const-string p0, "Maps - Route detail"

    .line 466
    .line 467
    return-object p0

    .line 468
    :pswitch_95
    const-string p0, "Maps - Poi picker"

    .line 469
    .line 470
    return-object p0

    .line 471
    :pswitch_96
    const-string p0, "Maps - Charging stations - detail"

    .line 472
    .line 473
    return-object p0

    .line 474
    :pswitch_97
    const-string p0, "Maps - Favourites"

    .line 475
    .line 476
    return-object p0

    .line 477
    :pswitch_98
    const-string p0, "MySkoda App - Maps - Charging stations filter"

    .line 478
    .line 479
    return-object p0

    .line 480
    :pswitch_99
    const-string p0, "Force update"

    .line 481
    .line 482
    return-object p0

    .line 483
    :pswitch_9a
    return-object v0

    .line 484
    :pswitch_9b
    const-string p0, "Consents flow"

    .line 485
    .line 486
    return-object p0

    .line 487
    :pswitch_9c
    const-string p0, "Terms of use"

    .line 488
    .line 489
    return-object p0

    .line 490
    :pswitch_9d
    const-string p0, "SAD Third party dealer consent"

    .line 491
    .line 492
    return-object p0

    .line 493
    :pswitch_9e
    const-string p0, "SAD Third party consent"

    .line 494
    .line 495
    return-object p0

    .line 496
    :pswitch_9f
    const-string p0, "SAD Marketing consent"

    .line 497
    .line 498
    return-object p0

    .line 499
    :pswitch_a0
    const-string p0, "Marketing consent"

    .line 500
    .line 501
    return-object p0

    .line 502
    :pswitch_a1
    const-string p0, "Legal documents"

    .line 503
    .line 504
    return-object p0

    .line 505
    :pswitch_a2
    const-string p0, "Third party consent"

    .line 506
    .line 507
    return-object p0

    .line 508
    :pswitch_a3
    const-string p0, "Data processing"

    .line 509
    .line 510
    return-object p0

    .line 511
    :pswitch_a4
    const-string p0, "Vehicle - Licenses"

    .line 512
    .line 513
    return-object p0

    .line 514
    :pswitch_a5
    const-string p0, "Laura"

    .line 515
    .line 516
    return-object p0

    .line 517
    :pswitch_a6
    const-string p0, "Legal documents - Vehicle data access"

    .line 518
    .line 519
    return-object p0

    .line 520
    :pswitch_a7
    const-string p0, "Data tracking"

    .line 521
    .line 522
    return-object p0

    .line 523
    :pswitch_a8
    return-object v0

    .line 524
    :pswitch_a9
    const-string p0, "Laura QnA Info"

    .line 525
    .line 526
    return-object p0

    .line 527
    :pswitch_aa
    const-string p0, "Laura QnA"

    .line 528
    .line 529
    return-object p0

    .line 530
    :pswitch_ab
    const-string p0, "Vehicle - Health Scan"

    .line 531
    .line 532
    return-object p0

    .line 533
    :pswitch_ac
    const-string p0, "Guest user management - Guest user detail"

    .line 534
    .line 535
    return-object p0

    .line 536
    :pswitch_ad
    const-string p0, "Guest user management - Guest user list"

    .line 537
    .line 538
    return-object p0

    .line 539
    :pswitch_ae
    const-string p0, "Guest user management - Primary user detail"

    .line 540
    .line 541
    return-object p0

    .line 542
    :pswitch_af
    const-string p0, "Garage - Rename vehicle"

    .line 543
    .line 544
    return-object p0

    .line 545
    :pswitch_b0
    const-string p0, "Garage"

    .line 546
    .line 547
    return-object p0

    .line 548
    :pswitch_b1
    const-string p0, "Enrollment"

    .line 549
    .line 550
    return-object p0

    .line 551
    :pswitch_b2
    const-string p0, "Plan 1-3"

    .line 552
    .line 553
    return-object p0

    .line 554
    :pswitch_b3
    const-string p0, "Climate control"

    .line 555
    .line 556
    return-object p0

    .line 557
    :pswitch_b4
    const-string p0, "Planner"

    .line 558
    .line 559
    return-object p0

    .line 560
    :pswitch_b5
    const-string p0, "Demo onboarding"

    .line 561
    .line 562
    return-object p0

    .line 563
    :pswitch_b6
    const-string p0, "Contact us - Give feedback"

    .line 564
    .line 565
    return-object p0

    .line 566
    :pswitch_b7
    const-string p0, "Development Screen"

    .line 567
    .line 568
    return-object p0

    .line 569
    :pswitch_b8
    const-string p0, "Vehicle - Dealer - detail"

    .line 570
    .line 571
    return-object p0

    .line 572
    :pswitch_b9
    const-string p0, "Contact us - Info call"

    .line 573
    .line 574
    return-object p0

    .line 575
    :pswitch_ba
    const-string p0, "Contact us"

    .line 576
    .line 577
    return-object p0

    .line 578
    :pswitch_bb
    const-string p0, "Vehicle - Active Ventilation"

    .line 579
    .line 580
    return-object p0

    .line 581
    :pswitch_bc
    const-string p0, "Vehicle - Climate Plans"

    .line 582
    .line 583
    return-object p0

    .line 584
    :pswitch_bd
    const-string p0, "Vehicle - Auxiliary Heating"

    .line 585
    .line 586
    return-object p0

    .line 587
    :pswitch_be
    const-string p0, "Vehicle - Clima - seat heating"

    .line 588
    .line 589
    return-object p0

    .line 590
    :pswitch_bf
    const-string p0, "Vehicle - Clima - settings"

    .line 591
    .line 592
    return-object p0

    .line 593
    :pswitch_c0
    const-string p0, "Vehicle - Clima"

    .line 594
    .line 595
    return-object p0

    .line 596
    :pswitch_c1
    const-string p0, "Settings - Language - app language"

    .line 597
    .line 598
    return-object p0

    .line 599
    :pswitch_c2
    const-string p0, "Plan is active"

    .line 600
    .line 601
    return-object p0

    .line 602
    :pswitch_c3
    const-string p0, "Powerpass - Registration"

    .line 603
    .line 604
    return-object p0

    .line 605
    :pswitch_c4
    const-string p0, "Powerpass - Legal notice"

    .line 606
    .line 607
    return-object p0

    .line 608
    :pswitch_c5
    const-string p0, "Powerpass - Help and support"

    .line 609
    .line 610
    return-object p0

    .line 611
    :pswitch_c6
    const-string p0, "Powerpass"

    .line 612
    .line 613
    return-object p0

    .line 614
    :pswitch_c7
    const-string p0, "Plug and charge"

    .line 615
    .line 616
    return-object p0

    .line 617
    :pswitch_c8
    const-string p0, "Charging statistics"

    .line 618
    .line 619
    return-object p0

    .line 620
    :pswitch_c9
    const-string p0, "Charging statistics history"

    .line 621
    .line 622
    return-object p0

    .line 623
    :pswitch_ca
    const-string p0, "Battery settings"

    .line 624
    .line 625
    return-object p0

    .line 626
    :pswitch_cb
    const-string p0, "Charging locations - Detail - rename"

    .line 627
    .line 628
    return-object p0

    .line 629
    :pswitch_cc
    const-string p0, "Charging locations - Create - map"

    .line 630
    .line 631
    return-object p0

    .line 632
    :pswitch_cd
    const-string p0, "Charging locations - Detail"

    .line 633
    .line 634
    return-object p0

    .line 635
    :pswitch_ce
    const-string p0, "Charging locations - Create"

    .line 636
    .line 637
    return-object p0

    .line 638
    :pswitch_cf
    const-string p0, "Charging locations - list"

    .line 639
    .line 640
    return-object p0

    .line 641
    :pswitch_d0
    const-string p0, "Charge modes"

    .line 642
    .line 643
    return-object p0

    .line 644
    :pswitch_d1
    return-object v1

    .line 645
    :pswitch_d2
    const/4 p0, 0x0

    .line 646
    return-object p0

    .line 647
    :pswitch_d3
    const-string p0, "Battery"

    .line 648
    .line 649
    return-object p0

    .line 650
    :pswitch_d4
    const-string p0, "Demo Garage"

    .line 651
    .line 652
    return-object p0

    .line 653
    :pswitch_d5
    const-string p0, "Vehicle - Settings"

    .line 654
    .line 655
    return-object p0

    .line 656
    :pswitch_d6
    const-string p0, "Vehicle - Discover"

    .line 657
    .line 658
    return-object p0

    .line 659
    :pswitch_d7
    const-string p0, "Vehicle - Inspect - Ordered"

    .line 660
    .line 661
    return-object p0

    .line 662
    :pswitch_d8
    const-string p0, "Vehicle - Inspect - Delivered"

    .line 663
    .line 664
    return-object p0

    .line 665
    :pswitch_d9
    const-string p0, "Vehicle - Maps"

    .line 666
    .line 667
    return-object p0

    .line 668
    :pswitch_da
    const-string p0, "Vehicle - Home"

    .line 669
    .line 670
    return-object p0

    .line 671
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_da
        :pswitch_d9
        :pswitch_d8
        :pswitch_d7
        :pswitch_d6
        :pswitch_d5
        :pswitch_d4
        :pswitch_d3
        :pswitch_d2
        :pswitch_d1
        :pswitch_d0
        :pswitch_cf
        :pswitch_ce
        :pswitch_cd
        :pswitch_cc
        :pswitch_cb
        :pswitch_ca
        :pswitch_c9
        :pswitch_c8
        :pswitch_c7
        :pswitch_c6
        :pswitch_c5
        :pswitch_c4
        :pswitch_c3
        :pswitch_c2
        :pswitch_c1
        :pswitch_c0
        :pswitch_bf
        :pswitch_be
        :pswitch_c0
        :pswitch_bf
        :pswitch_bd
        :pswitch_bc
        :pswitch_bb
        :pswitch_ba
        :pswitch_b9
        :pswitch_b8
        :pswitch_b7
        :pswitch_b7
        :pswitch_b7
        :pswitch_b6
        :pswitch_b7
        :pswitch_b7
        :pswitch_b5
        :pswitch_b4
        :pswitch_b3
        :pswitch_b2
        :pswitch_b1
        :pswitch_b1
        :pswitch_b1
        :pswitch_b1
        :pswitch_b1
        :pswitch_b1
        :pswitch_b1
        :pswitch_b1
        :pswitch_b0
        :pswitch_af
        :pswitch_ae
        :pswitch_ad
        :pswitch_ac
        :pswitch_ab
        :pswitch_aa
        :pswitch_a9
        :pswitch_a8
        :pswitch_a7
        :pswitch_a6
        :pswitch_a5
        :pswitch_a4
        :pswitch_a3
        :pswitch_a4
        :pswitch_a2
        :pswitch_a1
        :pswitch_a0
        :pswitch_9f
        :pswitch_9e
        :pswitch_9d
        :pswitch_9c
        :pswitch_9b
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_9a
        :pswitch_99
        :pswitch_98
        :pswitch_97
        :pswitch_96
        :pswitch_95
        :pswitch_94
        :pswitch_93
        :pswitch_92
        :pswitch_91
        :pswitch_90
        :pswitch_8f
        :pswitch_8e
        :pswitch_8d
        :pswitch_8c
        :pswitch_8b
        :pswitch_8a
        :pswitch_89
        :pswitch_88
        :pswitch_87
        :pswitch_86
        :pswitch_85
        :pswitch_84
        :pswitch_83
        :pswitch_82
        :pswitch_81
        :pswitch_80
        :pswitch_7f
        :pswitch_7e
        :pswitch_7d
        :pswitch_7c
        :pswitch_7b
        :pswitch_7a
        :pswitch_79
        :pswitch_78
        :pswitch_77
        :pswitch_76
        :pswitch_75
        :pswitch_74
        :pswitch_73
        :pswitch_72
        :pswitch_71
        :pswitch_70
        :pswitch_6f
        :pswitch_6e
        :pswitch_6d
        :pswitch_6c
        :pswitch_6b
        :pswitch_6a
        :pswitch_69
        :pswitch_68
        :pswitch_67
        :pswitch_66
        :pswitch_65
        :pswitch_64
        :pswitch_63
        :pswitch_62
        :pswitch_61
        :pswitch_60
        :pswitch_5f
        :pswitch_5e
        :pswitch_5d
        :pswitch_5c
        :pswitch_5b
        :pswitch_5a
        :pswitch_5a
        :pswitch_59
        :pswitch_58
        :pswitch_57
        :pswitch_56
        :pswitch_55
        :pswitch_56
        :pswitch_54
        :pswitch_53
        :pswitch_52
        :pswitch_51
        :pswitch_50
        :pswitch_4f
        :pswitch_4e
        :pswitch_4d
        :pswitch_4c
        :pswitch_4b
        :pswitch_4a
        :pswitch_49
        :pswitch_48
        :pswitch_47
        :pswitch_46
        :pswitch_45
        :pswitch_44
        :pswitch_45
        :pswitch_43
        :pswitch_42
        :pswitch_42
        :pswitch_42
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_33
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
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

.method public static declared-synchronized b(Landroid/content/Context;)I
    .locals 7

    .line 1
    const-class v0, Lqp/i;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    const-string v1, "Context is null"

    .line 5
    .line 6
    invoke-static {p0, v1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    const-string v1, "i"

    .line 10
    .line 11
    const-string v2, "null"

    .line 12
    .line 13
    const-string v3, "preferredRenderer: "

    .line 14
    .line 15
    invoke-virtual {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    sget-boolean v1, Lqp/i;->a:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    goto/16 :goto_5

    .line 28
    .line 29
    :cond_0
    :try_start_1
    invoke-static {p0}, Lkp/z5;->b(Landroid/content/Context;)Lrp/e;

    .line 30
    .line 31
    .line 32
    move-result-object v1
    :try_end_1
    .catch Ljo/g; {:try_start_1 .. :try_end_1} :catch_2
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    :try_start_2
    invoke-virtual {v1}, Lrp/e;->W()Lrp/a;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    sput-object v3, Ljp/wf;->a:Lrp/a;

    .line 41
    .line 42
    invoke-virtual {v1}, Lrp/e;->Y()Lhp/m;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    sget-object v4, Lkp/m8;->a:Lhp/m;

    .line 47
    .line 48
    if-eqz v4, :cond_1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    const-string v4, "delegate must not be null"

    .line 52
    .line 53
    invoke-static {v3, v4}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    sput-object v3, Lkp/m8;->a:Lhp/m;
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 57
    .line 58
    :goto_0
    const/4 v3, 0x1

    .line 59
    :try_start_3
    sput-boolean v3, Lqp/i;->a:Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 60
    .line 61
    const/4 v4, 0x2

    .line 62
    :try_start_4
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    const/16 v6, 0x9

    .line 67
    .line 68
    invoke-virtual {v1, v5, v6}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    invoke-virtual {v5}, Landroid/os/Parcel;->readInt()I

    .line 73
    .line 74
    .line 75
    move-result v6

    .line 76
    invoke-virtual {v5}, Landroid/os/Parcel;->recycle()V

    .line 77
    .line 78
    .line 79
    if-ne v6, v4, :cond_2

    .line 80
    .line 81
    sput v4, Lqp/i;->b:I

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :catchall_0
    move-exception p0

    .line 85
    goto :goto_6

    .line 86
    :catch_0
    move-exception p0

    .line 87
    goto :goto_2

    .line 88
    :cond_2
    :goto_1
    new-instance v5, Lyo/b;

    .line 89
    .line 90
    invoke-direct {v5, p0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-static {p0, v5}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 101
    .line 102
    .line 103
    const/16 v5, 0xa

    .line 104
    .line 105
    invoke-virtual {v1, p0, v5}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 106
    .line 107
    .line 108
    goto :goto_3

    .line 109
    :goto_2
    :try_start_5
    const-string v1, "i"

    .line 110
    .line 111
    const-string v5, "Failed to retrieve renderer type or log initialization."

    .line 112
    .line 113
    invoke-static {v1, v5, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 114
    .line 115
    .line 116
    :goto_3
    const-string p0, "i"

    .line 117
    .line 118
    sget v1, Lqp/i;->b:I

    .line 119
    .line 120
    if-eq v1, v3, :cond_4

    .line 121
    .line 122
    if-eq v1, v4, :cond_3

    .line 123
    .line 124
    const-string v1, "null"

    .line 125
    .line 126
    goto :goto_4

    .line 127
    :cond_3
    const-string v1, "LATEST"

    .line 128
    .line 129
    goto :goto_4

    .line 130
    :cond_4
    const-string v1, "LEGACY"

    .line 131
    .line 132
    :goto_4
    const-string v3, "loadedRenderer: "

    .line 133
    .line 134
    invoke-virtual {v3, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    invoke-static {p0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 139
    .line 140
    .line 141
    :goto_5
    monitor-exit v0

    .line 142
    return v2

    .line 143
    :catch_1
    move-exception p0

    .line 144
    :try_start_6
    new-instance v1, La8/r0;

    .line 145
    .line 146
    invoke-direct {v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 147
    .line 148
    .line 149
    throw v1

    .line 150
    :catch_2
    move-exception p0

    .line 151
    iget p0, p0, Ljo/g;->d:I
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 152
    .line 153
    monitor-exit v0

    .line 154
    return p0

    .line 155
    :goto_6
    :try_start_7
    monitor-exit v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 156
    throw p0
.end method

.method public static c(Lv7/a;)V
    .locals 5

    .line 1
    const v0, -0x800001

    .line 2
    .line 3
    .line 4
    iput v0, p0, Lv7/a;->k:F

    .line 5
    .line 6
    const/high16 v0, -0x80000000

    .line 7
    .line 8
    iput v0, p0, Lv7/a;->j:I

    .line 9
    .line 10
    iget-object v0, p0, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 11
    .line 12
    instance-of v1, v0, Landroid/text/Spanned;

    .line 13
    .line 14
    if-eqz v1, :cond_3

    .line 15
    .line 16
    instance-of v1, v0, Landroid/text/Spannable;

    .line 17
    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    invoke-static {v0}, Landroid/text/SpannableString;->valueOf(Ljava/lang/CharSequence;)Landroid/text/SpannableString;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    iput-object v0, p0, Lv7/a;->b:Landroid/graphics/Bitmap;

    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    check-cast p0, Landroid/text/Spannable;

    .line 35
    .line 36
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const-class v1, Ljava/lang/Object;

    .line 41
    .line 42
    const/4 v2, 0x0

    .line 43
    invoke-interface {p0, v2, v0, v1}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    array-length v1, v0

    .line 48
    :goto_0
    if-ge v2, v1, :cond_3

    .line 49
    .line 50
    aget-object v3, v0, v2

    .line 51
    .line 52
    instance-of v4, v3, Landroid/text/style/AbsoluteSizeSpan;

    .line 53
    .line 54
    if-nez v4, :cond_1

    .line 55
    .line 56
    instance-of v4, v3, Landroid/text/style/RelativeSizeSpan;

    .line 57
    .line 58
    if-eqz v4, :cond_2

    .line 59
    .line 60
    :cond_1
    invoke-interface {p0, v3}, Landroid/text/Spannable;->removeSpan(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_3
    return-void
.end method

.method public static d(IIIF)F
    .locals 2

    .line 1
    const v0, -0x800001

    .line 2
    .line 3
    .line 4
    cmpl-float v1, p3, v0

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    return v0

    .line 9
    :cond_0
    if-eqz p0, :cond_3

    .line 10
    .line 11
    const/4 p2, 0x1

    .line 12
    if-eq p0, p2, :cond_2

    .line 13
    .line 14
    const/4 p1, 0x2

    .line 15
    if-eq p0, p1, :cond_1

    .line 16
    .line 17
    return v0

    .line 18
    :cond_1
    return p3

    .line 19
    :cond_2
    int-to-float p0, p1

    .line 20
    :goto_0
    mul-float/2addr p3, p0

    .line 21
    return p3

    .line 22
    :cond_3
    int-to-float p0, p2

    .line 23
    goto :goto_0
.end method
