.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/a;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Ls71/n;Ls71/e;ZZLjava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;
    .locals 2

    .line 1
    iget-object v0, p1, Ls71/e;->b:Ljava/util/List;

    .line 2
    .line 3
    iget-object p1, p1, Ls71/e;->a:Ls71/f;

    .line 4
    .line 5
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 6
    .line 7
    invoke-virtual {p4, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p4

    .line 11
    if-eqz p4, :cond_0

    .line 12
    .line 13
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$BadConnectionQuality;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$BadConnectionQuality;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    if-eqz p0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    packed-switch p0, :pswitch_data_0

    .line 23
    .line 24
    .line 25
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :pswitch_0
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KABVokoVkmOn;

    .line 32
    .line 33
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KABVokoVkmOn;-><init>(Ls71/c;)V

    .line 36
    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KABVovoVkmOff;

    .line 40
    .line 41
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KABVovoVkmOff;-><init>(Ls71/c;)V

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_2
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationIncreasedDrivingResistance;

    .line 48
    .line 49
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationIncreasedDrivingResistance;-><init>(Ls71/c;)V

    .line 52
    .line 53
    .line 54
    return-object p0

    .line 55
    :pswitch_3
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$StandbyIncreasedDrivingResistance;

    .line 56
    .line 57
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$StandbyIncreasedDrivingResistance;-><init>(Ls71/c;)V

    .line 60
    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_4
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationTSKGradient;

    .line 64
    .line 65
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationTSKGradient;-><init>(Ls71/c;)V

    .line 68
    .line 69
    .line 70
    return-object p0

    .line 71
    :pswitch_5
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$PPLossPOSOK;

    .line 72
    .line 73
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 74
    .line 75
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$PPLossPOSOK;-><init>(Ls71/c;)V

    .line 76
    .line 77
    .line 78
    return-object p0

    .line 79
    :pswitch_6
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$PPErrorKeyAuthorizer;

    .line 80
    .line 81
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 82
    .line 83
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$PPErrorKeyAuthorizer;-><init>(Ls71/c;)V

    .line 84
    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_7
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationEscIntervention;

    .line 88
    .line 89
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 90
    .line 91
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationEscIntervention;-><init>(Ls71/c;)V

    .line 92
    .line 93
    .line 94
    return-object p0

    .line 95
    :pswitch_8
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TrailerDetected;

    .line 96
    .line 97
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 98
    .line 99
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TrailerDetected;-><init>(Ls71/c;)V

    .line 100
    .line 101
    .line 102
    return-object p0

    .line 103
    :pswitch_9
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ObstacleDetected;

    .line 104
    .line 105
    sget-object p2, Ls71/c;->d:Ls71/c;

    .line 106
    .line 107
    invoke-direct {p0, p2, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ObstacleDetected;-><init>(Ls71/c;Ls71/f;Ljava/util/List;)V

    .line 108
    .line 109
    .line 110
    return-object p0

    .line 111
    :pswitch_a
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeyOutOfRange;

    .line 112
    .line 113
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 114
    .line 115
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeyOutOfRange;-><init>(Ls71/c;)V

    .line 116
    .line 117
    .line 118
    return-object p0

    .line 119
    :pswitch_b
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ParkingSpaceTooSmall;

    .line 120
    .line 121
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ParkingSpaceTooSmall;-><init>(Ls71/c;)V

    .line 124
    .line 125
    .line 126
    return-object p0

    .line 127
    :pswitch_c
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MaxMovesReached;

    .line 128
    .line 129
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 130
    .line 131
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MaxMovesReached;-><init>(Ls71/c;)V

    .line 132
    .line 133
    .line 134
    return-object p0

    .line 135
    :pswitch_d
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationByGWSM;

    .line 136
    .line 137
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 138
    .line 139
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationByGWSM;-><init>(Ls71/c;)V

    .line 140
    .line 141
    .line 142
    return-object p0

    .line 143
    :pswitch_e
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ShuntingAreaTooSmall;

    .line 144
    .line 145
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 146
    .line 147
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ShuntingAreaTooSmall;-><init>(Ls71/c;)V

    .line 148
    .line 149
    .line 150
    return-object p0

    .line 151
    :pswitch_f
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MaxDistanceReached;

    .line 152
    .line 153
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 154
    .line 155
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MaxDistanceReached;-><init>(Ls71/c;)V

    .line 156
    .line 157
    .line 158
    return-object p0

    .line 159
    :pswitch_10
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$AirSuspensionHeightNio;

    .line 160
    .line 161
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 162
    .line 163
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$AirSuspensionHeightNio;-><init>(Ls71/c;)V

    .line 164
    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_11
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$OffRoadActive;

    .line 168
    .line 169
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 170
    .line 171
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$OffRoadActive;-><init>(Ls71/c;)V

    .line 172
    .line 173
    .line 174
    return-object p0

    .line 175
    :pswitch_12
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MultipleKeysDetected;

    .line 176
    .line 177
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 178
    .line 179
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MultipleKeysDetected;-><init>(Ls71/c;)V

    .line 180
    .line 181
    .line 182
    return-object p0

    .line 183
    :pswitch_13
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeyInsideInterior;

    .line 184
    .line 185
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 186
    .line 187
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeyInsideInterior;-><init>(Ls71/c;)V

    .line 188
    .line 189
    .line 190
    return-object p0

    .line 191
    :pswitch_14
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$GarageDoorOpen;

    .line 192
    .line 193
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 194
    .line 195
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$GarageDoorOpen;-><init>(Ls71/c;)V

    .line 196
    .line 197
    .line 198
    return-object p0

    .line 199
    :pswitch_15
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$RouteNotTrained;

    .line 200
    .line 201
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 202
    .line 203
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$RouteNotTrained;-><init>(Ls71/c;)V

    .line 204
    .line 205
    .line 206
    return-object p0

    .line 207
    :pswitch_16
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeySwitchOperated;

    .line 208
    .line 209
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 210
    .line 211
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeySwitchOperated;-><init>(Ls71/c;)V

    .line 212
    .line 213
    .line 214
    return-object p0

    .line 215
    :pswitch_17
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$CountryNotAllowed;

    .line 216
    .line 217
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 218
    .line 219
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$CountryNotAllowed;-><init>(Ls71/c;)V

    .line 220
    .line 221
    .line 222
    return-object p0

    .line 223
    :pswitch_18
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ChargeLevelLow;

    .line 224
    .line 225
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 226
    .line 227
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ChargeLevelLow;-><init>(Ls71/c;)V

    .line 228
    .line 229
    .line 230
    return-object p0

    .line 231
    :pswitch_19
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ReceptionObstructed;

    .line 232
    .line 233
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 234
    .line 235
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ReceptionObstructed;-><init>(Ls71/c;)V

    .line 236
    .line 237
    .line 238
    return-object p0

    .line 239
    :pswitch_1a
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ChargingPlugPlugged;

    .line 240
    .line 241
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 242
    .line 243
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ChargingPlugPlugged;-><init>(Ls71/c;)V

    .line 244
    .line 245
    .line 246
    return-object p0

    .line 247
    :pswitch_1b
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$NoContinuationOfTheJourney;

    .line 248
    .line 249
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 250
    .line 251
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$NoContinuationOfTheJourney;-><init>(Ls71/c;)V

    .line 252
    .line 253
    .line 254
    return-object p0

    .line 255
    :pswitch_1c
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$Timeout;

    .line 256
    .line 257
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 258
    .line 259
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$Timeout;-><init>(Ls71/c;)V

    .line 260
    .line 261
    .line 262
    return-object p0

    .line 263
    :pswitch_1d
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$IntrusionVehicleSystem;

    .line 264
    .line 265
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 266
    .line 267
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$IntrusionVehicleSystem;-><init>(Ls71/c;)V

    .line 268
    .line 269
    .line 270
    return-object p0

    .line 271
    :pswitch_1e
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$InteractionDetected;

    .line 272
    .line 273
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 274
    .line 275
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$InteractionDetected;-><init>(Ls71/c;)V

    .line 276
    .line 277
    .line 278
    return-object p0

    .line 279
    :pswitch_1f
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TrafficDetected;

    .line 280
    .line 281
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 282
    .line 283
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TrafficDetected;-><init>(Ls71/c;)V

    .line 284
    .line 285
    .line 286
    return-object p0

    .line 287
    :pswitch_20
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$DoorsAndFlaps;

    .line 288
    .line 289
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 290
    .line 291
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$DoorsAndFlaps;-><init>(Ls71/c;)V

    .line 292
    .line 293
    .line 294
    return-object p0

    .line 295
    :pswitch_21
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$FunctionNotAvailable;

    .line 296
    .line 297
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 298
    .line 299
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$FunctionNotAvailable;-><init>(Ls71/c;)V

    .line 300
    .line 301
    .line 302
    return-object p0

    .line 303
    :pswitch_22
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MalFunction;

    .line 304
    .line 305
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 306
    .line 307
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MalFunction;-><init>(Ls71/c;)V

    .line 308
    .line 309
    .line 310
    return-object p0

    .line 311
    :cond_1
    sget-object p0, Ls71/f;->d:Ls71/f;

    .line 312
    .line 313
    if-eq p1, p0, :cond_2

    .line 314
    .line 315
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ObstacleDetected;

    .line 316
    .line 317
    sget-object p2, Ls71/c;->d:Ls71/c;

    .line 318
    .line 319
    invoke-direct {p0, p2, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ObstacleDetected;-><init>(Ls71/c;Ls71/f;Ljava/util/List;)V

    .line 320
    .line 321
    .line 322
    return-object p0

    .line 323
    :cond_2
    if-eqz p2, :cond_3

    .line 324
    .line 325
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeyOutOfRange;

    .line 326
    .line 327
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 328
    .line 329
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeyOutOfRange;-><init>(Ls71/c;)V

    .line 330
    .line 331
    .line 332
    return-object p0

    .line 333
    :cond_3
    invoke-virtual {p5, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 334
    .line 335
    .line 336
    move-result p0

    .line 337
    if-eqz p0, :cond_4

    .line 338
    .line 339
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ReverseNotPossible;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ReverseNotPossible;

    .line 340
    .line 341
    return-object p0

    .line 342
    :cond_4
    invoke-static {p6, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 343
    .line 344
    .line 345
    move-result p0

    .line 346
    if-eqz p0, :cond_5

    .line 347
    .line 348
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ScenarioSelectionFailed;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ScenarioSelectionFailed;

    .line 349
    .line 350
    return-object p0

    .line 351
    :cond_5
    if-eqz p3, :cond_6

    .line 352
    .line 353
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MultiTouch;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MultiTouch;

    .line 354
    .line 355
    return-object p0

    .line 356
    :cond_6
    invoke-static {p7, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 357
    .line 358
    .line 359
    move-result p0

    .line 360
    if-eqz p0, :cond_7

    .line 361
    .line 362
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$DriveActivationThresholdNotReached;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$DriveActivationThresholdNotReached;

    .line 363
    .line 364
    return-object p0

    .line 365
    :cond_7
    const/4 p0, 0x0

    .line 366
    return-object p0

    .line 367
    :pswitch_data_0
    .packed-switch 0x0
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
