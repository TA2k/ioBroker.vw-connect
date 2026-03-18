.class public final synthetic Lpg/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lpg/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lpg/m;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lpg/m;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lpg/m;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WindowClosingNotPossible;

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 11
    .line 12
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WindowClosingNotPossible;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WindowClosingNotPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WaitingForFinish;

    .line 18
    .line 19
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 20
    .line 21
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WaitingForFinish;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WaitingForFinish;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :pswitch_1
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$ClosingWindows;

    .line 27
    .line 28
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 29
    .line 30
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$ClosingWindows;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$ClosingWindows;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_2
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/h;

    .line 36
    .line 37
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 38
    .line 39
    const-string v0, "input"

    .line 40
    .line 41
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    if-eqz v0, :cond_2

    .line 48
    .line 49
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 50
    .line 51
    invoke-static {p1}, Llp/fd;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState$ParkingFailed;

    .line 60
    .line 61
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    instance-of v3, p1, Li81/a;

    .line 66
    .line 67
    if-eqz v3, :cond_0

    .line 68
    .line 69
    check-cast p1, Li81/a;

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    move-object p1, v1

    .line 73
    :goto_0
    if-eqz p1, :cond_1

    .line 74
    .line 75
    iget-object p1, p1, Li81/a;->f:Ll71/c;

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    move-object p1, v1

    .line 79
    :goto_1
    invoke-direct {v2, v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState$ParkingFailed;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ll71/c;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {v2, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState$ParkingFailed;->equals(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    if-nez p0, :cond_2

    .line 91
    .line 92
    move-object v1, v2

    .line 93
    :cond_2
    return-object v1

    .line 94
    :pswitch_3
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationSubState;

    .line 95
    .line 96
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 97
    .line 98
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationSubState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationSubState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$WaitingForResponseConfirmed;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0

    .line 103
    :pswitch_4
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/b;

    .line 104
    .line 105
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 106
    .line 107
    const-string v0, "it"

    .line 108
    .line 109
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    iget-object p0, p0, Lj81/a;->b:Li40/e1;

    .line 113
    .line 114
    invoke-virtual {p0, p1}, Li40/e1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 119
    .line 120
    return-object p0

    .line 121
    :pswitch_5
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$WaitingForResponseConfirmed;

    .line 122
    .line 123
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 124
    .line 125
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$WaitingForResponseConfirmed;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$WaitingForResponseConfirmed;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0

    .line 130
    :pswitch_6
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$WaitingForResponse;

    .line 131
    .line 132
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 133
    .line 134
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$WaitingForResponse;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$WaitingForResponse;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    return-object p0

    .line 139
    :pswitch_7
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$PressingNotAllowed;

    .line 140
    .line 141
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 142
    .line 143
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$PressingNotAllowed;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$PressingNotAllowed;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0

    .line 148
    :pswitch_8
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$PressingAllowed;

    .line 149
    .line 150
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 151
    .line 152
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$PressingAllowed;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$PressingAllowed;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    return-object p0

    .line 157
    :pswitch_9
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$Pressing;

    .line 158
    .line 159
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 160
    .line 161
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$Pressing;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$Pressing;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    return-object p0

    .line 166
    :pswitch_a
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$PressTimeThresholdNotReached;

    .line 167
    .line 168
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 169
    .line 170
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$PressTimeThresholdNotReached;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState$PressTimeThresholdNotReached;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    return-object p0

    .line 175
    :pswitch_b
    check-cast p0, Ltd/o;

    .line 176
    .line 177
    check-cast p1, Lgi/c;

    .line 178
    .line 179
    const-string v0, "$this$log"

    .line 180
    .line 181
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    new-instance p1, Ljava/lang/StringBuilder;

    .line 185
    .line 186
    const-string v0, "Handling UI event: "

    .line 187
    .line 188
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    return-object p0

    .line 199
    :pswitch_c
    check-cast p0, Lki/j;

    .line 200
    .line 201
    check-cast p1, Lhi/a;

    .line 202
    .line 203
    const-string v0, "$this$sdkViewModel"

    .line 204
    .line 205
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 209
    .line 210
    const-class v1, Lqd/c;

    .line 211
    .line 212
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    check-cast p1, Lii/a;

    .line 217
    .line 218
    invoke-virtual {p1, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v1

    .line 222
    move-object v4, v1

    .line 223
    check-cast v4, Lqd/c;

    .line 224
    .line 225
    const-class v1, Ltd/c;

    .line 226
    .line 227
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object p1

    .line 235
    check-cast p1, Ltd/c;

    .line 236
    .line 237
    new-instance v0, Ltd/x;

    .line 238
    .line 239
    iget-object p0, p0, Lki/j;->b:Ljava/util/List;

    .line 240
    .line 241
    new-instance v2, Ljd/b;

    .line 242
    .line 243
    const/4 v8, 0x0

    .line 244
    const/16 v9, 0x1c

    .line 245
    .line 246
    const/4 v3, 0x2

    .line 247
    const-class v5, Lqd/c;

    .line 248
    .line 249
    const-string v6, "getChargingStatistics"

    .line 250
    .line 251
    const-string v7, "getChargingStatistics-gIAlu-s(Lcariad/charging/multicharge/kitten/chargingstatistics/models/ChargingStatisticsRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 252
    .line 253
    invoke-direct/range {v2 .. v9}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 254
    .line 255
    .line 256
    new-instance v5, Lt90/c;

    .line 257
    .line 258
    const/4 v11, 0x0

    .line 259
    const/16 v12, 0x9

    .line 260
    .line 261
    const/4 v6, 0x0

    .line 262
    const-class v8, Ltd/c;

    .line 263
    .line 264
    const-string v9, "get"

    .line 265
    .line 266
    const-string v10, "get()Ljava/util/List;"

    .line 267
    .line 268
    move-object v7, p1

    .line 269
    invoke-direct/range {v5 .. v12}, Lt90/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 270
    .line 271
    .line 272
    move-object p1, v5

    .line 273
    new-instance v5, Lt10/k;

    .line 274
    .line 275
    const/4 v6, 0x1

    .line 276
    const-class v8, Ltd/c;

    .line 277
    .line 278
    const-string v9, "put"

    .line 279
    .line 280
    const-string v10, "put(Ljava/util/List;)V"

    .line 281
    .line 282
    invoke-direct/range {v5 .. v12}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 283
    .line 284
    .line 285
    invoke-direct {v0, p0, v2, p1, v5}, Ltd/x;-><init>(Ljava/util/List;Ljd/b;Lt90/c;Lt10/k;)V

    .line 286
    .line 287
    .line 288
    return-object v0

    .line 289
    :pswitch_d
    check-cast p0, Lt51/j;

    .line 290
    .line 291
    if-nez p1, :cond_3

    .line 292
    .line 293
    iget-object p0, p0, Lt51/j;->b:Lt51/i;

    .line 294
    .line 295
    const/4 p0, 0x0

    .line 296
    throw p0

    .line 297
    :cond_3
    new-instance p0, Ljava/lang/ClassCastException;

    .line 298
    .line 299
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 300
    .line 301
    .line 302
    throw p0

    .line 303
    :pswitch_e
    check-cast p0, Lt1/h1;

    .line 304
    .line 305
    check-cast p1, Ljava/lang/Float;

    .line 306
    .line 307
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 308
    .line 309
    .line 310
    move-result p1

    .line 311
    iget-object v0, p0, Lt1/h1;->a:Ll2/f1;

    .line 312
    .line 313
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 314
    .line 315
    .line 316
    move-result v1

    .line 317
    add-float/2addr v1, p1

    .line 318
    iget-object p0, p0, Lt1/h1;->b:Ll2/f1;

    .line 319
    .line 320
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 321
    .line 322
    .line 323
    move-result v2

    .line 324
    cmpl-float v2, v1, v2

    .line 325
    .line 326
    if-lez v2, :cond_4

    .line 327
    .line 328
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 329
    .line 330
    .line 331
    move-result p0

    .line 332
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 333
    .line 334
    .line 335
    move-result p1

    .line 336
    sub-float p1, p0, p1

    .line 337
    .line 338
    goto :goto_2

    .line 339
    :cond_4
    const/4 p0, 0x0

    .line 340
    cmpg-float p0, v1, p0

    .line 341
    .line 342
    if-gez p0, :cond_5

    .line 343
    .line 344
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 345
    .line 346
    .line 347
    move-result p0

    .line 348
    neg-float p1, p0

    .line 349
    :cond_5
    :goto_2
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 350
    .line 351
    .line 352
    move-result p0

    .line 353
    add-float/2addr p0, p1

    .line 354
    invoke-virtual {v0, p0}, Ll2/f1;->p(F)V

    .line 355
    .line 356
    .line 357
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 358
    .line 359
    .line 360
    move-result-object p0

    .line 361
    return-object p0

    .line 362
    :pswitch_f
    check-cast p0, Le2/l;

    .line 363
    .line 364
    check-cast p1, Ld4/l;

    .line 365
    .line 366
    sget-object v0, Le2/d0;->c:Ld4/z;

    .line 367
    .line 368
    new-instance v1, Le2/c0;

    .line 369
    .line 370
    sget-object v2, Lt1/b0;->d:Lt1/b0;

    .line 371
    .line 372
    invoke-interface {p0}, Le2/l;->a()J

    .line 373
    .line 374
    .line 375
    move-result-wide v3

    .line 376
    sget-object v5, Le2/b0;->e:Le2/b0;

    .line 377
    .line 378
    const/4 v6, 0x1

    .line 379
    invoke-direct/range {v1 .. v6}, Le2/c0;-><init>(Lt1/b0;JLe2/b0;Z)V

    .line 380
    .line 381
    .line 382
    invoke-virtual {p1, v0, v1}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 383
    .line 384
    .line 385
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 386
    .line 387
    return-object p0

    .line 388
    :pswitch_10
    check-cast p0, Lk21/a;

    .line 389
    .line 390
    check-cast p1, Lm6/b;

    .line 391
    .line 392
    const-string v0, "cause"

    .line 393
    .line 394
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 395
    .line 396
    .line 397
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 398
    .line 399
    const-string v1, "DataStore preferences file is corrupted"

    .line 400
    .line 401
    invoke-direct {v0, v1, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 402
    .line 403
    .line 404
    invoke-static {p0, v0}, Llp/nd;->j(Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 405
    .line 406
    .line 407
    new-instance p0, Lq6/b;

    .line 408
    .line 409
    const/4 p1, 0x1

    .line 410
    invoke-direct {p0, p1}, Lq6/b;-><init>(Z)V

    .line 411
    .line 412
    .line 413
    return-object p0

    .line 414
    :pswitch_11
    check-cast p0, Ls70/c;

    .line 415
    .line 416
    check-cast p1, Ljava/lang/Throwable;

    .line 417
    .line 418
    new-instance p1, Lqf0/d;

    .line 419
    .line 420
    const/16 v0, 0xc

    .line 421
    .line 422
    invoke-direct {p1, v0}, Lqf0/d;-><init>(I)V

    .line 423
    .line 424
    .line 425
    invoke-static {p0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 426
    .line 427
    .line 428
    iget-object p0, p0, Ls70/c;->i:Lq70/f;

    .line 429
    .line 430
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 434
    .line 435
    return-object p0

    .line 436
    :pswitch_12
    check-cast p0, Lrf/a;

    .line 437
    .line 438
    check-cast p1, Lgi/c;

    .line 439
    .line 440
    const-string v0, "$this$log"

    .line 441
    .line 442
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 443
    .line 444
    .line 445
    new-instance p1, Ljava/lang/StringBuilder;

    .line 446
    .line 447
    const-string v0, "Handling "

    .line 448
    .line 449
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 450
    .line 451
    .line 452
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 453
    .line 454
    .line 455
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 456
    .line 457
    .line 458
    move-result-object p0

    .line 459
    return-object p0

    .line 460
    :pswitch_13
    check-cast p0, Lrb/a;

    .line 461
    .line 462
    check-cast p1, Ljava/util/List;

    .line 463
    .line 464
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 465
    .line 466
    .line 467
    move-object v0, p1

    .line 468
    check-cast v0, Ljava/util/Collection;

    .line 469
    .line 470
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 471
    .line 472
    .line 473
    move-result v0

    .line 474
    if-nez v0, :cond_6

    .line 475
    .line 476
    invoke-virtual {p0, p1}, Lrb/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 477
    .line 478
    .line 479
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 480
    .line 481
    return-object p0

    .line 482
    :pswitch_14
    check-cast p0, Lqz0/d;

    .line 483
    .line 484
    check-cast p1, Lsz0/a;

    .line 485
    .line 486
    const-string v0, "$this$buildSerialDescriptor"

    .line 487
    .line 488
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    const-string v0, "type"

    .line 492
    .line 493
    sget-object v1, Luz0/q1;->b:Luz0/h1;

    .line 494
    .line 495
    invoke-virtual {p1, v0, v1}, Lsz0/a;->a(Ljava/lang/String;Lsz0/g;)V

    .line 496
    .line 497
    .line 498
    new-instance v0, Ljava/lang/StringBuilder;

    .line 499
    .line 500
    const-string v1, "kotlinx.serialization.Polymorphic<"

    .line 501
    .line 502
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 503
    .line 504
    .line 505
    iget-object v1, p0, Lqz0/d;->a:Lhy0/d;

    .line 506
    .line 507
    invoke-interface {v1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 508
    .line 509
    .line 510
    move-result-object v1

    .line 511
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 512
    .line 513
    .line 514
    const/16 v1, 0x3e

    .line 515
    .line 516
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 517
    .line 518
    .line 519
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 520
    .line 521
    .line 522
    move-result-object v0

    .line 523
    const/4 v1, 0x0

    .line 524
    new-array v1, v1, [Lsz0/g;

    .line 525
    .line 526
    sget-object v2, Lsz0/i;->b:Lsz0/i;

    .line 527
    .line 528
    invoke-static {v0, v2, v1}, Lkp/x8;->e(Ljava/lang/String;Lkp/y8;[Lsz0/g;)Lsz0/h;

    .line 529
    .line 530
    .line 531
    move-result-object v0

    .line 532
    const-string v1, "value"

    .line 533
    .line 534
    invoke-virtual {p1, v1, v0}, Lsz0/a;->a(Ljava/lang/String;Lsz0/g;)V

    .line 535
    .line 536
    .line 537
    iget-object p0, p0, Lqz0/d;->b:Ljava/util/List;

    .line 538
    .line 539
    const-string v0, "<set-?>"

    .line 540
    .line 541
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 542
    .line 543
    .line 544
    iput-object p0, p1, Lsz0/a;->b:Ljava/util/List;

    .line 545
    .line 546
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 547
    .line 548
    return-object p0

    .line 549
    :pswitch_15
    check-cast p0, Lqj0/b;

    .line 550
    .line 551
    check-cast p1, Lkj0/f;

    .line 552
    .line 553
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 554
    .line 555
    .line 556
    iget-object p0, p1, Lkj0/f;->a:Ljava/time/OffsetDateTime;

    .line 557
    .line 558
    const-string v0, "yyyy-MM-dd HH:mm:ss.SSS"

    .line 559
    .line 560
    invoke-static {v0}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 561
    .line 562
    .line 563
    move-result-object v0

    .line 564
    invoke-virtual {p0, v0}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 565
    .line 566
    .line 567
    move-result-object p0

    .line 568
    iget-object v0, p1, Lkj0/f;->b:Lkj0/e;

    .line 569
    .line 570
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 571
    .line 572
    .line 573
    move-result v0

    .line 574
    if-eqz v0, :cond_b

    .line 575
    .line 576
    const/4 v1, 0x1

    .line 577
    if-eq v0, v1, :cond_a

    .line 578
    .line 579
    const/4 v1, 0x2

    .line 580
    if-eq v0, v1, :cond_9

    .line 581
    .line 582
    const/4 v1, 0x3

    .line 583
    if-eq v0, v1, :cond_8

    .line 584
    .line 585
    const/4 v1, 0x4

    .line 586
    if-ne v0, v1, :cond_7

    .line 587
    .line 588
    const-string v0, "E"

    .line 589
    .line 590
    goto :goto_3

    .line 591
    :cond_7
    new-instance p0, La8/r0;

    .line 592
    .line 593
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 594
    .line 595
    .line 596
    throw p0

    .line 597
    :cond_8
    const-string v0, "W"

    .line 598
    .line 599
    goto :goto_3

    .line 600
    :cond_9
    const-string v0, "I"

    .line 601
    .line 602
    goto :goto_3

    .line 603
    :cond_a
    const-string v0, "V"

    .line 604
    .line 605
    goto :goto_3

    .line 606
    :cond_b
    const-string v0, "D"

    .line 607
    .line 608
    :goto_3
    iget-object v1, p1, Lkj0/f;->c:Ljava/lang/String;

    .line 609
    .line 610
    iget-object p1, p1, Lkj0/f;->d:Ljava/lang/String;

    .line 611
    .line 612
    new-instance v2, Ljava/lang/StringBuilder;

    .line 613
    .line 614
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 615
    .line 616
    .line 617
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 618
    .line 619
    .line 620
    const-string p0, " "

    .line 621
    .line 622
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 623
    .line 624
    .line 625
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 626
    .line 627
    .line 628
    const-string v0, "/"

    .line 629
    .line 630
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 631
    .line 632
    .line 633
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 634
    .line 635
    .line 636
    invoke-static {v2, p0, p1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 637
    .line 638
    .line 639
    move-result-object p0

    .line 640
    return-object p0

    .line 641
    :pswitch_16
    check-cast p0, Lkg/d0;

    .line 642
    .line 643
    check-cast p1, Lgi/c;

    .line 644
    .line 645
    const-string v0, "$this$log"

    .line 646
    .line 647
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 648
    .line 649
    .line 650
    iget-object p0, p0, Lkg/d0;->d:Lkg/c;

    .line 651
    .line 652
    iget-object p0, p0, Lkg/c;->d:Lkg/p0;

    .line 653
    .line 654
    iget-object p0, p0, Lkg/p0;->e:Ljava/lang/String;

    .line 655
    .line 656
    const-string p1, "Upgraded to `"

    .line 657
    .line 658
    const-string v0, "` tariff"

    .line 659
    .line 660
    invoke-static {p1, p0, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 661
    .line 662
    .line 663
    move-result-object p0

    .line 664
    return-object p0

    .line 665
    :pswitch_17
    check-cast p0, Lq61/p;

    .line 666
    .line 667
    check-cast p1, Ls61/a;

    .line 668
    .line 669
    new-instance v0, Lg61/f;

    .line 670
    .line 671
    const/4 v1, 0x5

    .line 672
    invoke-direct {v0, p1, v1}, Lg61/f;-><init>(Ls61/a;I)V

    .line 673
    .line 674
    .line 675
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 676
    .line 677
    .line 678
    if-eqz p1, :cond_c

    .line 679
    .line 680
    const/4 p0, 0x1

    .line 681
    goto :goto_4

    .line 682
    :cond_c
    const/4 p0, 0x0

    .line 683
    :goto_4
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 684
    .line 685
    .line 686
    move-result-object p0

    .line 687
    return-object p0

    .line 688
    :pswitch_18
    check-cast p0, Lq61/e;

    .line 689
    .line 690
    check-cast p1, Ls61/a;

    .line 691
    .line 692
    new-instance v0, Lg61/f;

    .line 693
    .line 694
    const/4 v1, 0x1

    .line 695
    invoke-direct {v0, p1, v1}, Lg61/f;-><init>(Ls61/a;I)V

    .line 696
    .line 697
    .line 698
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 699
    .line 700
    .line 701
    if-eqz p1, :cond_d

    .line 702
    .line 703
    const/4 p0, 0x1

    .line 704
    goto :goto_5

    .line 705
    :cond_d
    const/4 p0, 0x0

    .line 706
    :goto_5
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 707
    .line 708
    .line 709
    move-result-object p0

    .line 710
    return-object p0

    .line 711
    :pswitch_19
    check-cast p0, Ljava/util/Calendar;

    .line 712
    .line 713
    move-object v0, p1

    .line 714
    check-cast v0, Li31/b;

    .line 715
    .line 716
    const-string p1, "$this$updateCurrentAppointmentUseCase"

    .line 717
    .line 718
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 719
    .line 720
    .line 721
    invoke-virtual {p0}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 722
    .line 723
    .line 724
    move-result-wide p0

    .line 725
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 726
    .line 727
    .line 728
    move-result-object v3

    .line 729
    const/4 v7, 0x0

    .line 730
    const/16 v8, 0x7b

    .line 731
    .line 732
    const/4 v1, 0x0

    .line 733
    const/4 v2, 0x0

    .line 734
    const/4 v4, 0x0

    .line 735
    const/4 v5, 0x0

    .line 736
    const/4 v6, 0x0

    .line 737
    invoke-static/range {v0 .. v8}, Li31/b;->a(Li31/b;Ljava/lang/String;Li31/b0;Ljava/lang/Long;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;I)Li31/b;

    .line 738
    .line 739
    .line 740
    move-result-object p0

    .line 741
    return-object p0

    .line 742
    :pswitch_1a
    check-cast p0, Lyy0/q1;

    .line 743
    .line 744
    check-cast p1, Lsq0/d;

    .line 745
    .line 746
    const-string v0, "result"

    .line 747
    .line 748
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 749
    .line 750
    .line 751
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 752
    .line 753
    .line 754
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 755
    .line 756
    return-object p0

    .line 757
    :pswitch_1b
    check-cast p0, Lph/i;

    .line 758
    .line 759
    move-object v4, p1

    .line 760
    check-cast v4, Ljava/lang/String;

    .line 761
    .line 762
    const-string p1, "it"

    .line 763
    .line 764
    invoke-static {v4, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 765
    .line 766
    .line 767
    iget-object v7, p0, Lph/i;->e:Lyy0/c2;

    .line 768
    .line 769
    const-string p0, "<this>"

    .line 770
    .line 771
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 772
    .line 773
    .line 774
    :cond_e
    invoke-virtual {v7}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 775
    .line 776
    .line 777
    move-result-object p0

    .line 778
    move-object v0, p0

    .line 779
    check-cast v0, Lph/j;

    .line 780
    .line 781
    const/4 v5, 0x0

    .line 782
    const/16 v6, 0x17

    .line 783
    .line 784
    const/4 v1, 0x0

    .line 785
    const/4 v2, 0x0

    .line 786
    const/4 v3, 0x0

    .line 787
    invoke-static/range {v0 .. v6}, Lph/j;->a(Lph/j;ZZZLjava/lang/String;ZI)Lph/j;

    .line 788
    .line 789
    .line 790
    move-result-object p1

    .line 791
    invoke-virtual {v7, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 792
    .line 793
    .line 794
    move-result p0

    .line 795
    if-eqz p0, :cond_e

    .line 796
    .line 797
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 798
    .line 799
    return-object p0

    .line 800
    :pswitch_1c
    check-cast p0, Lpg/n;

    .line 801
    .line 802
    check-cast p1, Lpg/l;

    .line 803
    .line 804
    const-string v0, "it"

    .line 805
    .line 806
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 807
    .line 808
    .line 809
    iget-object p0, p0, Lpg/n;->o:Lug/a;

    .line 810
    .line 811
    const v0, 0xbfff

    .line 812
    .line 813
    .line 814
    const/4 v1, 0x0

    .line 815
    invoke-static {p1, v1, v1, p0, v0}, Lpg/l;->a(Lpg/l;ZZLug/a;I)Lpg/l;

    .line 816
    .line 817
    .line 818
    move-result-object p0

    .line 819
    return-object p0

    .line 820
    nop

    .line 821
    :pswitch_data_0
    .packed-switch 0x0
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
