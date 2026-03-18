.class public final synthetic Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x6

    iput v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Lkotlin/jvm/internal/n;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->d:I

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->e:Ljava/lang/Object;

    .line 5
    .line 6
    packed-switch v0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingBackward;

    .line 10
    .line 11
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 12
    .line 13
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingBackward;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingBackward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_0
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$Init;

    .line 19
    .line 20
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 21
    .line 22
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$Init;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$Init;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_1
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationSubState;

    .line 28
    .line 29
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 30
    .line 31
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationSubState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationSubState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$HoldKeyState;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_2
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/a;

    .line 37
    .line 38
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 39
    .line 40
    const-string v0, "it"

    .line 41
    .line 42
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lv81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_3
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$WaitingForResponse;

    .line 55
    .line 56
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 57
    .line 58
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$WaitingForResponse;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$WaitingForResponse;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :pswitch_4
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingNotAllowed;

    .line 64
    .line 65
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 66
    .line 67
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingNotAllowed;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingNotAllowed;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :pswitch_5
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingAllowed;

    .line 73
    .line 74
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 75
    .line 76
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingAllowed;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingAllowed;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_6
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;

    .line 82
    .line 83
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 84
    .line 85
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    :pswitch_7
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressTimeThresholdNotReached;

    .line 91
    .line 92
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 93
    .line 94
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressTimeThresholdNotReached;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressTimeThresholdNotReached;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    return-object p0

    .line 99
    :pswitch_8
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$HoldKeyState;

    .line 100
    .line 101
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 102
    .line 103
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$HoldKeyState;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$HoldKeyState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :pswitch_9
    check-cast p0, Lw31/g;

    .line 109
    .line 110
    check-cast p1, Ljava/lang/Throwable;

    .line 111
    .line 112
    const-string v0, "yyyy-MM-dd HH:mm:ss"

    .line 113
    .line 114
    invoke-static {}, Ljava/time/LocalDateTime;->now()Ljava/time/LocalDateTime;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    iget-object v2, p0, Lq41/b;->d:Lyy0/c2;

    .line 119
    .line 120
    :cond_0
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    move-object v3, p0

    .line 125
    check-cast v3, Lw31/h;

    .line 126
    .line 127
    invoke-static {v0}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    invoke-virtual {p1, v1}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v7

    .line 135
    const/4 v8, 0x6

    .line 136
    const/4 v4, 0x0

    .line 137
    const/4 v5, 0x0

    .line 138
    const/4 v6, 0x0

    .line 139
    invoke-static/range {v3 .. v8}, Lw31/h;->a(Lw31/h;ZLjava/util/ArrayList;Ljava/util/List;Ljava/lang/String;I)Lw31/h;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result p0

    .line 147
    if-eqz p0, :cond_0

    .line 148
    .line 149
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object p0

    .line 152
    :pswitch_a
    check-cast p0, Lqu/c;

    .line 153
    .line 154
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 155
    .line 156
    const-string v0, "$this$DisposableEffect"

    .line 157
    .line 158
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    new-instance p1, La2/j;

    .line 162
    .line 163
    const/16 v0, 0xf

    .line 164
    .line 165
    invoke-direct {p1, p0, v0}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 166
    .line 167
    .line 168
    return-object p1

    .line 169
    :pswitch_b
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;

    .line 170
    .line 171
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 172
    .line 173
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    return-object p0

    .line 178
    :pswitch_c
    check-cast p0, Lv81/a;

    .line 179
    .line 180
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 181
    .line 182
    const-string v0, "input"

    .line 183
    .line 184
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 188
    .line 189
    if-eqz v0, :cond_1

    .line 190
    .line 191
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 192
    .line 193
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    sget-object v2, Ls71/p;->E:Ls71/p;

    .line 198
    .line 199
    if-ne v0, v2, :cond_1

    .line 200
    .line 201
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;

    .line 202
    .line 203
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    invoke-direct {v1, p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)V

    .line 208
    .line 209
    .line 210
    :cond_1
    return-object v1

    .line 211
    :pswitch_d
    check-cast p0, Lqz0/a;

    .line 212
    .line 213
    check-cast p1, Lvz0/n;

    .line 214
    .line 215
    sget-object v0, Lvz0/d;->d:Lvz0/c;

    .line 216
    .line 217
    check-cast p0, Lqz0/a;

    .line 218
    .line 219
    invoke-virtual {v0, p0, p1}, Lvz0/d;->a(Lqz0/a;Lvz0/n;)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    return-object p0

    .line 224
    :pswitch_e
    check-cast p0, Lv2/r;

    .line 225
    .line 226
    iget-object v1, p0, Lv2/r;->g:Ljava/lang/Object;

    .line 227
    .line 228
    monitor-enter v1

    .line 229
    :try_start_0
    iget-object p0, p0, Lv2/r;->i:Lv2/q;

    .line 230
    .line 231
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    iget-object v0, p0, Lv2/q;->b:Ljava/lang/Object;

    .line 235
    .line 236
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    iget v2, p0, Lv2/q;->d:I

    .line 240
    .line 241
    iget-object v3, p0, Lv2/q;->c:Landroidx/collection/h0;

    .line 242
    .line 243
    if-nez v3, :cond_2

    .line 244
    .line 245
    new-instance v3, Landroidx/collection/h0;

    .line 246
    .line 247
    invoke-direct {v3}, Landroidx/collection/h0;-><init>()V

    .line 248
    .line 249
    .line 250
    iput-object v3, p0, Lv2/q;->c:Landroidx/collection/h0;

    .line 251
    .line 252
    iget-object v4, p0, Lv2/q;->f:Landroidx/collection/q0;

    .line 253
    .line 254
    invoke-virtual {v4, v0, v3}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    :cond_2
    invoke-virtual {p0, p1, v2, v0, v3}, Lv2/q;->c(Ljava/lang/Object;ILjava/lang/Object;Landroidx/collection/h0;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 258
    .line 259
    .line 260
    monitor-exit v1

    .line 261
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 262
    .line 263
    return-object p0

    .line 264
    :catchall_0
    move-exception v0

    .line 265
    move-object p0, v0

    .line 266
    monitor-exit v1

    .line 267
    throw p0

    .line 268
    :pswitch_f
    check-cast p0, Lb0/u;

    .line 269
    .line 270
    check-cast p1, Ljava/lang/Void;

    .line 271
    .line 272
    iget-object p0, p0, Lb0/u;->m:Ly4/k;

    .line 273
    .line 274
    return-object p0

    .line 275
    :pswitch_10
    check-cast p0, Luz0/r1;

    .line 276
    .line 277
    check-cast p1, Lsz0/a;

    .line 278
    .line 279
    const-string v0, "$this$buildClassSerialDescriptor"

    .line 280
    .line 281
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    const-string v0, "first"

    .line 285
    .line 286
    iget-object v1, p0, Luz0/r1;->a:Lqz0/a;

    .line 287
    .line 288
    invoke-interface {v1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 289
    .line 290
    .line 291
    move-result-object v1

    .line 292
    invoke-virtual {p1, v0, v1}, Lsz0/a;->a(Ljava/lang/String;Lsz0/g;)V

    .line 293
    .line 294
    .line 295
    const-string v0, "second"

    .line 296
    .line 297
    iget-object v1, p0, Luz0/r1;->b:Lqz0/a;

    .line 298
    .line 299
    invoke-interface {v1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    invoke-virtual {p1, v0, v1}, Lsz0/a;->a(Ljava/lang/String;Lsz0/g;)V

    .line 304
    .line 305
    .line 306
    const-string v0, "third"

    .line 307
    .line 308
    iget-object p0, p0, Luz0/r1;->c:Lqz0/a;

    .line 309
    .line 310
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    invoke-virtual {p1, v0, p0}, Lsz0/a;->a(Ljava/lang/String;Lsz0/g;)V

    .line 315
    .line 316
    .line 317
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 318
    .line 319
    return-object p0

    .line 320
    :pswitch_11
    check-cast p0, Lsz0/g;

    .line 321
    .line 322
    check-cast p1, Ljava/lang/Integer;

    .line 323
    .line 324
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 325
    .line 326
    .line 327
    move-result p1

    .line 328
    new-instance v0, Ljava/lang/StringBuilder;

    .line 329
    .line 330
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 331
    .line 332
    .line 333
    invoke-interface {p0, p1}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 338
    .line 339
    .line 340
    const-string v1, ": "

    .line 341
    .line 342
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 343
    .line 344
    .line 345
    invoke-interface {p0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 346
    .line 347
    .line 348
    move-result-object p0

    .line 349
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object p0

    .line 353
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 354
    .line 355
    .line 356
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object p0

    .line 360
    return-object p0

    .line 361
    :pswitch_12
    check-cast p0, Luz0/y;

    .line 362
    .line 363
    check-cast p1, Lsz0/a;

    .line 364
    .line 365
    const-string v0, "$this$buildSerialDescriptor"

    .line 366
    .line 367
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 368
    .line 369
    .line 370
    iget-object p0, p0, Luz0/y;->c:Ljava/lang/Object;

    .line 371
    .line 372
    check-cast p0, Ljava/util/List;

    .line 373
    .line 374
    const-string v0, "<set-?>"

    .line 375
    .line 376
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 377
    .line 378
    .line 379
    iput-object p0, p1, Lsz0/a;->b:Ljava/util/List;

    .line 380
    .line 381
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 382
    .line 383
    return-object p0

    .line 384
    :pswitch_13
    check-cast p0, Luu/x;

    .line 385
    .line 386
    check-cast p1, Lsp/k;

    .line 387
    .line 388
    const-string v0, "marker"

    .line 389
    .line 390
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    iget-object p0, p0, Luu/x;->k:Ljava/util/ArrayList;

    .line 394
    .line 395
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 396
    .line 397
    .line 398
    move-result-object p0

    .line 399
    :cond_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 400
    .line 401
    .line 402
    move-result v0

    .line 403
    if-eqz v0, :cond_4

    .line 404
    .line 405
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 406
    .line 407
    .line 408
    move-result-object v0

    .line 409
    move-object v2, v0

    .line 410
    check-cast v2, Luu/s0;

    .line 411
    .line 412
    instance-of v3, v2, Luu/k1;

    .line 413
    .line 414
    if-eqz v3, :cond_3

    .line 415
    .line 416
    check-cast v2, Luu/k1;

    .line 417
    .line 418
    iget-object v2, v2, Luu/k1;->b:Lsp/k;

    .line 419
    .line 420
    invoke-virtual {v2, p1}, Lsp/k;->equals(Ljava/lang/Object;)Z

    .line 421
    .line 422
    .line 423
    move-result v2

    .line 424
    if-eqz v2, :cond_3

    .line 425
    .line 426
    move-object v1, v0

    .line 427
    :cond_4
    check-cast v1, Luu/k1;

    .line 428
    .line 429
    return-object v1

    .line 430
    :pswitch_14
    check-cast p0, Luf/k;

    .line 431
    .line 432
    check-cast p1, Lgi/c;

    .line 433
    .line 434
    const-string v0, "$this$log"

    .line 435
    .line 436
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 437
    .line 438
    .line 439
    new-instance p1, Ljava/lang/StringBuilder;

    .line 440
    .line 441
    const-string v0, "Handling event: "

    .line 442
    .line 443
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 444
    .line 445
    .line 446
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 447
    .line 448
    .line 449
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 450
    .line 451
    .line 452
    move-result-object p0

    .line 453
    return-object p0

    .line 454
    :pswitch_15
    check-cast p0, Lu2/e;

    .line 455
    .line 456
    iget-object p0, p0, Lu2/e;->f:Lu2/g;

    .line 457
    .line 458
    if-eqz p0, :cond_5

    .line 459
    .line 460
    invoke-interface {p0, p1}, Lu2/g;->d(Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    move-result p0

    .line 464
    goto :goto_0

    .line 465
    :cond_5
    const/4 p0, 0x1

    .line 466
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 467
    .line 468
    .line 469
    move-result-object p0

    .line 470
    return-object p0

    .line 471
    :pswitch_16
    check-cast p0, Lkotlin/jvm/internal/n;

    .line 472
    .line 473
    check-cast p1, Ljava/util/List;

    .line 474
    .line 475
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 476
    .line 477
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 478
    .line 479
    .line 480
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 481
    .line 482
    .line 483
    move-result v1

    .line 484
    rem-int/lit8 v1, v1, 0x2

    .line 485
    .line 486
    if-nez v1, :cond_7

    .line 487
    .line 488
    const/4 v1, 0x0

    .line 489
    :goto_1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 490
    .line 491
    .line 492
    move-result v2

    .line 493
    if-ge v1, v2, :cond_6

    .line 494
    .line 495
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 496
    .line 497
    .line 498
    move-result-object v2

    .line 499
    const-string v3, "null cannot be cast to non-null type kotlin.String"

    .line 500
    .line 501
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 502
    .line 503
    .line 504
    check-cast v2, Ljava/lang/String;

    .line 505
    .line 506
    add-int/lit8 v3, v1, 0x1

    .line 507
    .line 508
    invoke-interface {p1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 509
    .line 510
    .line 511
    move-result-object v3

    .line 512
    invoke-interface {v0, v2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    add-int/lit8 v1, v1, 0x2

    .line 516
    .line 517
    goto :goto_1

    .line 518
    :cond_6
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object p0

    .line 522
    return-object p0

    .line 523
    :cond_7
    const-string p0, "non-zero remainder"

    .line 524
    .line 525
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 526
    .line 527
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 528
    .line 529
    .line 530
    throw p1

    .line 531
    :pswitch_17
    check-cast p0, Ltz/n0;

    .line 532
    .line 533
    check-cast p1, Lss0/k;

    .line 534
    .line 535
    sget v0, Ltz/n0;->J:I

    .line 536
    .line 537
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 538
    .line 539
    .line 540
    sget-object p0, Lss0/m;->g:Lss0/m;

    .line 541
    .line 542
    sget-object v0, Lss0/m;->k:Lss0/m;

    .line 543
    .line 544
    sget-object v1, Lss0/m;->j:Lss0/m;

    .line 545
    .line 546
    filled-new-array {p0, v0, v1}, [Lss0/m;

    .line 547
    .line 548
    .line 549
    move-result-object p0

    .line 550
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 551
    .line 552
    .line 553
    move-result-object p0

    .line 554
    iget-object v0, p1, Lss0/k;->d:Lss0/m;

    .line 555
    .line 556
    invoke-interface {p0, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 557
    .line 558
    .line 559
    move-result p0

    .line 560
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 561
    .line 562
    .line 563
    move-result-object p0

    .line 564
    iget-object p1, p1, Lss0/k;->i:Lss0/a0;

    .line 565
    .line 566
    if-eqz p1, :cond_8

    .line 567
    .line 568
    iget-object p1, p1, Lss0/a0;->a:Lss0/b;

    .line 569
    .line 570
    new-instance v0, Llx0/l;

    .line 571
    .line 572
    invoke-direct {v0, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 573
    .line 574
    .line 575
    return-object v0

    .line 576
    :cond_8
    const-string p0, "vehicle detail is missing"

    .line 577
    .line 578
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 579
    .line 580
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 581
    .line 582
    .line 583
    throw p1

    .line 584
    :pswitch_18
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$UnlockInProgressThresholdReached;

    .line 585
    .line 586
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 587
    .line 588
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$UnlockInProgressThresholdReached;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$UnlockInProgressThresholdReached;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 589
    .line 590
    .line 591
    move-result-object p0

    .line 592
    return-object p0

    .line 593
    :pswitch_19
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/o;

    .line 594
    .line 595
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 596
    .line 597
    const-string v0, "input"

    .line 598
    .line 599
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 600
    .line 601
    .line 602
    iget-object v0, p0, Lj81/a;->b:Li40/e1;

    .line 603
    .line 604
    invoke-virtual {v0, p1}, Li40/e1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 605
    .line 606
    .line 607
    move-result-object v0

    .line 608
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 609
    .line 610
    if-eqz v0, :cond_9

    .line 611
    .line 612
    move-object v1, v0

    .line 613
    goto :goto_2

    .line 614
    :cond_9
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 615
    .line 616
    if-eqz v0, :cond_a

    .line 617
    .line 618
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 619
    .line 620
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 621
    .line 622
    invoke-static {p1}, Llp/aa;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 623
    .line 624
    .line 625
    move-result-object p1

    .line 626
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

    .line 627
    .line 628
    iget-object v2, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;

    .line 629
    .line 630
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

    .line 631
    .line 632
    invoke-static {v0, v2, p1}, Llp/gd;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;)Z

    .line 633
    .line 634
    .line 635
    move-result p1

    .line 636
    if-eqz p1, :cond_a

    .line 637
    .line 638
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getStateCallback$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 639
    .line 640
    .line 641
    move-result-object p0

    .line 642
    sget-object p1, Ls71/m;->f:Ls71/m;

    .line 643
    .line 644
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 645
    .line 646
    .line 647
    :cond_a
    :goto_2
    return-object v1

    .line 648
    :pswitch_1a
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$Init;

    .line 649
    .line 650
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 651
    .line 652
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$Init;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$Init;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelection;

    .line 653
    .line 654
    .line 655
    move-result-object p0

    .line 656
    return-object p0

    .line 657
    :pswitch_1b
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/l;

    .line 658
    .line 659
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 660
    .line 661
    const-string v0, "input"

    .line 662
    .line 663
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 664
    .line 665
    .line 666
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 667
    .line 668
    if-eqz v0, :cond_b

    .line 669
    .line 670
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 671
    .line 672
    invoke-static {p1}, Llp/fd;->d(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 673
    .line 674
    .line 675
    move-result-object p1

    .line 676
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->getHasOpenWindows$remoteparkassistcoremeb_release()Z

    .line 677
    .line 678
    .line 679
    move-result p1

    .line 680
    if-nez p1, :cond_b

    .line 681
    .line 682
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getStateCallback$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 683
    .line 684
    .line 685
    move-result-object p0

    .line 686
    sget-object p1, Ls71/m;->g:Ls71/m;

    .line 687
    .line 688
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 689
    .line 690
    .line 691
    :cond_b
    return-object v1

    .line 692
    :pswitch_1c
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WindowClosingPossible;

    .line 693
    .line 694
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 695
    .line 696
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WindowClosingPossible;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WindowClosingPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;

    .line 697
    .line 698
    .line 699
    move-result-object p0

    .line 700
    return-object p0

    .line 701
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
