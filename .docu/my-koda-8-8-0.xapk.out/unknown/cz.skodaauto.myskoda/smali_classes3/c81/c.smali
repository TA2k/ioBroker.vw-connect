.class public final Lc81/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;


# instance fields
.field public final synthetic a:Lc81/d;


# direct methods
.method public constructor <init>(Lc81/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc81/c;->a:Lc81/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onSafetyInstructionChange(Lt71/e;)V
    .locals 1

    .line 1
    const-string v0, "safetyInstructionStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lc81/c;->a:Lc81/d;

    .line 7
    .line 8
    iget-object p0, p0, Lc81/d;->e:Lt71/a;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lt71/a;->f:Lt71/e;

    .line 13
    .line 14
    if-eq v0, p1, :cond_0

    .line 15
    .line 16
    iput-object p1, p0, Lt71/a;->f:Lt71/e;

    .line 17
    .line 18
    iget-object p1, p0, Lt71/a;->g:Lt71/b;

    .line 19
    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    invoke-interface {p1, p0}, Lt71/b;->safetyInstructionDidChange(Lt71/a;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public final onSideEffect(Ljava/lang/Object;)V
    .locals 2

    .line 1
    const-string v0, "sideEffect"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ls71/m;

    .line 7
    .line 8
    iget-object p0, p0, Lc81/c;->a:Lc81/d;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object p0, p0, Lc81/d;->e:Lt71/a;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    check-cast p1, Ls71/m;

    .line 17
    .line 18
    iput-object p1, p0, Lt71/a;->c:Ls71/m;

    .line 19
    .line 20
    iget-object p1, p0, Lt71/a;->g:Lt71/b;

    .line 21
    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    invoke-interface {p1, p0}, Lt71/b;->sideEffectTriggered(Lt71/a;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void

    .line 28
    :cond_1
    iget-object p0, p0, Lc81/d;->a:Ll71/w;

    .line 29
    .line 30
    iget-object p0, p0, Ll71/w;->b:Lu61/b;

    .line 31
    .line 32
    new-instance v0, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string v1, "Got unexpected side effect "

    .line 35
    .line 36
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final onStateChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateChangeInformation;)V
    .locals 12

    .line 1
    iget-object p0, p0, Lc81/c;->a:Lc81/d;

    .line 2
    .line 3
    iget-object v0, p0, Lc81/d;->a:Ll71/w;

    .line 4
    .line 5
    const-string v1, "stateChangeInformation"

    .line 6
    .line 7
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateChangeInformation;->getNewState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StoppedState;

    .line 15
    .line 16
    const-wide/16 v2, 0x0

    .line 17
    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    iget-object p1, v0, Ll71/w;->a:Ln71/a;

    .line 21
    .line 22
    new-instance v0, La71/u;

    .line 23
    .line 24
    const/16 v1, 0x1b

    .line 25
    .line 26
    invoke-direct {v0, p0, v1}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    invoke-interface {p1, v2, v3, v0}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 34
    .line 35
    if-eqz v1, :cond_24

    .line 36
    .line 37
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 38
    .line 39
    iget-object v1, p0, Lc81/d;->c:Lb81/b;

    .line 40
    .line 41
    iget-object v4, v1, Lb81/b;->f:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v4, Lb81/d;

    .line 44
    .line 45
    iget-object v5, v4, Lb81/d;->f:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v5, Ll71/z;

    .line 48
    .line 49
    iget-object v4, v4, Lb81/d;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v4, Ll71/w;

    .line 52
    .line 53
    instance-of v6, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBScreenState;

    .line 54
    .line 55
    const/4 v7, 0x0

    .line 56
    if-eqz v6, :cond_7

    .line 57
    .line 58
    new-instance v6, Lb81/a;

    .line 59
    .line 60
    invoke-direct {v6, v4, v5}, Lb81/a;-><init>(Ll71/w;Ll71/z;)V

    .line 61
    .line 62
    .line 63
    move-object v4, p1

    .line 64
    check-cast v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBScreenState;

    .line 65
    .line 66
    iget-object v5, v6, Lb81/a;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v5, Ll71/w;

    .line 69
    .line 70
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    move-result-object v8

    .line 74
    sget-object v9, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 75
    .line 76
    invoke-virtual {v9, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 77
    .line 78
    .line 79
    move-result-object v8

    .line 80
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;

    .line 81
    .line 82
    invoke-virtual {v9, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 83
    .line 84
    .line 85
    move-result-object v10

    .line 86
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v10

    .line 90
    if-eqz v10, :cond_1

    .line 91
    .line 92
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;

    .line 93
    .line 94
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;-><init>(Ll71/w;)V

    .line 95
    .line 96
    .line 97
    goto/16 :goto_5

    .line 98
    .line 99
    :cond_1
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState;

    .line 100
    .line 101
    invoke-virtual {v9, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 102
    .line 103
    .line 104
    move-result-object v10

    .line 105
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v10

    .line 109
    if-eqz v10, :cond_2

    .line 110
    .line 111
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;

    .line 112
    .line 113
    new-instance v6, Le81/a;

    .line 114
    .line 115
    sget-wide v8, Li81/b;->a:J

    .line 116
    .line 117
    invoke-static {v8, v9}, Lmy0/c;->e(J)J

    .line 118
    .line 119
    .line 120
    move-result-wide v8

    .line 121
    sget-wide v10, Li81/b;->b:J

    .line 122
    .line 123
    invoke-static {v10, v11}, Lmy0/c;->e(J)J

    .line 124
    .line 125
    .line 126
    move-result-wide v10

    .line 127
    invoke-direct {v6, v8, v9, v10, v11}, Le81/a;-><init>(JJ)V

    .line 128
    .line 129
    .line 130
    invoke-direct {v4, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;-><init>(Ll71/w;Le81/a;)V

    .line 131
    .line 132
    .line 133
    goto/16 :goto_5

    .line 134
    .line 135
    :cond_2
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState;

    .line 136
    .line 137
    invoke-virtual {v9, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 138
    .line 139
    .line 140
    move-result-object v10

    .line 141
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v10

    .line 145
    if-eqz v10, :cond_3

    .line 146
    .line 147
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;

    .line 148
    .line 149
    iget-object v6, v6, Lb81/a;->f:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v6, Ll71/z;

    .line 152
    .line 153
    invoke-direct {v4, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;-><init>(Ll71/w;Ll71/z;)V

    .line 154
    .line 155
    .line 156
    goto/16 :goto_5

    .line 157
    .line 158
    :cond_3
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState;

    .line 159
    .line 160
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 161
    .line 162
    .line 163
    move-result-object v6

    .line 164
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result v6

    .line 168
    if-eqz v6, :cond_4

    .line 169
    .line 170
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;

    .line 171
    .line 172
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;-><init>(Ll71/w;)V

    .line 173
    .line 174
    .line 175
    goto/16 :goto_5

    .line 176
    .line 177
    :cond_4
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState;

    .line 178
    .line 179
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 180
    .line 181
    .line 182
    move-result-object v6

    .line 183
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result v6

    .line 187
    if-eqz v6, :cond_5

    .line 188
    .line 189
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;

    .line 190
    .line 191
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;-><init>(Ll71/w;)V

    .line 192
    .line 193
    .line 194
    goto/16 :goto_5

    .line 195
    .line 196
    :cond_5
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState;

    .line 197
    .line 198
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 199
    .line 200
    .line 201
    move-result-object v6

    .line 202
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    move-result v6

    .line 206
    if-eqz v6, :cond_6

    .line 207
    .line 208
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;

    .line 209
    .line 210
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;-><init>(Ll71/w;)V

    .line 211
    .line 212
    .line 213
    goto/16 :goto_5

    .line 214
    .line 215
    :cond_6
    iget-object v5, v5, Ll71/w;->b:Lu61/b;

    .line 216
    .line 217
    const-class v6, Lb81/a;

    .line 218
    .line 219
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 220
    .line 221
    .line 222
    move-result-object v6

    .line 223
    invoke-interface {v6}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v6

    .line 227
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    move-result-object v4

    .line 231
    invoke-virtual {v9, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 232
    .line 233
    .line 234
    move-result-object v4

    .line 235
    invoke-interface {v4}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v4

    .line 239
    new-instance v8, Ljava/lang/StringBuilder;

    .line 240
    .line 241
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 245
    .line 246
    .line 247
    const-string v6, ": unimplemented screenState type: "

    .line 248
    .line 249
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 250
    .line 251
    .line 252
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 253
    .line 254
    .line 255
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object v4

    .line 259
    invoke-static {v5, v4}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 260
    .line 261
    .line 262
    const/4 v4, 0x0

    .line 263
    goto/16 :goto_5

    .line 264
    .line 265
    :cond_7
    instance-of v6, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBScreenState;

    .line 266
    .line 267
    if-eqz v6, :cond_11

    .line 268
    .line 269
    new-instance v6, Lb81/b;

    .line 270
    .line 271
    invoke-direct {v6, v4, v5}, Lb81/b;-><init>(Ll71/w;Ll71/z;)V

    .line 272
    .line 273
    .line 274
    move-object v4, p1

    .line 275
    check-cast v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBScreenState;

    .line 276
    .line 277
    iget-object v5, v6, Lb81/b;->e:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v5, Ll71/w;

    .line 280
    .line 281
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 282
    .line 283
    .line 284
    move-result-object v8

    .line 285
    sget-object v9, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 286
    .line 287
    invoke-virtual {v9, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 288
    .line 289
    .line 290
    move-result-object v8

    .line 291
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState;

    .line 292
    .line 293
    invoke-virtual {v9, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 294
    .line 295
    .line 296
    move-result-object v10

    .line 297
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 298
    .line 299
    .line 300
    move-result v10

    .line 301
    if-eqz v10, :cond_8

    .line 302
    .line 303
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;

    .line 304
    .line 305
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;-><init>(Ll71/w;)V

    .line 306
    .line 307
    .line 308
    goto/16 :goto_5

    .line 309
    .line 310
    :cond_8
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState;

    .line 311
    .line 312
    invoke-virtual {v9, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 313
    .line 314
    .line 315
    move-result-object v10

    .line 316
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 317
    .line 318
    .line 319
    move-result v10

    .line 320
    if-eqz v10, :cond_9

    .line 321
    .line 322
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;

    .line 323
    .line 324
    new-instance v6, Le81/a;

    .line 325
    .line 326
    sget-wide v8, Ln81/b;->a:J

    .line 327
    .line 328
    invoke-static {v8, v9}, Lmy0/c;->e(J)J

    .line 329
    .line 330
    .line 331
    move-result-wide v8

    .line 332
    sget-wide v10, Ln81/b;->b:J

    .line 333
    .line 334
    invoke-static {v10, v11}, Lmy0/c;->e(J)J

    .line 335
    .line 336
    .line 337
    move-result-wide v10

    .line 338
    invoke-direct {v6, v8, v9, v10, v11}, Le81/a;-><init>(JJ)V

    .line 339
    .line 340
    .line 341
    invoke-direct {v4, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;-><init>(Ll71/w;Le81/a;)V

    .line 342
    .line 343
    .line 344
    goto/16 :goto_5

    .line 345
    .line 346
    :cond_9
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState;

    .line 347
    .line 348
    invoke-virtual {v9, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 349
    .line 350
    .line 351
    move-result-object v10

    .line 352
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 353
    .line 354
    .line 355
    move-result v10

    .line 356
    if-eqz v10, :cond_a

    .line 357
    .line 358
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;

    .line 359
    .line 360
    iget-object v6, v6, Lb81/b;->f:Ljava/lang/Object;

    .line 361
    .line 362
    check-cast v6, Ll71/z;

    .line 363
    .line 364
    invoke-direct {v4, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;-><init>(Ll71/w;Ll71/z;)V

    .line 365
    .line 366
    .line 367
    goto/16 :goto_5

    .line 368
    .line 369
    :cond_a
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState;

    .line 370
    .line 371
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 372
    .line 373
    .line 374
    move-result-object v6

    .line 375
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 376
    .line 377
    .line 378
    move-result v6

    .line 379
    if-eqz v6, :cond_b

    .line 380
    .line 381
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;

    .line 382
    .line 383
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;-><init>(Ll71/w;)V

    .line 384
    .line 385
    .line 386
    goto/16 :goto_5

    .line 387
    .line 388
    :cond_b
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState;

    .line 389
    .line 390
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 391
    .line 392
    .line 393
    move-result-object v6

    .line 394
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 395
    .line 396
    .line 397
    move-result v6

    .line 398
    if-eqz v6, :cond_c

    .line 399
    .line 400
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;

    .line 401
    .line 402
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;-><init>(Ll71/w;)V

    .line 403
    .line 404
    .line 405
    goto/16 :goto_5

    .line 406
    .line 407
    :cond_c
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;

    .line 408
    .line 409
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 410
    .line 411
    .line 412
    move-result-object v6

    .line 413
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 414
    .line 415
    .line 416
    move-result v6

    .line 417
    const/4 v10, 0x0

    .line 418
    if-eqz v6, :cond_f

    .line 419
    .line 420
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;

    .line 421
    .line 422
    invoke-direct {v6, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;-><init>(Ll71/w;)V

    .line 423
    .line 424
    .line 425
    instance-of v5, v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;

    .line 426
    .line 427
    if-eqz v5, :cond_d

    .line 428
    .line 429
    move-object v10, v4

    .line 430
    check-cast v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;

    .line 431
    .line 432
    :cond_d
    if-eqz v10, :cond_e

    .line 433
    .line 434
    invoke-virtual {v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;->getInitialStateValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 435
    .line 436
    .line 437
    move-result-object v4

    .line 438
    if-eqz v4, :cond_e

    .line 439
    .line 440
    iget-object v4, v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->a:Ls71/h;

    .line 441
    .line 442
    goto :goto_0

    .line 443
    :cond_e
    sget-object v4, Ls71/h;->d:Ls71/h;

    .line 444
    .line 445
    :goto_0
    invoke-virtual {v6, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setActiveParkingManeuver$remoteparkassistcoremeb_release(Ls71/h;)V

    .line 446
    .line 447
    .line 448
    :goto_1
    move-object v4, v6

    .line 449
    goto/16 :goto_5

    .line 450
    .line 451
    :cond_f
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState;

    .line 452
    .line 453
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 454
    .line 455
    .line 456
    move-result-object v6

    .line 457
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 458
    .line 459
    .line 460
    move-result v6

    .line 461
    if-eqz v6, :cond_10

    .line 462
    .line 463
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;

    .line 464
    .line 465
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;-><init>(Ll71/w;)V

    .line 466
    .line 467
    .line 468
    goto/16 :goto_5

    .line 469
    .line 470
    :cond_10
    iget-object v5, v5, Ll71/w;->b:Lu61/b;

    .line 471
    .line 472
    const-class v6, Lb81/b;

    .line 473
    .line 474
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 475
    .line 476
    .line 477
    move-result-object v6

    .line 478
    invoke-interface {v6}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 479
    .line 480
    .line 481
    move-result-object v6

    .line 482
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 483
    .line 484
    .line 485
    move-result-object v4

    .line 486
    invoke-virtual {v9, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 487
    .line 488
    .line 489
    move-result-object v4

    .line 490
    invoke-interface {v4}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 491
    .line 492
    .line 493
    move-result-object v4

    .line 494
    new-instance v8, Ljava/lang/StringBuilder;

    .line 495
    .line 496
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 497
    .line 498
    .line 499
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 500
    .line 501
    .line 502
    const-string v6, ": unimplemented screenState type: "

    .line 503
    .line 504
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 505
    .line 506
    .line 507
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 508
    .line 509
    .line 510
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 511
    .line 512
    .line 513
    move-result-object v4

    .line 514
    invoke-static {v5, v4}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 515
    .line 516
    .line 517
    :goto_2
    move-object v4, v10

    .line 518
    goto/16 :goto_5

    .line 519
    .line 520
    :cond_11
    instance-of v6, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPEScreenState;

    .line 521
    .line 522
    if-eqz v6, :cond_1b

    .line 523
    .line 524
    new-instance v6, Lb81/c;

    .line 525
    .line 526
    invoke-direct {v6, v4, v5}, Lb81/c;-><init>(Ll71/w;Ll71/z;)V

    .line 527
    .line 528
    .line 529
    move-object v4, p1

    .line 530
    check-cast v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPEScreenState;

    .line 531
    .line 532
    iget-object v5, v6, Lb81/c;->e:Ljava/lang/Object;

    .line 533
    .line 534
    check-cast v5, Ll71/w;

    .line 535
    .line 536
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 537
    .line 538
    .line 539
    move-result-object v8

    .line 540
    sget-object v9, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 541
    .line 542
    invoke-virtual {v9, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 543
    .line 544
    .line 545
    move-result-object v8

    .line 546
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;

    .line 547
    .line 548
    invoke-virtual {v9, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 549
    .line 550
    .line 551
    move-result-object v10

    .line 552
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 553
    .line 554
    .line 555
    move-result v10

    .line 556
    if-eqz v10, :cond_12

    .line 557
    .line 558
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;

    .line 559
    .line 560
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;-><init>(Ll71/w;)V

    .line 561
    .line 562
    .line 563
    goto/16 :goto_5

    .line 564
    .line 565
    :cond_12
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState;

    .line 566
    .line 567
    invoke-virtual {v9, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 568
    .line 569
    .line 570
    move-result-object v10

    .line 571
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 572
    .line 573
    .line 574
    move-result v10

    .line 575
    if-eqz v10, :cond_13

    .line 576
    .line 577
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;

    .line 578
    .line 579
    new-instance v6, Le81/a;

    .line 580
    .line 581
    sget-wide v8, Lu81/b;->g:J

    .line 582
    .line 583
    invoke-static {v8, v9}, Lmy0/c;->e(J)J

    .line 584
    .line 585
    .line 586
    move-result-wide v8

    .line 587
    sget-wide v10, Lu81/b;->f:J

    .line 588
    .line 589
    invoke-static {v10, v11}, Lmy0/c;->e(J)J

    .line 590
    .line 591
    .line 592
    move-result-wide v10

    .line 593
    invoke-direct {v6, v8, v9, v10, v11}, Le81/a;-><init>(JJ)V

    .line 594
    .line 595
    .line 596
    invoke-direct {v4, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;-><init>(Ll71/w;Le81/a;)V

    .line 597
    .line 598
    .line 599
    goto/16 :goto_5

    .line 600
    .line 601
    :cond_13
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;

    .line 602
    .line 603
    invoke-virtual {v9, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 604
    .line 605
    .line 606
    move-result-object v10

    .line 607
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 608
    .line 609
    .line 610
    move-result v10

    .line 611
    if-eqz v10, :cond_14

    .line 612
    .line 613
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;

    .line 614
    .line 615
    iget-object v6, v6, Lb81/c;->f:Ljava/lang/Object;

    .line 616
    .line 617
    check-cast v6, Ll71/z;

    .line 618
    .line 619
    invoke-direct {v4, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;-><init>(Ll71/w;Ll71/z;)V

    .line 620
    .line 621
    .line 622
    goto/16 :goto_5

    .line 623
    .line 624
    :cond_14
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState;

    .line 625
    .line 626
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 627
    .line 628
    .line 629
    move-result-object v6

    .line 630
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 631
    .line 632
    .line 633
    move-result v6

    .line 634
    if-eqz v6, :cond_15

    .line 635
    .line 636
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;

    .line 637
    .line 638
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;-><init>(Ll71/w;)V

    .line 639
    .line 640
    .line 641
    goto/16 :goto_5

    .line 642
    .line 643
    :cond_15
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;

    .line 644
    .line 645
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 646
    .line 647
    .line 648
    move-result-object v6

    .line 649
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 650
    .line 651
    .line 652
    move-result v6

    .line 653
    if-eqz v6, :cond_16

    .line 654
    .line 655
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;

    .line 656
    .line 657
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;-><init>(Ll71/w;)V

    .line 658
    .line 659
    .line 660
    goto/16 :goto_5

    .line 661
    .line 662
    :cond_16
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 663
    .line 664
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 665
    .line 666
    .line 667
    move-result-object v6

    .line 668
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 669
    .line 670
    .line 671
    move-result v6

    .line 672
    const/4 v10, 0x0

    .line 673
    if-eqz v6, :cond_19

    .line 674
    .line 675
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;

    .line 676
    .line 677
    invoke-direct {v6, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;-><init>(Ll71/w;)V

    .line 678
    .line 679
    .line 680
    instance-of v5, v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 681
    .line 682
    if-eqz v5, :cond_17

    .line 683
    .line 684
    move-object v10, v4

    .line 685
    check-cast v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 686
    .line 687
    :cond_17
    if-eqz v10, :cond_18

    .line 688
    .line 689
    invoke-virtual {v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;->getInitialStateValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 690
    .line 691
    .line 692
    move-result-object v4

    .line 693
    if-eqz v4, :cond_18

    .line 694
    .line 695
    iget-object v4, v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->f:Ls71/h;

    .line 696
    .line 697
    goto :goto_3

    .line 698
    :cond_18
    sget-object v4, Ls71/h;->d:Ls71/h;

    .line 699
    .line 700
    :goto_3
    invoke-virtual {v6, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setActiveParkingManeuver$remoteparkassistcoremeb_release(Ls71/h;)V

    .line 701
    .line 702
    .line 703
    goto/16 :goto_1

    .line 704
    .line 705
    :cond_19
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;

    .line 706
    .line 707
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 708
    .line 709
    .line 710
    move-result-object v6

    .line 711
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 712
    .line 713
    .line 714
    move-result v6

    .line 715
    if-eqz v6, :cond_1a

    .line 716
    .line 717
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;

    .line 718
    .line 719
    invoke-direct {v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;-><init>(Ll71/w;)V

    .line 720
    .line 721
    .line 722
    goto/16 :goto_5

    .line 723
    .line 724
    :cond_1a
    iget-object v5, v5, Ll71/w;->b:Lu61/b;

    .line 725
    .line 726
    const-class v6, Lb81/c;

    .line 727
    .line 728
    invoke-virtual {v9, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 729
    .line 730
    .line 731
    move-result-object v6

    .line 732
    invoke-interface {v6}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 733
    .line 734
    .line 735
    move-result-object v6

    .line 736
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 737
    .line 738
    .line 739
    move-result-object v4

    .line 740
    invoke-virtual {v9, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 741
    .line 742
    .line 743
    move-result-object v4

    .line 744
    invoke-interface {v4}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 745
    .line 746
    .line 747
    move-result-object v4

    .line 748
    new-instance v8, Ljava/lang/StringBuilder;

    .line 749
    .line 750
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 751
    .line 752
    .line 753
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 754
    .line 755
    .line 756
    const-string v6, ": unimplemented screenState type: "

    .line 757
    .line 758
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 759
    .line 760
    .line 761
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 762
    .line 763
    .line 764
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 765
    .line 766
    .line 767
    move-result-object v4

    .line 768
    invoke-static {v5, v4}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 769
    .line 770
    .line 771
    goto/16 :goto_2

    .line 772
    .line 773
    :cond_1b
    instance-of v5, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;

    .line 774
    .line 775
    if-eqz v5, :cond_1c

    .line 776
    .line 777
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ConnectionEstablishmentViewModelController;

    .line 778
    .line 779
    invoke-direct {v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ConnectionEstablishmentViewModelController;-><init>(Ll71/w;)V

    .line 780
    .line 781
    .line 782
    :goto_4
    move-object v4, v5

    .line 783
    goto :goto_5

    .line 784
    :cond_1c
    instance-of v5, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;

    .line 785
    .line 786
    if-eqz v5, :cond_1d

    .line 787
    .line 788
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;

    .line 789
    .line 790
    invoke-direct {v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;-><init>(Ll71/w;)V

    .line 791
    .line 792
    .line 793
    goto :goto_4

    .line 794
    :cond_1d
    instance-of v5, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/MEBParkingState;

    .line 795
    .line 796
    if-nez v5, :cond_1e

    .line 797
    .line 798
    instance-of v5, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/MLBParkingState;

    .line 799
    .line 800
    if-nez v5, :cond_1e

    .line 801
    .line 802
    instance-of v5, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;

    .line 803
    .line 804
    if-nez v5, :cond_1e

    .line 805
    .line 806
    iget-object v4, v4, Ll71/w;->b:Lu61/b;

    .line 807
    .line 808
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 809
    .line 810
    const-class v6, Lb81/d;

    .line 811
    .line 812
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 813
    .line 814
    .line 815
    move-result-object v6

    .line 816
    invoke-interface {v6}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 817
    .line 818
    .line 819
    move-result-object v6

    .line 820
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 821
    .line 822
    .line 823
    move-result-object v8

    .line 824
    invoke-virtual {v5, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 825
    .line 826
    .line 827
    move-result-object v5

    .line 828
    invoke-interface {v5}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 829
    .line 830
    .line 831
    move-result-object v5

    .line 832
    new-instance v8, Ljava/lang/StringBuilder;

    .line 833
    .line 834
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 835
    .line 836
    .line 837
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 838
    .line 839
    .line 840
    const-string v6, ": unimplemented screenState type: "

    .line 841
    .line 842
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 843
    .line 844
    .line 845
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 846
    .line 847
    .line 848
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 849
    .line 850
    .line 851
    move-result-object v5

    .line 852
    invoke-static {v4, v5}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 853
    .line 854
    .line 855
    :cond_1e
    move-object v4, v7

    .line 856
    :goto_5
    if-eqz v4, :cond_1f

    .line 857
    .line 858
    new-instance v5, Landroidx/lifecycle/c1;

    .line 859
    .line 860
    iget-object v1, v1, Lb81/b;->e:Ljava/lang/Object;

    .line 861
    .line 862
    check-cast v1, Ll71/w;

    .line 863
    .line 864
    invoke-direct {v5, v4, v1}, Landroidx/lifecycle/c1;-><init>(Le81/x;Ll71/w;)V

    .line 865
    .line 866
    .line 867
    goto :goto_6

    .line 868
    :cond_1f
    move-object v5, v7

    .line 869
    :goto_6
    if-eqz v5, :cond_25

    .line 870
    .line 871
    iget-object v1, v5, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 872
    .line 873
    check-cast v1, Le81/x;

    .line 874
    .line 875
    iget-object v4, p0, Lc81/d;->f:Landroidx/lifecycle/c1;

    .line 876
    .line 877
    if-eqz v4, :cond_20

    .line 878
    .line 879
    iput-object v7, v4, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 880
    .line 881
    iget-object v6, v4, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 882
    .line 883
    check-cast v6, Le81/x;

    .line 884
    .line 885
    invoke-virtual {v6, v7}, Le81/x;->setDelegate$remoteparkassistcoremeb_release(Lay0/k;)V

    .line 886
    .line 887
    .line 888
    iput-object v7, v4, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 889
    .line 890
    :cond_20
    iput-object v5, p0, Lc81/d;->f:Landroidx/lifecycle/c1;

    .line 891
    .line 892
    new-instance v4, La2/e;

    .line 893
    .line 894
    const/16 v6, 0xb

    .line 895
    .line 896
    invoke-direct {v4, p0, v6}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 897
    .line 898
    .line 899
    invoke-virtual {v1}, Le81/x;->getSupportedScreenStates$remoteparkassistcoremeb_release()Ljava/util/Set;

    .line 900
    .line 901
    .line 902
    move-result-object v6

    .line 903
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 904
    .line 905
    .line 906
    move-result-object v7

    .line 907
    sget-object v8, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 908
    .line 909
    invoke-virtual {v8, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 910
    .line 911
    .line 912
    move-result-object v7

    .line 913
    invoke-interface {v6, v7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 914
    .line 915
    .line 916
    move-result v6

    .line 917
    if-nez v6, :cond_21

    .line 918
    .line 919
    iget-object v4, v5, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 920
    .line 921
    check-cast v4, Ll71/w;

    .line 922
    .line 923
    iget-object v4, v4, Ll71/w;->b:Lu61/b;

    .line 924
    .line 925
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 926
    .line 927
    .line 928
    move-result-object p1

    .line 929
    invoke-virtual {v8, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 930
    .line 931
    .line 932
    move-result-object p1

    .line 933
    invoke-interface {p1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 934
    .line 935
    .line 936
    move-result-object p1

    .line 937
    new-instance v6, Ljava/lang/StringBuilder;

    .line 938
    .line 939
    const-string v7, "Cannot start with "

    .line 940
    .line 941
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 942
    .line 943
    .line 944
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 945
    .line 946
    .line 947
    const-string p1, " as it\'s not supported."

    .line 948
    .line 949
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 950
    .line 951
    .line 952
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 953
    .line 954
    .line 955
    move-result-object p1

    .line 956
    invoke-static {v4, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 957
    .line 958
    .line 959
    goto :goto_7

    .line 960
    :cond_21
    iput-object v4, v5, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 961
    .line 962
    iget-object v4, v5, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 963
    .line 964
    check-cast v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 965
    .line 966
    invoke-virtual {p1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->equals(Ljava/lang/Object;)Z

    .line 967
    .line 968
    .line 969
    move-result v4

    .line 970
    if-nez v4, :cond_22

    .line 971
    .line 972
    iput-object p1, v5, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 973
    .line 974
    iget-object p1, v5, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 975
    .line 976
    check-cast p1, La2/e;

    .line 977
    .line 978
    invoke-virtual {v1, p1}, Le81/x;->setDelegate$remoteparkassistcoremeb_release(Lay0/k;)V

    .line 979
    .line 980
    .line 981
    iget-object p1, v5, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 982
    .line 983
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 984
    .line 985
    if-eqz p1, :cond_22

    .line 986
    .line 987
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateMachine()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

    .line 988
    .line 989
    .line 990
    move-result-object p1

    .line 991
    if-eqz p1, :cond_22

    .line 992
    .line 993
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 994
    .line 995
    .line 996
    move-result-object p1

    .line 997
    invoke-virtual {v1, p1}, Le81/x;->update$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;)V

    .line 998
    .line 999
    .line 1000
    :cond_22
    :goto_7
    iget-object p1, p0, Lc81/d;->e:Lt71/a;

    .line 1001
    .line 1002
    if-eqz p1, :cond_23

    .line 1003
    .line 1004
    invoke-interface {v1}, Lz71/h;->getRepresentingScreen()Ls71/l;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v1

    .line 1008
    const-string v4, "value"

    .line 1009
    .line 1010
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1011
    .line 1012
    .line 1013
    iget-object v4, p1, Lt71/a;->e:Ls71/l;

    .line 1014
    .line 1015
    if-eq v4, v1, :cond_23

    .line 1016
    .line 1017
    iput-object v1, p1, Lt71/a;->e:Ls71/l;

    .line 1018
    .line 1019
    iget-object v1, p1, Lt71/a;->g:Lt71/b;

    .line 1020
    .line 1021
    if-eqz v1, :cond_23

    .line 1022
    .line 1023
    invoke-interface {v1, p1}, Lt71/b;->screenDidChange(Lt71/a;)V

    .line 1024
    .line 1025
    .line 1026
    :cond_23
    iget-object p1, v0, Ll71/w;->a:Ln71/a;

    .line 1027
    .line 1028
    new-instance v0, Laa/k;

    .line 1029
    .line 1030
    const/16 v1, 0xf

    .line 1031
    .line 1032
    invoke-direct {v0, v1, p0, v5}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1033
    .line 1034
    .line 1035
    invoke-interface {p1, v2, v3, v0}, Ln71/a;->dispatchToMainThread(JLay0/a;)Ln71/b;

    .line 1036
    .line 1037
    .line 1038
    return-void

    .line 1039
    :cond_24
    iget-object p0, p0, Lc81/d;->f:Landroidx/lifecycle/c1;

    .line 1040
    .line 1041
    if-eqz p0, :cond_25

    .line 1042
    .line 1043
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 1044
    .line 1045
    check-cast p0, Le81/x;

    .line 1046
    .line 1047
    invoke-virtual {p0, p1}, Le81/x;->update$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;)V

    .line 1048
    .line 1049
    .line 1050
    :cond_25
    return-void
.end method

.method public final onStateValuesChange(Ll71/x;)V
    .locals 1

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lc81/c;->a:Lc81/d;

    .line 7
    .line 8
    iget-object p0, p0, Lc81/d;->f:Landroidx/lifecycle/c1;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Le81/x;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Le81/x;->onStateValuesChange$remoteparkassistcoremeb_release(Ll71/x;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method
