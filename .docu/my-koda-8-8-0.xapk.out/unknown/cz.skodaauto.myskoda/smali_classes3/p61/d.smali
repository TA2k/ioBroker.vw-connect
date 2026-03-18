.class public final synthetic Lp61/d;
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
    iput p2, p0, Lp61/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lp61/d;->e:Ljava/lang/Object;

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
    .locals 4

    .line 1
    iget v0, p0, Lp61/d;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "input"

    .line 5
    .line 6
    iget-object p0, p0, Lp61/d;->e:Ljava/lang/Object;

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$WaitingForNewFunctionState;

    .line 12
    .line 13
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 14
    .line 15
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$WaitingForNewFunctionState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$WaitingForNewFunctionState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :pswitch_0
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;

    .line 21
    .line 22
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 23
    .line 24
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_1
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockInProgressThresholdReached;

    .line 30
    .line 31
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 32
    .line 33
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockInProgressThresholdReached;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockInProgressThresholdReached;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :pswitch_2
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockInProgress;

    .line 39
    .line 40
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 41
    .line 42
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockInProgress;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockInProgress;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_3
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$LockedByDefault;

    .line 48
    .line 49
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 50
    .line 51
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$LockedByDefault;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$LockedByDefault;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_4
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$LockedByCar;

    .line 57
    .line 58
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 59
    .line 60
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$LockedByCar;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$LockedByCar;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :pswitch_5
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/u;

    .line 66
    .line 67
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 68
    .line 69
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    iget-object v0, p0, Lo81/a;->b:Lla/p;

    .line 73
    .line 74
    invoke-virtual {v0, p1}, Lla/p;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 79
    .line 80
    if-eqz v0, :cond_0

    .line 81
    .line 82
    move-object v1, v0

    .line 83
    goto :goto_0

    .line 84
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 85
    .line 86
    if-eqz v0, :cond_1

    .line 87
    .line 88
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->n:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 89
    .line 90
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 91
    .line 92
    invoke-static {p1}, Ljp/fa;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 97
    .line 98
    iget-object v2, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;

    .line 99
    .line 100
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 101
    .line 102
    invoke-static {v0, v2, p1}, Lkp/r;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;)Z

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    if-eqz p1, :cond_1

    .line 107
    .line 108
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getStateCallback$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    sget-object p1, Ls71/m;->f:Ls71/m;

    .line 113
    .line 114
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    :cond_1
    :goto_0
    return-object v1

    .line 118
    :pswitch_6
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;

    .line 119
    .line 120
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 121
    .line 122
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$HoldKeyInterruption;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    return-object p0

    .line 127
    :pswitch_7
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/t;

    .line 128
    .line 129
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 130
    .line 131
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 135
    .line 136
    if-eqz v0, :cond_2

    .line 137
    .line 138
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 139
    .line 140
    invoke-static {p1}, Lkp/q;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->getHasOpenWindows$remoteparkassistcoremeb_release()Z

    .line 145
    .line 146
    .line 147
    move-result p1

    .line 148
    if-nez p1, :cond_2

    .line 149
    .line 150
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getStateCallback$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    sget-object p1, Ls71/m;->g:Ls71/m;

    .line 155
    .line 156
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    :cond_2
    return-object v1

    .line 160
    :pswitch_8
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;

    .line 161
    .line 162
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 163
    .line 164
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    return-object p0

    .line 169
    :pswitch_9
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingNotPossible;

    .line 170
    .line 171
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 172
    .line 173
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingNotPossible;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingNotPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    return-object p0

    .line 178
    :pswitch_a
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$Init;

    .line 179
    .line 180
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 181
    .line 182
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$Init;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$Init;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    return-object p0

    .line 187
    :pswitch_b
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$ClosingWindows;

    .line 188
    .line 189
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 190
    .line 191
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$ClosingWindows;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$ClosingWindows;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    return-object p0

    .line 196
    :pswitch_c
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/r;

    .line 197
    .line 198
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 199
    .line 200
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 204
    .line 205
    if-eqz v0, :cond_5

    .line 206
    .line 207
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 208
    .line 209
    invoke-static {p1}, Lkp/q;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->getStoppingReasonStatusExtended()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;

    .line 218
    .line 219
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    instance-of v3, p1, Ln81/a;

    .line 224
    .line 225
    if-eqz v3, :cond_3

    .line 226
    .line 227
    check-cast p1, Ln81/a;

    .line 228
    .line 229
    goto :goto_1

    .line 230
    :cond_3
    move-object p1, v1

    .line 231
    :goto_1
    if-eqz p1, :cond_4

    .line 232
    .line 233
    iget-object p1, p1, Ln81/a;->f:Ll71/c;

    .line 234
    .line 235
    goto :goto_2

    .line 236
    :cond_4
    move-object p1, v1

    .line 237
    :goto_2
    invoke-direct {v2, v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ll71/c;)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    invoke-virtual {v2, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->equals(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    move-result p0

    .line 248
    if-nez p0, :cond_5

    .line 249
    .line 250
    move-object v1, v2

    .line 251
    :cond_5
    return-object v1

    .line 252
    :pswitch_d
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingForward;

    .line 253
    .line 254
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 255
    .line 256
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingForward;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingForward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$DriveCorrectionSubState;

    .line 257
    .line 258
    .line 259
    move-result-object p0

    .line 260
    return-object p0

    .line 261
    :pswitch_e
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingBackward;

    .line 262
    .line 263
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 264
    .line 265
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingBackward;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingBackward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$DriveCorrectionSubState;

    .line 266
    .line 267
    .line 268
    move-result-object p0

    .line 269
    return-object p0

    .line 270
    :pswitch_f
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedParking;

    .line 271
    .line 272
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 273
    .line 274
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedParking;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedParking;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 275
    .line 276
    .line 277
    move-result-object p0

    .line 278
    return-object p0

    .line 279
    :pswitch_10
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedAndHoldKeyInterruption;

    .line 280
    .line 281
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 282
    .line 283
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedAndHoldKeyInterruption;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedAndHoldKeyInterruption;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 284
    .line 285
    .line 286
    move-result-object p0

    .line 287
    return-object p0

    .line 288
    :pswitch_11
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingForward;

    .line 289
    .line 290
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 291
    .line 292
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingForward;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingForward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedParking;

    .line 293
    .line 294
    .line 295
    move-result-object p0

    .line 296
    return-object p0

    .line 297
    :pswitch_12
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingBackward;

    .line 298
    .line 299
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 300
    .line 301
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingBackward;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingBackward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedParking;

    .line 302
    .line 303
    .line 304
    move-result-object p0

    .line 305
    return-object p0

    .line 306
    :pswitch_13
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$Init;

    .line 307
    .line 308
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 309
    .line 310
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$Init;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$Init;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    return-object p0

    .line 315
    :pswitch_14
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;

    .line 316
    .line 317
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 318
    .line 319
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;

    .line 320
    .line 321
    .line 322
    move-result-object p0

    .line 323
    return-object p0

    .line 324
    :pswitch_15
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/b;

    .line 325
    .line 326
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 327
    .line 328
    const-string v0, "it"

    .line 329
    .line 330
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 331
    .line 332
    .line 333
    iget-object p0, p0, Lo81/a;->b:Lla/p;

    .line 334
    .line 335
    invoke-virtual {p0, p1}, Lla/p;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object p0

    .line 339
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 340
    .line 341
    return-object p0

    .line 342
    :pswitch_16
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$WaitingForResponse;

    .line 343
    .line 344
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 345
    .line 346
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$WaitingForResponse;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$WaitingForResponse;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 347
    .line 348
    .line 349
    move-result-object p0

    .line 350
    return-object p0

    .line 351
    :pswitch_17
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingNotAllowed;

    .line 352
    .line 353
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 354
    .line 355
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingNotAllowed;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingNotAllowed;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 356
    .line 357
    .line 358
    move-result-object p0

    .line 359
    return-object p0

    .line 360
    :pswitch_18
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingAllowed;

    .line 361
    .line 362
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 363
    .line 364
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingAllowed;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingAllowed;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 365
    .line 366
    .line 367
    move-result-object p0

    .line 368
    return-object p0

    .line 369
    :pswitch_19
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;

    .line 370
    .line 371
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 372
    .line 373
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 374
    .line 375
    .line 376
    move-result-object p0

    .line 377
    return-object p0

    .line 378
    :pswitch_1a
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressTimeThresholdNotReached;

    .line 379
    .line 380
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 381
    .line 382
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressTimeThresholdNotReached;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressTimeThresholdNotReached;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 383
    .line 384
    .line 385
    move-result-object p0

    .line 386
    return-object p0

    .line 387
    :pswitch_1b
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;

    .line 388
    .line 389
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 390
    .line 391
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 392
    .line 393
    .line 394
    move-result-object p0

    .line 395
    return-object p0

    .line 396
    :pswitch_1c
    check-cast p0, Lx61/a;

    .line 397
    .line 398
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 399
    .line 400
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->b(Lx61/a;Landroidx/compose/runtime/DisposableEffectScope;)Ll2/j0;

    .line 401
    .line 402
    .line 403
    move-result-object p0

    .line 404
    return-object p0

    .line 405
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
