.class public final synthetic Lh2/d9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/d9;->d:I

    iput-object p1, p0, Lh2/d9;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Lh2/d9;->e:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/Object;I)V
    .locals 0

    .line 2
    iput p3, p0, Lh2/d9;->d:I

    iput-boolean p1, p0, Lh2/d9;->e:Z

    iput-object p2, p0, Lh2/d9;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lh2/d9;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/d9;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroid/app/Activity;

    .line 9
    .line 10
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 11
    .line 12
    const-string v1, "$this$DisposableEffect"

    .line 13
    .line 14
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-boolean p0, p0, Lh2/d9;->e:Z

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    new-instance p0, Lw81/d;

    .line 22
    .line 23
    const/16 p1, 0x18

    .line 24
    .line 25
    invoke-direct {p0, p1}, Lw81/d;-><init>(I)V

    .line 26
    .line 27
    .line 28
    const/16 p1, 0x21

    .line 29
    .line 30
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 31
    .line 32
    if-lt v1, p1, :cond_0

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Lw81/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    invoke-virtual {v0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    const/16 p1, 0x2000

    .line 43
    .line 44
    invoke-virtual {p0, p1, p1}, Landroid/view/Window;->setFlags(II)V

    .line 45
    .line 46
    .line 47
    :cond_1
    :goto_0
    new-instance p0, La2/j;

    .line 48
    .line 49
    const/16 p1, 0x14

    .line 50
    .line 51
    invoke-direct {p0, v0, p1}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    return-object p0

    .line 55
    :pswitch_0
    iget-object v0, p0, Lh2/d9;->f:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;

    .line 58
    .line 59
    iget-boolean p0, p0, Lh2/d9;->e:Z

    .line 60
    .line 61
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 62
    .line 63
    invoke-static {v0, p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :pswitch_1
    iget-object v0, p0, Lh2/d9;->f:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;

    .line 71
    .line 72
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 73
    .line 74
    iget-boolean p0, p0, Lh2/d9;->e:Z

    .line 75
    .line 76
    invoke-static {p0, v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;->a(ZLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_2
    iget-object v0, p0, Lh2/d9;->f:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v0, Lr31/i;

    .line 84
    .line 85
    move-object v1, p1

    .line 86
    check-cast v1, Li31/b;

    .line 87
    .line 88
    const-string p1, "$this$updateCurrentAppointmentUseCase"

    .line 89
    .line 90
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0}, Lq41/b;->a()Lq41/a;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    check-cast p1, Lr31/j;

    .line 98
    .line 99
    iget-object p1, p1, Lr31/j;->a:Ljava/lang/String;

    .line 100
    .line 101
    iget-boolean p0, p0, Lh2/d9;->e:Z

    .line 102
    .line 103
    if-nez p0, :cond_2

    .line 104
    .line 105
    :goto_1
    move-object v8, p1

    .line 106
    goto :goto_2

    .line 107
    :cond_2
    const/4 p1, 0x0

    .line 108
    goto :goto_1

    .line 109
    :goto_2
    const/16 v9, 0x3f

    .line 110
    .line 111
    const/4 v2, 0x0

    .line 112
    const/4 v3, 0x0

    .line 113
    const/4 v4, 0x0

    .line 114
    const/4 v5, 0x0

    .line 115
    const/4 v6, 0x0

    .line 116
    const/4 v7, 0x0

    .line 117
    invoke-static/range {v1 .. v9}, Li31/b;->a(Li31/b;Ljava/lang/String;Li31/b0;Ljava/lang/Long;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;I)Li31/b;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    return-object p0

    .line 122
    :pswitch_3
    iget-object v0, p0, Lh2/d9;->f:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$MLBUnlockSubState;

    .line 125
    .line 126
    iget-boolean p0, p0, Lh2/d9;->e:Z

    .line 127
    .line 128
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 129
    .line 130
    invoke-static {v0, p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$MLBUnlockSubState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$MLBUnlockSubState;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0

    .line 135
    :pswitch_4
    iget-object v0, p0, Lh2/d9;->f:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v0, Ljava/lang/StringBuilder;

    .line 138
    .line 139
    check-cast p1, Ljava/lang/Byte;

    .line 140
    .line 141
    invoke-virtual {p1}, Ljava/lang/Byte;->byteValue()B

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    sget-object v2, Low0/a;->a:Ljava/util/Set;

    .line 146
    .line 147
    invoke-interface {v2, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v2

    .line 151
    if-nez v2, :cond_5

    .line 152
    .line 153
    sget-object v2, Low0/a;->e:Ljava/util/ArrayList;

    .line 154
    .line 155
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result p1

    .line 159
    if-eqz p1, :cond_3

    .line 160
    .line 161
    goto :goto_3

    .line 162
    :cond_3
    iget-boolean p0, p0, Lh2/d9;->e:Z

    .line 163
    .line 164
    if-eqz p0, :cond_4

    .line 165
    .line 166
    const/16 p0, 0x20

    .line 167
    .line 168
    if-ne v1, p0, :cond_4

    .line 169
    .line 170
    const/16 p0, 0x2b

    .line 171
    .line 172
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_4
    invoke-static {v1}, Low0/a;->g(B)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    goto :goto_4

    .line 184
    :cond_5
    :goto_3
    int-to-char p0, v1

    .line 185
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 189
    .line 190
    return-object p0

    .line 191
    :pswitch_5
    iget-object v0, p0, Lh2/d9;->f:Ljava/lang/Object;

    .line 192
    .line 193
    move-object v2, v0

    .line 194
    check-cast v2, Lmc0/d;

    .line 195
    .line 196
    move-object v3, p1

    .line 197
    check-cast v3, Ljava/lang/String;

    .line 198
    .line 199
    invoke-static {v2}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    new-instance v1, Lbp0/g;

    .line 204
    .line 205
    const/4 v6, 0x5

    .line 206
    iget-boolean v4, p0, Lh2/d9;->e:Z

    .line 207
    .line 208
    const/4 v5, 0x0

    .line 209
    invoke-direct/range {v1 .. v6}, Lbp0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 210
    .line 211
    .line 212
    const/4 p0, 0x3

    .line 213
    invoke-static {p1, v5, v5, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 214
    .line 215
    .line 216
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 217
    .line 218
    return-object p0

    .line 219
    :pswitch_6
    iget-object v0, p0, Lh2/d9;->f:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v0, Lc1/c;

    .line 222
    .line 223
    check-cast p1, Lt4/c;

    .line 224
    .line 225
    const-string v1, "$this$offset"

    .line 226
    .line 227
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    iget-boolean p0, p0, Lh2/d9;->e:Z

    .line 231
    .line 232
    const/4 p1, 0x0

    .line 233
    if-eqz p0, :cond_6

    .line 234
    .line 235
    move p0, p1

    .line 236
    goto :goto_5

    .line 237
    :cond_6
    invoke-virtual {v0}, Lc1/c;->d()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    check-cast p0, Ljava/lang/Number;

    .line 242
    .line 243
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 244
    .line 245
    .line 246
    move-result p0

    .line 247
    float-to-int p0, p0

    .line 248
    :goto_5
    int-to-long v0, p0

    .line 249
    const/16 p0, 0x20

    .line 250
    .line 251
    shl-long/2addr v0, p0

    .line 252
    int-to-long p0, p1

    .line 253
    const-wide v2, 0xffffffffL

    .line 254
    .line 255
    .line 256
    .line 257
    .line 258
    and-long/2addr p0, v2

    .line 259
    or-long/2addr p0, v0

    .line 260
    new-instance v0, Lt4/j;

    .line 261
    .line 262
    invoke-direct {v0, p0, p1}, Lt4/j;-><init>(J)V

    .line 263
    .line 264
    .line 265
    return-object v0

    .line 266
    :pswitch_7
    iget-object v0, p0, Lh2/d9;->f:Ljava/lang/Object;

    .line 267
    .line 268
    check-cast v0, Lh2/s9;

    .line 269
    .line 270
    check-cast p1, Ld4/l;

    .line 271
    .line 272
    iget-boolean p0, p0, Lh2/d9;->e:Z

    .line 273
    .line 274
    if-nez p0, :cond_7

    .line 275
    .line 276
    invoke-static {p1}, Ld4/x;->a(Ld4/l;)V

    .line 277
    .line 278
    .line 279
    :cond_7
    iget-object p0, v0, Lh2/s9;->d:Ll2/f1;

    .line 280
    .line 281
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 282
    .line 283
    .line 284
    move-result p0

    .line 285
    invoke-static {p0}, Lh2/q9;->k(F)Ljava/lang/String;

    .line 286
    .line 287
    .line 288
    move-result-object p0

    .line 289
    invoke-static {p1, p0}, Ld4/x;->j(Ld4/l;Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    new-instance p0, Lh2/c9;

    .line 293
    .line 294
    const/4 v1, 0x1

    .line 295
    invoke-direct {p0, v0, v1}, Lh2/c9;-><init>(Lh2/s9;I)V

    .line 296
    .line 297
    .line 298
    invoke-static {p1, p0}, Ld4/x;->g(Ld4/l;Lay0/k;)V

    .line 299
    .line 300
    .line 301
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 302
    .line 303
    return-object p0

    .line 304
    nop

    .line 305
    :pswitch_data_0
    .packed-switch 0x0
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
