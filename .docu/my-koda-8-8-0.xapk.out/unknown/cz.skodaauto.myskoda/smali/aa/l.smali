.class public final synthetic Laa/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZLjava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Laa/l;->d:I

    iput-object p1, p0, Laa/l;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Laa/l;->e:Z

    iput-object p3, p0, Laa/l;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p4, p0, Laa/l;->d:I

    iput-boolean p1, p0, Laa/l;->e:Z

    iput-object p2, p0, Laa/l;->f:Ljava/lang/Object;

    iput-object p3, p0, Laa/l;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Laa/l;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x2

    .line 8
    const/4 v4, 0x1

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v6, 0x0

    .line 11
    iget-object v7, v0, Laa/l;->g:Ljava/lang/Object;

    .line 12
    .line 13
    iget-boolean v8, v0, Laa/l;->e:Z

    .line 14
    .line 15
    iget-object v0, v0, Laa/l;->f:Ljava/lang/Object;

    .line 16
    .line 17
    packed-switch v1, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    check-cast v0, Lxh/e;

    .line 21
    .line 22
    check-cast v7, Ljava/lang/String;

    .line 23
    .line 24
    move-object/from16 v1, p1

    .line 25
    .line 26
    check-cast v1, Lhi/a;

    .line 27
    .line 28
    const-string v2, "$this$sdkViewModel"

    .line 29
    .line 30
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-class v2, Luc/g;

    .line 34
    .line 35
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 36
    .line 37
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    check-cast v1, Lii/a;

    .line 42
    .line 43
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    move-object v11, v1

    .line 48
    check-cast v11, Luc/g;

    .line 49
    .line 50
    new-instance v9, Lth/b;

    .line 51
    .line 52
    const/4 v15, 0x0

    .line 53
    const/16 v16, 0x6

    .line 54
    .line 55
    const/4 v10, 0x2

    .line 56
    const-class v12, Luc/g;

    .line 57
    .line 58
    const-string v13, "addChargingCard"

    .line 59
    .line 60
    const-string v14, "addChargingCard-gIAlu-s(Lcariad/charging/multicharge/kitten/chargingcard/models/ChargingCardPostRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 61
    .line 62
    invoke-direct/range {v9 .. v16}, Lth/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 63
    .line 64
    .line 65
    new-instance v1, Lwc/g;

    .line 66
    .line 67
    invoke-direct {v1, v0, v9, v8, v7}, Lwc/g;-><init>(Lxh/e;Lth/b;ZLjava/lang/String;)V

    .line 68
    .line 69
    .line 70
    return-object v1

    .line 71
    :pswitch_0
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$MEBUnlockSubState;

    .line 72
    .line 73
    check-cast v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;

    .line 74
    .line 75
    move-object/from16 v1, p1

    .line 76
    .line 77
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 78
    .line 79
    invoke-static {v0, v8, v7, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$MEBUnlockSubState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$MEBUnlockSubState;ZLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    return-object v0

    .line 84
    :pswitch_1
    check-cast v0, Lp1/v;

    .line 85
    .line 86
    check-cast v7, Lvy0/b0;

    .line 87
    .line 88
    move-object/from16 v1, p1

    .line 89
    .line 90
    check-cast v1, Ld4/l;

    .line 91
    .line 92
    if-eqz v8, :cond_0

    .line 93
    .line 94
    new-instance v3, Lp1/j;

    .line 95
    .line 96
    invoke-direct {v3, v0, v7, v6}, Lp1/j;-><init>(Lp1/v;Lvy0/b0;I)V

    .line 97
    .line 98
    .line 99
    sget-object v6, Ld4/x;->a:[Lhy0/z;

    .line 100
    .line 101
    sget-object v6, Ld4/k;->x:Ld4/z;

    .line 102
    .line 103
    new-instance v8, Ld4/a;

    .line 104
    .line 105
    invoke-direct {v8, v5, v3}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v1, v6, v8}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    new-instance v3, Lp1/j;

    .line 112
    .line 113
    invoke-direct {v3, v0, v7, v4}, Lp1/j;-><init>(Lp1/v;Lvy0/b0;I)V

    .line 114
    .line 115
    .line 116
    sget-object v0, Ld4/k;->z:Ld4/z;

    .line 117
    .line 118
    new-instance v4, Ld4/a;

    .line 119
    .line 120
    invoke-direct {v4, v5, v3}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v1, v0, v4}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_0
    new-instance v4, Lp1/j;

    .line 128
    .line 129
    invoke-direct {v4, v0, v7, v3}, Lp1/j;-><init>(Lp1/v;Lvy0/b0;I)V

    .line 130
    .line 131
    .line 132
    sget-object v3, Ld4/x;->a:[Lhy0/z;

    .line 133
    .line 134
    sget-object v3, Ld4/k;->y:Ld4/z;

    .line 135
    .line 136
    new-instance v6, Ld4/a;

    .line 137
    .line 138
    invoke-direct {v6, v5, v4}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v1, v3, v6}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    new-instance v3, Lp1/j;

    .line 145
    .line 146
    const/4 v4, 0x3

    .line 147
    invoke-direct {v3, v0, v7, v4}, Lp1/j;-><init>(Lp1/v;Lvy0/b0;I)V

    .line 148
    .line 149
    .line 150
    sget-object v0, Ld4/k;->A:Ld4/z;

    .line 151
    .line 152
    new-instance v4, Ld4/a;

    .line 153
    .line 154
    invoke-direct {v4, v5, v3}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v1, v0, v4}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    :goto_0
    return-object v2

    .line 161
    :pswitch_2
    check-cast v0, Landroidx/media3/exoplayer/ExoPlayer;

    .line 162
    .line 163
    check-cast v7, Ll2/b1;

    .line 164
    .line 165
    move-object/from16 v1, p1

    .line 166
    .line 167
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 168
    .line 169
    const-string v2, "$this$DisposableEffect"

    .line 170
    .line 171
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    check-cast v0, La8/i0;

    .line 175
    .line 176
    invoke-virtual {v0}, La8/i0;->w0()V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v0, v4, v4}, La8/i0;->I0(IZ)V

    .line 183
    .line 184
    .line 185
    if-eqz v8, :cond_1

    .line 186
    .line 187
    move v3, v6

    .line 188
    :cond_1
    invoke-virtual {v0, v3}, La8/i0;->C0(I)V

    .line 189
    .line 190
    .line 191
    new-instance v1, Lio0/b;

    .line 192
    .line 193
    invoke-direct {v1, v7}, Lio0/b;-><init>(Ll2/b1;)V

    .line 194
    .line 195
    .line 196
    iget-object v2, v0, La8/i0;->q:Le30/v;

    .line 197
    .line 198
    invoke-virtual {v2, v1}, Le30/v;->a(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    new-instance v1, La2/j;

    .line 202
    .line 203
    const/16 v2, 0x8

    .line 204
    .line 205
    invoke-direct {v1, v0, v2}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 206
    .line 207
    .line 208
    return-object v1

    .line 209
    :pswitch_3
    check-cast v0, Ljava/lang/String;

    .line 210
    .line 211
    check-cast v7, Lh2/t9;

    .line 212
    .line 213
    move-object/from16 v1, p1

    .line 214
    .line 215
    check-cast v1, Ld4/l;

    .line 216
    .line 217
    if-eqz v8, :cond_2

    .line 218
    .line 219
    invoke-static {v1, v6}, Ld4/x;->e(Ld4/l;I)V

    .line 220
    .line 221
    .line 222
    :cond_2
    new-instance v3, Lh2/v9;

    .line 223
    .line 224
    invoke-direct {v3, v7, v6}, Lh2/v9;-><init>(Lh2/t9;I)V

    .line 225
    .line 226
    .line 227
    sget-object v4, Ld4/x;->a:[Lhy0/z;

    .line 228
    .line 229
    sget-object v4, Ld4/k;->u:Ld4/z;

    .line 230
    .line 231
    new-instance v6, Ld4/a;

    .line 232
    .line 233
    invoke-direct {v6, v5, v3}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v1, v4, v6}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    invoke-static {v1, v0}, Ld4/x;->f(Ld4/l;Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    return-object v2

    .line 243
    :pswitch_4
    check-cast v0, Lz9/k;

    .line 244
    .line 245
    check-cast v7, Ljava/util/List;

    .line 246
    .line 247
    move-object/from16 v1, p1

    .line 248
    .line 249
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 250
    .line 251
    new-instance v1, Laa/n;

    .line 252
    .line 253
    invoke-direct {v1, v8, v7, v0}, Laa/n;-><init>(ZLjava/util/List;Lz9/k;)V

    .line 254
    .line 255
    .line 256
    iget-object v2, v0, Lz9/k;->k:Lca/c;

    .line 257
    .line 258
    iget-object v2, v2, Lca/c;->j:Landroidx/lifecycle/z;

    .line 259
    .line 260
    invoke-virtual {v2, v1}, Landroidx/lifecycle/z;->a(Landroidx/lifecycle/w;)V

    .line 261
    .line 262
    .line 263
    new-instance v2, Laa/t;

    .line 264
    .line 265
    invoke-direct {v2, v6, v0, v1}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    return-object v2

    .line 269
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
