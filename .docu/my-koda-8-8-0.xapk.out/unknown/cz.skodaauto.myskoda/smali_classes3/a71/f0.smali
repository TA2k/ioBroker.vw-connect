.class public final synthetic La71/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/t2;

.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Ll2/t2;

.field public final synthetic h:Ll2/t2;

.field public final synthetic i:Ll2/t2;

.field public final synthetic j:Ll2/t2;

.field public final synthetic k:Ll2/t2;

.field public final synthetic l:Ll2/b1;

.field public final synthetic m:Ll2/b1;

.field public final synthetic n:Ll2/t2;

.field public final synthetic o:Ll2/t2;

.field public final synthetic p:Ll2/t2;

.field public final synthetic q:Ll2/t2;


# direct methods
.method public synthetic constructor <init>(Ll2/t2;Ll2/b1;Ll2/t2;Ll2/t2;Ll2/t2;Ll2/t2;Ll2/t2;Ll2/b1;Ll2/b1;Ll2/t2;Ll2/t2;Ll2/t2;Ll2/t2;I)V
    .locals 0

    .line 1
    iput p14, p0, La71/f0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La71/f0;->e:Ll2/t2;

    .line 4
    .line 5
    iput-object p2, p0, La71/f0;->f:Ll2/b1;

    .line 6
    .line 7
    iput-object p3, p0, La71/f0;->g:Ll2/t2;

    .line 8
    .line 9
    iput-object p4, p0, La71/f0;->h:Ll2/t2;

    .line 10
    .line 11
    iput-object p5, p0, La71/f0;->i:Ll2/t2;

    .line 12
    .line 13
    iput-object p6, p0, La71/f0;->j:Ll2/t2;

    .line 14
    .line 15
    iput-object p7, p0, La71/f0;->k:Ll2/t2;

    .line 16
    .line 17
    iput-object p8, p0, La71/f0;->l:Ll2/b1;

    .line 18
    .line 19
    iput-object p9, p0, La71/f0;->m:Ll2/b1;

    .line 20
    .line 21
    iput-object p10, p0, La71/f0;->n:Ll2/t2;

    .line 22
    .line 23
    iput-object p11, p0, La71/f0;->o:Ll2/t2;

    .line 24
    .line 25
    iput-object p12, p0, La71/f0;->p:Ll2/t2;

    .line 26
    .line 27
    iput-object p13, p0, La71/f0;->q:Ll2/t2;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, La71/f0;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance v2, La71/f0;

    .line 9
    .line 10
    const/16 v16, 0x0

    .line 11
    .line 12
    iget-object v3, v0, La71/f0;->e:Ll2/t2;

    .line 13
    .line 14
    iget-object v4, v0, La71/f0;->f:Ll2/b1;

    .line 15
    .line 16
    iget-object v5, v0, La71/f0;->g:Ll2/t2;

    .line 17
    .line 18
    iget-object v6, v0, La71/f0;->h:Ll2/t2;

    .line 19
    .line 20
    iget-object v7, v0, La71/f0;->i:Ll2/t2;

    .line 21
    .line 22
    iget-object v8, v0, La71/f0;->j:Ll2/t2;

    .line 23
    .line 24
    iget-object v9, v0, La71/f0;->k:Ll2/t2;

    .line 25
    .line 26
    iget-object v10, v0, La71/f0;->l:Ll2/b1;

    .line 27
    .line 28
    iget-object v11, v0, La71/f0;->m:Ll2/b1;

    .line 29
    .line 30
    iget-object v12, v0, La71/f0;->n:Ll2/t2;

    .line 31
    .line 32
    iget-object v13, v0, La71/f0;->o:Ll2/t2;

    .line 33
    .line 34
    iget-object v14, v0, La71/f0;->p:Ll2/t2;

    .line 35
    .line 36
    iget-object v15, v0, La71/f0;->q:Ll2/t2;

    .line 37
    .line 38
    invoke-direct/range {v2 .. v16}, La71/f0;-><init>(Ll2/t2;Ll2/b1;Ll2/t2;Ll2/t2;Ll2/t2;Ll2/t2;Ll2/t2;Ll2/b1;Ll2/b1;Ll2/t2;Ll2/t2;Ll2/t2;Ll2/t2;I)V

    .line 39
    .line 40
    .line 41
    const/4 v0, 0x0

    .line 42
    const-string v1, "SkodaRPAPlugin"

    .line 43
    .line 44
    invoke-static {v1, v0, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logVerbose(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 45
    .line 46
    .line 47
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_0
    iget-object v1, v0, La71/f0;->e:Ll2/t2;

    .line 51
    .line 52
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    check-cast v1, Lx61/b;

    .line 57
    .line 58
    iget-object v2, v0, La71/f0;->f:Ll2/b1;

    .line 59
    .line 60
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    check-cast v2, Ls71/h;

    .line 65
    .line 66
    iget-object v3, v0, La71/f0;->g:Ll2/t2;

    .line 67
    .line 68
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    check-cast v3, Ljava/lang/Boolean;

    .line 73
    .line 74
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    iget-object v4, v0, La71/f0;->h:Ll2/t2;

    .line 79
    .line 80
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    check-cast v4, Ljava/lang/Boolean;

    .line 85
    .line 86
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    iget-object v5, v0, La71/f0;->i:Ll2/t2;

    .line 91
    .line 92
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    check-cast v5, Ljava/lang/Boolean;

    .line 97
    .line 98
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    iget-object v6, v0, La71/f0;->j:Ll2/t2;

    .line 103
    .line 104
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    check-cast v6, Lt71/d;

    .line 109
    .line 110
    iget-object v7, v0, La71/f0;->k:Ll2/t2;

    .line 111
    .line 112
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v7

    .line 116
    check-cast v7, Ljava/lang/Boolean;

    .line 117
    .line 118
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 119
    .line 120
    .line 121
    move-result v7

    .line 122
    iget-object v8, v0, La71/f0;->l:Ll2/b1;

    .line 123
    .line 124
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v8

    .line 128
    check-cast v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 129
    .line 130
    iget-object v9, v0, La71/f0;->m:Ll2/b1;

    .line 131
    .line 132
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v9

    .line 136
    check-cast v9, Ls71/k;

    .line 137
    .line 138
    iget-object v10, v0, La71/f0;->n:Ll2/t2;

    .line 139
    .line 140
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v10

    .line 144
    check-cast v10, Ljava/lang/Boolean;

    .line 145
    .line 146
    invoke-virtual {v10}, Ljava/lang/Boolean;->booleanValue()Z

    .line 147
    .line 148
    .line 149
    move-result v10

    .line 150
    iget-object v11, v0, La71/f0;->o:Ll2/t2;

    .line 151
    .line 152
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v11

    .line 156
    check-cast v11, Ljava/lang/Boolean;

    .line 157
    .line 158
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 159
    .line 160
    .line 161
    move-result v11

    .line 162
    iget-object v12, v0, La71/f0;->p:Ll2/t2;

    .line 163
    .line 164
    invoke-interface {v12}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v12

    .line 168
    check-cast v12, Ljava/util/Set;

    .line 169
    .line 170
    iget-object v0, v0, La71/f0;->q:Ll2/t2;

    .line 171
    .line 172
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    check-cast v0, Ljava/util/Set;

    .line 177
    .line 178
    new-instance v13, Ljava/lang/StringBuilder;

    .line 179
    .line 180
    const-string v14, "ScenarioSelectionAndDriveScreen: screenType= "

    .line 181
    .line 182
    invoke-direct {v13, v14}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    const-string v1, "parkingManeuverStatus= "

    .line 189
    .line 190
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    invoke-virtual {v13, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    const-string v1, "\nisUndoActionSupported= "

    .line 197
    .line 198
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    const-string v1, "\nisParkActionPossible= "

    .line 202
    .line 203
    const-string v2, "\nisUndoActionPossible= "

    .line 204
    .line 205
    invoke-static {v13, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v13, v5}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    const-string v1, "\ndriveMovementStatus= "

    .line 212
    .line 213
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 214
    .line 215
    .line 216
    invoke-virtual {v13, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    const-string v1, "\nisInTargetPosition= "

    .line 220
    .line 221
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 222
    .line 223
    .line 224
    invoke-virtual {v13, v7}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 225
    .line 226
    .line 227
    const-string v1, "\nerror= "

    .line 228
    .line 229
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 230
    .line 231
    .line 232
    invoke-virtual {v13, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 233
    .line 234
    .line 235
    const-string v1, "\ncurrentSelectedScenario= "

    .line 236
    .line 237
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 238
    .line 239
    .line 240
    invoke-virtual {v13, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 241
    .line 242
    .line 243
    const-string v1, "\nisWaitingForScenarioSelectionConfirmation= "

    .line 244
    .line 245
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    invoke-virtual {v13, v10}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    const-string v1, "\nisSelectionDisabled= "

    .line 252
    .line 253
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 254
    .line 255
    .line 256
    invoke-virtual {v13, v11}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 257
    .line 258
    .line 259
    const-string v1, "\nsupportedScenarios= "

    .line 260
    .line 261
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 262
    .line 263
    .line 264
    invoke-virtual {v13, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    const-string v1, "\nenabledScenarios= "

    .line 268
    .line 269
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 270
    .line 271
    .line 272
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    const-string v0, "\n"

    .line 276
    .line 277
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 278
    .line 279
    .line 280
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    return-object v0

    .line 285
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
