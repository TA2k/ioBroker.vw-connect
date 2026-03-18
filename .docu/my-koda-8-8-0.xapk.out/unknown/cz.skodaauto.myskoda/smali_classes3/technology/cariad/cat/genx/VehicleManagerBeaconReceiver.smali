.class public final Ltechnology/cariad/cat/genx/VehicleManagerBeaconReceiver;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u001f\u0010\t\u001a\u00020\u00082\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0006H\u0016\u00a2\u0006\u0004\u0008\t\u0010\n\u00a8\u0006\u000b"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleManagerBeaconReceiver;",
        "Landroid/content/BroadcastReceiver;",
        "<init>",
        "()V",
        "Landroid/content/Context;",
        "context",
        "Landroid/content/Intent;",
        "intent",
        "Llx0/b0;",
        "onReceive",
        "(Landroid/content/Context;Landroid/content/Intent;)V",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Landroid/content/Intent;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerBeaconReceiver;->onReceive$lambda$0(Landroid/content/Intent;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ljava/lang/String;Lt41/b;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerBeaconReceiver;->onReceive$lambda$2$1(Ljava/lang/String;Lt41/b;Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Ljava/lang/String;Lt41/b;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerBeaconReceiver;->onReceive$lambda$2$0(Ljava/lang/String;Lt41/b;Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Landroid/content/Intent;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerBeaconReceiver;->onReceive$lambda$1(Landroid/content/Intent;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final onReceive$lambda$0(Landroid/content/Intent;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "onReceive(): Action = "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final onReceive$lambda$1(Landroid/content/Intent;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "onReceive(): Received unknown action: \'"

    .line 6
    .line 7
    const-string v1, "\' -> Ignore"

    .line 8
    .line 9
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method private static final onReceive$lambda$2$0(Ljava/lang/String;Lt41/b;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onReceive(): "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, " beacon = "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string p0, ". -> Sending the \'"

    .line 20
    .line 21
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p0, "\' broadcast."

    .line 25
    .line 26
    invoke-static {v0, p2, p0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method private static final onReceive$lambda$2$1(Ljava/lang/String;Lt41/b;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onReceive(): "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, " beacon = "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string p0, ". -> App is active -> Do not send "

    .line 20
    .line 21
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p0, " broadcast."

    .line 25
    .line 26
    invoke-static {v0, p2, p0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method


# virtual methods
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 17

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    const-string v2, "context"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "intent"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v6, Ltechnology/cariad/cat/genx/g0;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-direct {v6, v1, v2}, Ltechnology/cariad/cat/genx/g0;-><init>(Landroid/content/Intent;I)V

    .line 19
    .line 20
    .line 21
    new-instance v3, Lt51/j;

    .line 22
    .line 23
    invoke-static/range {p0 .. p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v8

    .line 27
    const-string v2, "getName(...)"

    .line 28
    .line 29
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v9

    .line 33
    const-string v4, "GenX"

    .line 34
    .line 35
    sget-object v5, Lt51/g;->a:Lt51/g;

    .line 36
    .line 37
    const/4 v7, 0x0

    .line 38
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    if-eqz v3, :cond_4

    .line 49
    .line 50
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    const v6, 0x441e27bf

    .line 55
    .line 56
    .line 57
    if-eq v4, v6, :cond_2

    .line 58
    .line 59
    const v6, 0x7e143727

    .line 60
    .line 61
    .line 62
    if-eq v4, v6, :cond_0

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_0
    const-string v4, "technology.cariad.cat.beaconscanner.action.BEACON_LOST"

    .line 66
    .line 67
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-nez v3, :cond_1

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    const-string v3, "technology.cariad.cat.genx.action.BEACON_OUT_OF_RANGE"

    .line 75
    .line 76
    const-string v4, "BEACON_OUT_OF_RANGE"

    .line 77
    .line 78
    const-string v6, "Lost"

    .line 79
    .line 80
    :goto_0
    move-object/from16 v7, p0

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_2
    const-string v4, "technology.cariad.cat.beaconscanner.action.BEACON_FOUND"

    .line 84
    .line 85
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    if-nez v3, :cond_3

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_3
    const-string v3, "technology.cariad.cat.genx.action.BEACON_IN_RANGE"

    .line 93
    .line 94
    const-string v4, "BEACON_IN_RANGE"

    .line 95
    .line 96
    const-string v6, "Found"

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_4
    :goto_1
    new-instance v3, Ltechnology/cariad/cat/genx/g0;

    .line 100
    .line 101
    const/4 v4, 0x1

    .line 102
    invoke-direct {v3, v1, v4}, Ltechnology/cariad/cat/genx/g0;-><init>(Landroid/content/Intent;I)V

    .line 103
    .line 104
    .line 105
    const-string v4, "GenX"

    .line 106
    .line 107
    const/4 v6, 0x0

    .line 108
    move-object/from16 v7, p0

    .line 109
    .line 110
    invoke-static {v7, v4, v6, v3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 111
    .line 112
    .line 113
    move-object v3, v6

    .line 114
    move-object v4, v3

    .line 115
    :goto_2
    if-eqz v3, :cond_7

    .line 116
    .line 117
    sget v8, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 118
    .line 119
    const/16 v9, 0x21

    .line 120
    .line 121
    if-lt v8, v9, :cond_5

    .line 122
    .line 123
    invoke-static {v1}, Li2/p0;->h(Landroid/content/Intent;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    check-cast v1, Lt41/b;

    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_5
    const-string v8, "EXTRA_BEACON"

    .line 131
    .line 132
    invoke-virtual {v1, v8}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    check-cast v1, Lt41/b;

    .line 137
    .line 138
    :goto_3
    new-instance v8, Landroid/content/Intent;

    .line 139
    .line 140
    invoke-direct {v8, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    sget-object v3, Ltechnology/cariad/cat/genx/VehicleManager;->Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    .line 144
    .line 145
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->getINTENT_EXTRAS_BEACON()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    invoke-virtual {v8, v3, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 150
    .line 151
    .line 152
    sget-object v3, Landroidx/lifecycle/m0;->k:Landroidx/lifecycle/m0;

    .line 153
    .line 154
    iget-object v3, v3, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 155
    .line 156
    iget-object v3, v3, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 157
    .line 158
    sget-object v9, Landroidx/lifecycle/q;->h:Landroidx/lifecycle/q;

    .line 159
    .line 160
    if-eq v3, v9, :cond_6

    .line 161
    .line 162
    new-instance v13, Ltechnology/cariad/cat/genx/h0;

    .line 163
    .line 164
    const/4 v3, 0x0

    .line 165
    invoke-direct {v13, v6, v1, v4, v3}, Ltechnology/cariad/cat/genx/h0;-><init>(Ljava/lang/String;Lt41/b;Ljava/lang/String;I)V

    .line 166
    .line 167
    .line 168
    new-instance v10, Lt51/j;

    .line 169
    .line 170
    invoke-static {v7}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v15

    .line 174
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object v16

    .line 178
    const-string v11, "GenX"

    .line 179
    .line 180
    sget-object v12, Lt51/d;->a:Lt51/d;

    .line 181
    .line 182
    const/4 v14, 0x0

    .line 183
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    new-instance v2, Ljava/lang/StringBuilder;

    .line 194
    .line 195
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    const-string v1, ".genx.permission.BEACON_RANGING"

    .line 202
    .line 203
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v1

    .line 210
    invoke-virtual {v0, v8, v1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    return-void

    .line 214
    :cond_6
    new-instance v13, Ltechnology/cariad/cat/genx/h0;

    .line 215
    .line 216
    const/4 v0, 0x1

    .line 217
    invoke-direct {v13, v6, v1, v4, v0}, Ltechnology/cariad/cat/genx/h0;-><init>(Ljava/lang/String;Lt41/b;Ljava/lang/String;I)V

    .line 218
    .line 219
    .line 220
    new-instance v10, Lt51/j;

    .line 221
    .line 222
    invoke-static {v7}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v15

    .line 226
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object v16

    .line 230
    const-string v11, "GenX"

    .line 231
    .line 232
    const/4 v14, 0x0

    .line 233
    move-object v12, v5

    .line 234
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 238
    .line 239
    .line 240
    :cond_7
    return-void
.end method
