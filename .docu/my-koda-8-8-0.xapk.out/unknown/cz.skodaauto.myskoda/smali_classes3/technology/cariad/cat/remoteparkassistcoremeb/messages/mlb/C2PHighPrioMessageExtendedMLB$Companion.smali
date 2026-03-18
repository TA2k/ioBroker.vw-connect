.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessageDefinition;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0005\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0002\u0008\u0005\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0010\u0010 \u001a\u0004\u0018\u00010!2\u0006\u0010\"\u001a\u00020#J\n\u0010$\u001a\u00020!*\u00020%R\u0014\u0010\u0004\u001a\u00020\u0005X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007R\u0014\u0010\u0008\u001a\u00020\tX\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0014\u0010\u000c\u001a\u00020\u0005X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u0007R\u0014\u0010\u000e\u001a\u00020\u000fX\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\u0011R\u0014\u0010\u0012\u001a\u00020\u0013X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0015R\u000e\u0010\u0016\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0018\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0019\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001a\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001b\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001c\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001d\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001e\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001f\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006&"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB$Companion;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessageDefinition;",
        "<init>",
        "()V",
        "messageID",
        "",
        "getMessageID",
        "()B",
        "address",
        "",
        "getAddress",
        "()J",
        "priority",
        "getPriority",
        "requiresQueuing",
        "",
        "getRequiresQueuing",
        "()Z",
        "byteLength",
        "",
        "getByteLength",
        "()I",
        "FUNCTION_STATE",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;",
        "OBSTACLE_DETECTED",
        "FFB_KEY_STATUS",
        "TOUCH_DIAGNOSIS_REQUEST",
        "STOPPING_REASON",
        "HMS_SYSTEM_STATE",
        "MO_READY_TO_DRIVE",
        "CURRENT_GEAR",
        "DDA_STATE",
        "create",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;",
        "payload",
        "",
        "toExtended",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;",
        "remoteparkassistcoremeb_release"
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
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;
    .locals 10

    .line 1
    const-string v0, "payload"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p1

    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB$Companion;->getByteLength()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eq v0, p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    return-object p0

    .line 15
    :cond_0
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toUBytes([B)[B

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 20
    .line 21
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->getEntries()Lsx0/a;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getFUNCTION_STATE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-static {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    move-object v1, p1

    .line 38
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 39
    .line 40
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;->getEntries()Lsx0/a;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getOBSTACLE_DETECTED$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-static {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    move-object v2, p1

    .line 57
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;

    .line 58
    .line 59
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->getEntries()Lsx0/a;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getFFB_KEY_STATUS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-static {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    invoke-interface {p1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    move-object v3, p1

    .line 76
    check-cast v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 77
    .line 78
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getTOUCH_DIAGNOSIS_REQUEST$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getBool-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)Z

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->getEntries()Lsx0/a;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getSTOPPING_REASON$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    invoke-static {p0, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 95
    .line 96
    .line 97
    move-result v5

    .line 98
    invoke-interface {p1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    move-object v5, p1

    .line 103
    check-cast v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 104
    .line 105
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;->getEntries()Lsx0/a;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getHMS_SYSTEM_STATE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    invoke-static {p0, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 114
    .line 115
    .line 116
    move-result v6

    .line 117
    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    move-object v6, p1

    .line 122
    check-cast v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;

    .line 123
    .line 124
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;->getEntries()Lsx0/a;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getMO_READY_TO_DRIVE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 129
    .line 130
    .line 131
    move-result-object v7

    .line 132
    invoke-static {p0, v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 133
    .line 134
    .line 135
    move-result v7

    .line 136
    invoke-interface {p1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    move-object v7, p1

    .line 141
    check-cast v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;

    .line 142
    .line 143
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;->getEntries()Lsx0/a;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getCURRENT_GEAR$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 148
    .line 149
    .line 150
    move-result-object v8

    .line 151
    invoke-static {p0, v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 152
    .line 153
    .line 154
    move-result v8

    .line 155
    invoke-interface {p1, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    move-object v8, p1

    .line 160
    check-cast v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;

    .line 161
    .line 162
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;->getEntries()Lsx0/a;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getDDA_STATE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 167
    .line 168
    .line 169
    move-result-object v9

    .line 170
    invoke-static {p0, v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 171
    .line 172
    .line 173
    move-result p0

    .line 174
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    move-object v9, p0

    .line 179
    check-cast v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;

    .line 180
    .line 181
    invoke-direct/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;)V

    .line 182
    .line 183
    .line 184
    return-object v0
.end method

.method public getAddress()J
    .locals 2

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getAddress$cp()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public getByteLength()I
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getByteLength$cp()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getMessageID()B
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getMessageID$cp()B

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getPriority()B
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getPriority$cp()B

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getRequiresQueuing()Z
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->access$getRequiresQueuing$cp()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final toExtended(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;
    .locals 10

    .line 1
    const-string p0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 7
    .line 8
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getObstacleStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getKeyStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->isTouchDiagnosisRequest()Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/SignalsMLBKt;->toExtended(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getHandbrakeStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;

    .line 33
    .line 34
    .line 35
    move-result-object v6

    .line 36
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getEngineStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getGearStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getDdaStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;

    .line 45
    .line 46
    .line 47
    move-result-object v9

    .line 48
    invoke-direct/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;)V

    .line 49
    .line 50
    .line 51
    return-object v0
.end method
