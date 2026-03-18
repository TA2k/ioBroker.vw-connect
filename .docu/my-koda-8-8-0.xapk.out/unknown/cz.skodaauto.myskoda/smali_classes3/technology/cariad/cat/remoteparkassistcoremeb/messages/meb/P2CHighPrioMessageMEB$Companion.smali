.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessageDefinition;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0005\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0002\u0008\u0005\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0010\u0010\u001e\u001a\u0004\u0018\u00010\u001f2\u0006\u0010 \u001a\u00020!R\u0014\u0010\u0004\u001a\u00020\u0005X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007R\u0014\u0010\u0008\u001a\u00020\tX\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0014\u0010\u000c\u001a\u00020\u0005X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u0007R\u0014\u0010\u000e\u001a\u00020\u000fX\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\u0011R\u0014\u0010\u0012\u001a\u00020\u0013X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0015R\u000e\u0010\u0016\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0018\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0019\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001a\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001b\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001c\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001d\u001a\u00020\u0017X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\""
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessageDefinition;",
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
        "ALIVE_COUNTER",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;",
        "TOUCH_POS_X",
        "ENGINE_START_REQUEST",
        "USER_COMMAND_INVERTED",
        "TOUCH_POS_Y",
        "USER_COMMAND",
        "APP_LOCK_STATE",
        "create",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;",
        "payload",
        "",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;
    .locals 11

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
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;->getByteLength()I

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
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->getEntries()Lsx0/a;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getUSER_COMMAND$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-static {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 36
    .line 37
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->getEntries()Lsx0/a;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getUSER_COMMAND_INVERTED$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-static {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    invoke-static {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SignalsMEBKt;->invert(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;)I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-ne v2, v3, :cond_1

    .line 64
    .line 65
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 66
    .line 67
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getALIVE_COUNTER$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 72
    .line 73
    .line 74
    move-result v5

    .line 75
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->getEntries()Lsx0/a;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getUSER_COMMAND$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-static {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    move-object v6, p1

    .line 92
    check-cast v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 93
    .line 94
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getENGINE_START_REQUEST$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getBool-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)Z

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getTOUCH_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 107
    .line 108
    .line 109
    move-result v8

    .line 110
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getTOUCH_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 115
    .line 116
    .line 117
    move-result v9

    .line 118
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;->getEntries()Lsx0/a;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getAPP_LOCK_STATE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    invoke-static {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    move-object v10, p0

    .line 135
    check-cast v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    .line 136
    .line 137
    invoke-direct/range {v4 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;)V

    .line 138
    .line 139
    .line 140
    return-object v4

    .line 141
    :cond_1
    new-instance p0, Ljava/lang/Exception;

    .line 142
    .line 143
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteHexStringExtensionsKt;->toHexString([B)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    const-string v2, "! Reason: userCommand: "

    .line 156
    .line 157
    const-string v3, " do not match to userCommandInverted: "

    .line 158
    .line 159
    const-string v4, "Could not create a P2CHighPrioMessageMEB with payload: "

    .line 160
    .line 161
    invoke-static {v4, p1, v2, v0, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    const-string v0, "."

    .line 166
    .line 167
    invoke-static {p1, v1, v0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    throw p0
.end method

.method public getAddress()J
    .locals 2

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getAddress$cp()J

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
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getByteLength$cp()I

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
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getMessageID$cp()B

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
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getPriority$cp()B

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
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->access$getRequiresQueuing$cp()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method
