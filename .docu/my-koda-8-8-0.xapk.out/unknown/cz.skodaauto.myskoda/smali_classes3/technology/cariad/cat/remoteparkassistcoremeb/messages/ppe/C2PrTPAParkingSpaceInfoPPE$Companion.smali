.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessageDefinition;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0005\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0002\u0008\u0005\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0010\u0010\u001f\u001a\u00020\u00182\u0006\u0010 \u001a\u00020\u0013H\u0002J\u0010\u0010!\u001a\u0004\u0018\u00010\"2\u0006\u0010#\u001a\u00020$R\u0014\u0010\u0004\u001a\u00020\u0005X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007R\u0014\u0010\u0008\u001a\u00020\tX\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0014\u0010\u000c\u001a\u00020\u0005X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u0007R\u0014\u0010\u000e\u001a\u00020\u000fX\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\u0011R\u0014\u0010\u0012\u001a\u00020\u0013X\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0015R\u000e\u0010\u0016\u001a\u00020\u0013X\u0080T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0017\u001a\u00020\u0018X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0019\u001a\u00020\u0018X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001a\u001a\u00020\u0018X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001b\u001a\u00020\u0018X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001c\u001a\u00020\u0018X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001d\u001a\u00020\u0018X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001e\u001a\u00020\u0018X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006%"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;",
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
        "MINIMAL_BYTE_LENGTH",
        "NUMBER_OF_AVAILABLE_PARKING_SLOTS",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;",
        "PARKING_SLOT_ID",
        "PARKING_SLOT_ICON_ID",
        "AVAILABLE_SCENARIO",
        "TPA_STATUS",
        "IS_CURRENT_SELECTED_PARKING_SLOT",
        "NAME_LENGTH",
        "getNameBitPacket",
        "nameLength",
        "create",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;-><init>()V

    return-void
.end method

.method public static final synthetic access$getNameBitPacket(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;I)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;->getNameBitPacket(I)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final getNameBitPacket(I)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    mul-int/lit8 p1, p1, 0x8

    .line 4
    .line 5
    const/16 v0, 0x20

    .line 6
    .line 7
    invoke-direct {p0, v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method


# virtual methods
.method public final create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;
    .locals 13

    .line 1
    const-string v0, "payload"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;->getByteLength()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    array-length v1, p1

    .line 11
    const/4 v2, 0x4

    .line 12
    const/4 v3, 0x0

    .line 13
    if-gt v2, v1, :cond_1

    .line 14
    .line 15
    if-gt v1, v0, :cond_1

    .line 16
    .line 17
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toUBytes([B)[B

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getNAME_LENGTH$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 26
    .line 27
    .line 28
    move-result v11

    .line 29
    invoke-direct {p0, v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;->getNameBitPacket(I)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getString-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getNUMBER_OF_AVAILABLE_PARKING_SLOTS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-static {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getPARKING_SLOT_ID$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-static {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getPARKING_SLOT_ICON_ID$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-static {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 58
    .line 59
    .line 60
    move-result v7

    .line 61
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;->getEntries()Lsx0/a;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getAVAILABLE_SCENARIO$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    invoke-static {p1, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    move-object v8, v0

    .line 78
    check-cast v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 79
    .line 80
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->getEntries()Lsx0/a;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getTPA_STATUS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    invoke-static {p1, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getInt-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)I

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    move-object v9, v0

    .line 97
    check-cast v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 98
    .line 99
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getIS_CURRENT_SELECTED_PARKING_SLOT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    invoke-static {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->getBool-rto03Yo([BLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)Z

    .line 104
    .line 105
    .line 106
    move-result v10

    .line 107
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 108
    .line 109
    .line 110
    move-result p1

    .line 111
    if-nez p1, :cond_0

    .line 112
    .line 113
    move-object v12, v3

    .line 114
    goto :goto_0

    .line 115
    :cond_0
    move-object v12, p0

    .line 116
    :goto_0
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 117
    .line 118
    invoke-direct/range {v4 .. v12}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;-><init>(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;)V

    .line 119
    .line 120
    .line 121
    return-object v4

    .line 122
    :cond_1
    return-object v3
.end method

.method public getAddress()J
    .locals 2

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getAddress$cp()J

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
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getByteLength$cp()I

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
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getMessageID$cp()B

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
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getPriority$cp()B

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
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->access$getRequiresQueuing$cp()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method
