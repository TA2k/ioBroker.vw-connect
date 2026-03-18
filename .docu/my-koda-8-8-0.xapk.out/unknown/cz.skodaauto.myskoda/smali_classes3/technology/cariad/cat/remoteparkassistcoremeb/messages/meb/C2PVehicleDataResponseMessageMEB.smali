.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0006\n\u0002\u0010\u0012\n\u0002\u0008\u0011\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008\u0086\u0008\u0018\u0000 32\u00020\u0001:\u00013BM\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u0012\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u0006\u0012\u0008\u0008\u0002\u0010\t\u001a\u00020\u0006\u0012\u0008\u0008\u0002\u0010\n\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u000f\u0010\u000e\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u0010\u0010\u0012\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u0010\u0010\u0014\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u0013\u0010\u0011J\u0010\u0010\u0016\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u0015\u0010\u0011J\u0010\u0010\u0017\u001a\u00020\u0006H\u00c6\u0003\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u0010\u0010\u0019\u001a\u00020\u0006H\u00c6\u0003\u00a2\u0006\u0004\u0008\u0019\u0010\u0018J\u0010\u0010\u001a\u001a\u00020\u0006H\u00c6\u0003\u00a2\u0006\u0004\u0008\u001a\u0010\u0018J\u0010\u0010\u001b\u001a\u00020\u0006H\u00c6\u0003\u00a2\u0006\u0004\u0008\u001b\u0010\u0018JV\u0010\u001e\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u00062\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u00062\u0008\u0008\u0002\u0010\t\u001a\u00020\u00062\u0008\u0008\u0002\u0010\n\u001a\u00020\u0006H\u00c6\u0001\u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ\u0010\u0010 \u001a\u00020\u001fH\u00d6\u0001\u00a2\u0006\u0004\u0008 \u0010!J\u0010\u0010#\u001a\u00020\"H\u00d6\u0001\u00a2\u0006\u0004\u0008#\u0010$J\u001a\u0010\'\u001a\u00020\u00062\u0008\u0010&\u001a\u0004\u0018\u00010%H\u00d6\u0003\u00a2\u0006\u0004\u0008\'\u0010(R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010)\u001a\u0004\u0008*\u0010\u0011R\u0017\u0010\u0004\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0004\u0010)\u001a\u0004\u0008+\u0010\u0011R\u0017\u0010\u0005\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010)\u001a\u0004\u0008,\u0010\u0011R\u0017\u0010\u0007\u001a\u00020\u00068\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010-\u001a\u0004\u0008\u0007\u0010\u0018R\u0017\u0010\u0008\u001a\u00020\u00068\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0008\u0010-\u001a\u0004\u0008\u0008\u0010\u0018R\u0017\u0010\t\u001a\u00020\u00068\u0006\u00a2\u0006\u000c\n\u0004\u0008\t\u0010-\u001a\u0004\u0008\t\u0010\u0018R\u0017\u0010\n\u001a\u00020\u00068\u0006\u00a2\u0006\u000c\n\u0004\u0008\n\u0010-\u001a\u0004\u0008\n\u0010\u0018R\u001a\u0010/\u001a\u00020.8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008/\u00100\u001a\u0004\u00081\u00102\u00a8\u00064"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "Llx0/s;",
        "majorVersion",
        "minorVersion",
        "patchVersion",
        "",
        "isSunroofEquipped",
        "isElectricalVehicle",
        "isHALEquipped",
        "isLWBEquipped",
        "<init>",
        "(BBBZZZZLkotlin/jvm/internal/g;)V",
        "",
        "toBytes",
        "()[B",
        "component1-w2LRezQ",
        "()B",
        "component1",
        "component2-w2LRezQ",
        "component2",
        "component3-w2LRezQ",
        "component3",
        "component4",
        "()Z",
        "component5",
        "component6",
        "component7",
        "copy-Igy_y0Y",
        "(BBBZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;",
        "copy",
        "",
        "toString",
        "()Ljava/lang/String;",
        "",
        "hashCode",
        "()I",
        "",
        "other",
        "equals",
        "(Ljava/lang/Object;)Z",
        "B",
        "getMajorVersion-w2LRezQ",
        "getMinorVersion-w2LRezQ",
        "getPatchVersion-w2LRezQ",
        "Z",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getDefinition",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "Companion",
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


# static fields
.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;

.field private static final VEHICLE_DATA_MAJOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final VEHICLE_DATA_MINOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final VEHICLE_DATA_PATCH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final VEHICLE_EQUIPPED_ACCESSORY:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final VEHICLE_EQUIPPED_BEV_MEB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final VEHICLE_EQUIPPED_HAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final VEHICLE_EQUIPPED_LWB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final VEHICLE_EQUIPPED_SUNROOF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final isElectricalVehicle:Z

.field private final isHALEquipped:Z

.field private final isLWBEquipped:Z

.field private final isSunroofEquipped:Z

.field private final majorVersion:B

.field private final minorVersion:B

.field private final patchVersion:B


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;

    .line 8
    .line 9
    const/16 v0, 0x10

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->messageID:B

    .line 12
    .line 13
    const-wide v1, 0x5645480101000000L    # 3.904684204340278E107

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->address:J

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    sput-byte v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->priority:B

    .line 22
    .line 23
    const/16 v1, 0x8d

    .line 24
    .line 25
    sput v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->byteLength:I

    .line 26
    .line 27
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    const/16 v3, 0x8

    .line 31
    .line 32
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 33
    .line 34
    .line 35
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_DATA_MAJOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 36
    .line 37
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 38
    .line 39
    invoke-direct {v1, v3, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 40
    .line 41
    .line 42
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_DATA_MINOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 43
    .line 44
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    invoke-direct {v1, v0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 47
    .line 48
    .line 49
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_DATA_PATCH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 50
    .line 51
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 52
    .line 53
    const/16 v2, 0x18

    .line 54
    .line 55
    invoke-direct {v1, v2, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 56
    .line 57
    .line 58
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_ACCESSORY:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 59
    .line 60
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 61
    .line 62
    const/16 v1, 0x20

    .line 63
    .line 64
    const/4 v2, 0x1

    .line 65
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 66
    .line 67
    .line 68
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_SUNROOF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 69
    .line 70
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 71
    .line 72
    const/16 v1, 0x22

    .line 73
    .line 74
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 75
    .line 76
    .line 77
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_HAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 78
    .line 79
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 80
    .line 81
    const/16 v1, 0x23

    .line 82
    .line 83
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 84
    .line 85
    .line 86
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_LWB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 87
    .line 88
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 89
    .line 90
    const/16 v1, 0x24

    .line 91
    .line 92
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 93
    .line 94
    .line 95
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_BEV_MEB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 96
    .line 97
    return-void
.end method

.method private constructor <init>(BBBZZZZ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-byte p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->majorVersion:B

    .line 4
    iput-byte p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->minorVersion:B

    .line 5
    iput-byte p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->patchVersion:B

    .line 6
    iput-boolean p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isSunroofEquipped:Z

    .line 7
    iput-boolean p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle:Z

    .line 8
    iput-boolean p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isHALEquipped:Z

    .line 9
    iput-boolean p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isLWBEquipped:Z

    .line 10
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public constructor <init>(BBBZZZZILkotlin/jvm/internal/g;)V
    .locals 8

    and-int/lit8 v0, p8, 0x1

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    int-to-byte v0, v1

    goto :goto_0

    :cond_0
    move v0, p1

    :goto_0
    and-int/lit8 v2, p8, 0x2

    if-eqz v2, :cond_1

    int-to-byte v2, v1

    goto :goto_1

    :cond_1
    move v2, p2

    :goto_1
    and-int/lit8 v3, p8, 0x4

    if-eqz v3, :cond_2

    int-to-byte v3, v1

    goto :goto_2

    :cond_2
    move v3, p3

    :goto_2
    and-int/lit8 v4, p8, 0x8

    if-eqz v4, :cond_3

    move v4, v1

    goto :goto_3

    :cond_3
    move v4, p4

    :goto_3
    and-int/lit8 v5, p8, 0x10

    if-eqz v5, :cond_4

    move v5, v1

    goto :goto_4

    :cond_4
    move v5, p5

    :goto_4
    and-int/lit8 v6, p8, 0x20

    if-eqz v6, :cond_5

    move v6, v1

    goto :goto_5

    :cond_5
    move v6, p6

    :goto_5
    and-int/lit8 v7, p8, 0x40

    if-eqz v7, :cond_6

    goto :goto_6

    :cond_6
    move v1, p7

    :goto_6
    const/4 v7, 0x0

    move-object p1, p0

    move p2, v0

    move/from16 p8, v1

    move p3, v2

    move p4, v3

    move p5, v4

    move p6, v5

    move p7, v6

    move-object/from16 p9, v7

    .line 11
    invoke-direct/range {p1 .. p9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;-><init>(BBBZZZZLkotlin/jvm/internal/g;)V

    return-void
.end method

.method public synthetic constructor <init>(BBBZZZZLkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;-><init>(BBBZZZZ)V

    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getVEHICLE_DATA_MAJOR$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_DATA_MAJOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getVEHICLE_DATA_MINOR$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_DATA_MINOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getVEHICLE_DATA_PATCH$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_DATA_PATCH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getVEHICLE_EQUIPPED_BEV_MEB$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_BEV_MEB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getVEHICLE_EQUIPPED_HAL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_HAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getVEHICLE_EQUIPPED_LWB$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_LWB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getVEHICLE_EQUIPPED_SUNROOF$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_SUNROOF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy-Igy_y0Y$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;BBBZZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;
    .locals 0

    .line 1
    and-int/lit8 p9, p8, 0x1

    .line 2
    .line 3
    if-eqz p9, :cond_0

    .line 4
    .line 5
    iget-byte p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->majorVersion:B

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p9, p8, 0x2

    .line 8
    .line 9
    if-eqz p9, :cond_1

    .line 10
    .line 11
    iget-byte p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->minorVersion:B

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p9, p8, 0x4

    .line 14
    .line 15
    if-eqz p9, :cond_2

    .line 16
    .line 17
    iget-byte p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->patchVersion:B

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p9, p8, 0x8

    .line 20
    .line 21
    if-eqz p9, :cond_3

    .line 22
    .line 23
    iget-boolean p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isSunroofEquipped:Z

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p9, p8, 0x10

    .line 26
    .line 27
    if-eqz p9, :cond_4

    .line 28
    .line 29
    iget-boolean p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle:Z

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p9, p8, 0x20

    .line 32
    .line 33
    if-eqz p9, :cond_5

    .line 34
    .line 35
    iget-boolean p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isHALEquipped:Z

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p8, p8, 0x40

    .line 38
    .line 39
    if-eqz p8, :cond_6

    .line 40
    .line 41
    iget-boolean p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isLWBEquipped:Z

    .line 42
    .line 43
    :cond_6
    move p8, p6

    .line 44
    move p9, p7

    .line 45
    move p6, p4

    .line 46
    move p7, p5

    .line 47
    move p4, p2

    .line 48
    move p5, p3

    .line 49
    move-object p2, p0

    .line 50
    move p3, p1

    .line 51
    invoke-virtual/range {p2 .. p9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->copy-Igy_y0Y(BBBZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method


# virtual methods
.method public final component1-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->majorVersion:B

    .line 2
    .line 3
    return p0
.end method

.method public final component2-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->minorVersion:B

    .line 2
    .line 3
    return p0
.end method

.method public final component3-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->patchVersion:B

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isSunroofEquipped:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component5()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component6()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isHALEquipped:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component7()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isLWBEquipped:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy-Igy_y0Y(BBBZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;
    .locals 9

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 2
    .line 3
    const/4 v8, 0x0

    .line 4
    move v1, p1

    .line 5
    move v2, p2

    .line 6
    move v3, p3

    .line 7
    move v4, p4

    .line 8
    move v5, p5

    .line 9
    move v6, p6

    .line 10
    move/from16 v7, p7

    .line 11
    .line 12
    invoke-direct/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;-><init>(BBBZZZZLkotlin/jvm/internal/g;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 12
    .line 13
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->majorVersion:B

    .line 14
    .line 15
    iget-byte v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->majorVersion:B

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->minorVersion:B

    .line 21
    .line 22
    iget-byte v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->minorVersion:B

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->patchVersion:B

    .line 28
    .line 29
    iget-byte v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->patchVersion:B

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isSunroofEquipped:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isSunroofEquipped:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle:Z

    .line 42
    .line 43
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle:Z

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isHALEquipped:Z

    .line 49
    .line 50
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isHALEquipped:Z

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isLWBEquipped:Z

    .line 56
    .line 57
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isLWBEquipped:Z

    .line 58
    .line 59
    if-eq p0, p1, :cond_8

    .line 60
    .line 61
    return v2

    .line 62
    :cond_8
    return v0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMajorVersion-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->majorVersion:B

    .line 2
    .line 3
    return p0
.end method

.method public final getMinorVersion-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->minorVersion:B

    .line 2
    .line 3
    return p0
.end method

.method public final getPatchVersion-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->patchVersion:B

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-byte v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->majorVersion:B

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Byte;->hashCode(B)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-byte v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->minorVersion:B

    .line 11
    .line 12
    invoke-static {v2}, Ljava/lang/Byte;->hashCode(B)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-byte v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->patchVersion:B

    .line 19
    .line 20
    invoke-static {v0}, Ljava/lang/Byte;->hashCode(B)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isSunroofEquipped:Z

    .line 27
    .line 28
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle:Z

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isHALEquipped:Z

    .line 39
    .line 40
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isLWBEquipped:Z

    .line 45
    .line 46
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    add-int/2addr p0, v0

    .line 51
    return p0
.end method

.method public final isElectricalVehicle()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isHALEquipped()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isHALEquipped:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isLWBEquipped()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isLWBEquipped:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isSunroofEquipped()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isSunroofEquipped:Z

    .line 2
    .line 3
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->majorVersion:B

    .line 6
    .line 7
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_DATA_MAJOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 8
    .line 9
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 10
    .line 11
    .line 12
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->minorVersion:B

    .line 13
    .line 14
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_DATA_MINOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 17
    .line 18
    .line 19
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->patchVersion:B

    .line 20
    .line 21
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_DATA_PATCH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 22
    .line 23
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 24
    .line 25
    .line 26
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isSunroofEquipped:Z

    .line 27
    .line 28
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_SUNROOF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 31
    .line 32
    .line 33
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle:Z

    .line 34
    .line 35
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_BEV_MEB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 36
    .line 37
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 38
    .line 39
    .line 40
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isHALEquipped:Z

    .line 41
    .line 42
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_HAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 45
    .line 46
    .line 47
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isLWBEquipped:Z

    .line 48
    .line 49
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->VEHICLE_EQUIPPED_LWB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 50
    .line 51
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 52
    .line 53
    .line 54
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 9

    .line 1
    iget-byte v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->majorVersion:B

    .line 2
    .line 3
    invoke-static {v0}, Llx0/s;->a(B)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->minorVersion:B

    .line 8
    .line 9
    invoke-static {v1}, Llx0/s;->a(B)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-byte v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->patchVersion:B

    .line 14
    .line 15
    invoke-static {v2}, Llx0/s;->a(B)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    iget-boolean v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isSunroofEquipped:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle:Z

    .line 22
    .line 23
    iget-boolean v5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isHALEquipped:Z

    .line 24
    .line 25
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isLWBEquipped:Z

    .line 26
    .line 27
    const-string v6, ", minorVersion="

    .line 28
    .line 29
    const-string v7, ", patchVersion="

    .line 30
    .line 31
    const-string v8, "C2PVehicleDataResponseMessageMEB(majorVersion="

    .line 32
    .line 33
    invoke-static {v8, v0, v6, v1, v7}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    const-string v1, ", isSunroofEquipped="

    .line 38
    .line 39
    const-string v6, ", isElectricalVehicle="

    .line 40
    .line 41
    invoke-static {v2, v1, v6, v0, v3}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 42
    .line 43
    .line 44
    const-string v1, ", isHALEquipped="

    .line 45
    .line 46
    const-string v2, ", isLWBEquipped="

    .line 47
    .line 48
    invoke-static {v0, v4, v1, v5, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 49
    .line 50
    .line 51
    const-string v1, ")"

    .line 52
    .line 53
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method
