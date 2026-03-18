.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u000f\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u000b\n\u0002\u0010\u0000\n\u0002\u0008\u0004\u0008\u0086\u0008\u0018\u0000 12\u00020\u0001:\u00011BY\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0007\u0012\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\n\u001a\u00020\u000b\u0012\u0008\u0008\u0002\u0010\u000c\u001a\u00020\u0003\u0012\n\u0008\u0002\u0010\r\u001a\u0004\u0018\u00010\u000e\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u0008\u0010!\u001a\u00020\"H\u0016J\t\u0010#\u001a\u00020\u0003H\u00c6\u0003J\t\u0010$\u001a\u00020\u0003H\u00c6\u0003J\t\u0010%\u001a\u00020\u0003H\u00c6\u0003J\t\u0010&\u001a\u00020\u0007H\u00c6\u0003J\t\u0010\'\u001a\u00020\tH\u00c6\u0003J\t\u0010(\u001a\u00020\u000bH\u00c6\u0003J\t\u0010)\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010*\u001a\u0004\u0018\u00010\u000eH\u00c6\u0003J[\u0010+\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0002\u0010\n\u001a\u00020\u000b2\u0008\u0008\u0002\u0010\u000c\u001a\u00020\u00032\n\u0008\u0002\u0010\r\u001a\u0004\u0018\u00010\u000eH\u00c6\u0001J\u0013\u0010,\u001a\u00020\u000b2\u0008\u0010-\u001a\u0004\u0018\u00010.H\u00d6\u0003J\t\u0010/\u001a\u00020\u0003H\u00d6\u0001J\t\u00100\u001a\u00020\u000eH\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u0012R\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u0012R\u0011\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0012R\u0011\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0015\u0010\u0016R\u0011\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0017\u0010\u0018R\u0011\u0010\n\u001a\u00020\u000b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u0019R\u0011\u0010\u000c\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001a\u0010\u0012R\u0013\u0010\r\u001a\u0004\u0018\u00010\u000e\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001b\u0010\u001cR\u0014\u0010\u001d\u001a\u00020\u001eX\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001f\u0010 \u00a8\u00062"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "numberOfAvailableParkingSlots",
        "",
        "parkingSlotId",
        "parkingSlotIconId",
        "availableScenario",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;",
        "tpaStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;",
        "isCurrentSelectedParkingSlot",
        "",
        "nameLength",
        "name",
        "",
        "<init>",
        "(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;)V",
        "getNumberOfAvailableParkingSlots",
        "()I",
        "getParkingSlotId",
        "getParkingSlotIconId",
        "getAvailableScenario",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;",
        "getTpaStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;",
        "()Z",
        "getNameLength",
        "getName",
        "()Ljava/lang/String;",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getDefinition",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "toBytes",
        "",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "component7",
        "component8",
        "copy",
        "equals",
        "other",
        "",
        "hashCode",
        "toString",
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
.field private static final AVAILABLE_SCENARIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;

.field private static final IS_CURRENT_SELECTED_PARKING_SLOT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field public static final MINIMAL_BYTE_LENGTH:I = 0x4

.field private static final NAME_LENGTH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final NUMBER_OF_AVAILABLE_PARKING_SLOTS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SLOT_ICON_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SLOT_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final TPA_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final isCurrentSelectedParkingSlot:Z

.field private final name:Ljava/lang/String;

.field private final nameLength:I

.field private final numberOfAvailableParkingSlots:I

.field private final parkingSlotIconId:I

.field private final parkingSlotId:I

.field private final tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;

    .line 8
    .line 9
    const/16 v0, 0x26

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->messageID:B

    .line 12
    .line 13
    const-wide v0, 0x5250400601000000L    # 3.232619261041588E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->address:J

    .line 19
    .line 20
    const/4 v0, 0x2

    .line 21
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->priority:B

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    sput-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->requiresQueuing:Z

    .line 25
    .line 26
    const/16 v1, 0x7c

    .line 27
    .line 28
    sput v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->byteLength:I

    .line 29
    .line 30
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    const/4 v3, 0x4

    .line 34
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 35
    .line 36
    .line 37
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->NUMBER_OF_AVAILABLE_PARKING_SLOTS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 38
    .line 39
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 40
    .line 41
    invoke-direct {v1, v3, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 42
    .line 43
    .line 44
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->PARKING_SLOT_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 47
    .line 48
    const/16 v2, 0x8

    .line 49
    .line 50
    invoke-direct {v1, v2, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 51
    .line 52
    .line 53
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->PARKING_SLOT_ICON_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 54
    .line 55
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 56
    .line 57
    const/16 v4, 0x10

    .line 58
    .line 59
    invoke-direct {v1, v4, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 60
    .line 61
    .line 62
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->AVAILABLE_SCENARIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 63
    .line 64
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 65
    .line 66
    const/16 v3, 0x14

    .line 67
    .line 68
    const/4 v4, 0x3

    .line 69
    invoke-direct {v1, v3, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 70
    .line 71
    .line 72
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->TPA_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 73
    .line 74
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 75
    .line 76
    const/16 v3, 0x17

    .line 77
    .line 78
    invoke-direct {v1, v3, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 79
    .line 80
    .line 81
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->IS_CURRENT_SELECTED_PARKING_SLOT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 82
    .line 83
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 84
    .line 85
    const/16 v1, 0x18

    .line 86
    .line 87
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 88
    .line 89
    .line 90
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->NAME_LENGTH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 91
    .line 92
    return-void
.end method

.method public constructor <init>()V
    .locals 11

    .line 1
    const/16 v9, 0xff

    const/4 v10, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;-><init>(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;)V
    .locals 1

    const-string v0, "availableScenario"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "tpaStatus"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->numberOfAvailableParkingSlots:I

    .line 4
    iput p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotId:I

    .line 5
    iput p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotIconId:I

    .line 6
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 7
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 8
    iput-boolean p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->isCurrentSelectedParkingSlot:Z

    .line 9
    iput p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 10
    iput-object p8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->name:Ljava/lang/String;

    .line 11
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p10, p9, 0x1

    const/4 v0, 0x0

    if-eqz p10, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p10, p9, 0x2

    if-eqz p10, :cond_1

    move p2, v0

    :cond_1
    and-int/lit8 p10, p9, 0x4

    if-eqz p10, :cond_2

    move p3, v0

    :cond_2
    and-int/lit8 p10, p9, 0x8

    if-eqz p10, :cond_3

    .line 12
    sget-object p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;->NO_SCENARIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    :cond_3
    and-int/lit8 p10, p9, 0x10

    if-eqz p10, :cond_4

    .line 13
    sget-object p5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;->NOT_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    :cond_4
    and-int/lit8 p10, p9, 0x20

    if-eqz p10, :cond_5

    move p6, v0

    :cond_5
    and-int/lit8 p10, p9, 0x40

    if-eqz p10, :cond_6

    move p7, v0

    :cond_6
    and-int/lit16 p9, p9, 0x80

    if-eqz p9, :cond_7

    .line 14
    const-string p8, ""

    .line 15
    :cond_7
    invoke-direct/range {p0 .. p8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;-><init>(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;)V

    return-void
.end method

.method public static final synthetic access$getAVAILABLE_SCENARIO$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->AVAILABLE_SCENARIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getIS_CURRENT_SELECTED_PARKING_SLOT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->IS_CURRENT_SELECTED_PARKING_SLOT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getNAME_LENGTH$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->NAME_LENGTH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getNUMBER_OF_AVAILABLE_PARKING_SLOTS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->NUMBER_OF_AVAILABLE_PARKING_SLOTS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SLOT_ICON_ID$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->PARKING_SLOT_ICON_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SLOT_ID$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->PARKING_SLOT_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getTPA_STATUS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->TPA_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;
    .locals 0

    .line 1
    and-int/lit8 p10, p9, 0x1

    .line 2
    .line 3
    if-eqz p10, :cond_0

    .line 4
    .line 5
    iget p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->numberOfAvailableParkingSlots:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p10, p9, 0x2

    .line 8
    .line 9
    if-eqz p10, :cond_1

    .line 10
    .line 11
    iget p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotId:I

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p10, p9, 0x4

    .line 14
    .line 15
    if-eqz p10, :cond_2

    .line 16
    .line 17
    iget p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotIconId:I

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p10, p9, 0x8

    .line 20
    .line 21
    if-eqz p10, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p10, p9, 0x10

    .line 26
    .line 27
    if-eqz p10, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p10, p9, 0x20

    .line 32
    .line 33
    if-eqz p10, :cond_5

    .line 34
    .line 35
    iget-boolean p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->isCurrentSelectedParkingSlot:Z

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p10, p9, 0x40

    .line 38
    .line 39
    if-eqz p10, :cond_6

    .line 40
    .line 41
    iget p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 42
    .line 43
    :cond_6
    and-int/lit16 p9, p9, 0x80

    .line 44
    .line 45
    if-eqz p9, :cond_7

    .line 46
    .line 47
    iget-object p8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->name:Ljava/lang/String;

    .line 48
    .line 49
    :cond_7
    move p9, p7

    .line 50
    move-object p10, p8

    .line 51
    move-object p7, p5

    .line 52
    move p8, p6

    .line 53
    move p5, p3

    .line 54
    move-object p6, p4

    .line 55
    move p3, p1

    .line 56
    move p4, p2

    .line 57
    move-object p2, p0

    .line 58
    invoke-virtual/range {p2 .. p10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->copy(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->numberOfAvailableParkingSlots:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotId:I

    .line 2
    .line 3
    return p0
.end method

.method public final component3()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotIconId:I

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->isCurrentSelectedParkingSlot:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component7()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 2
    .line 3
    return p0
.end method

.method public final component8()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;
    .locals 9

    .line 1
    const-string p0, "availableScenario"

    .line 2
    .line 3
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "tpaStatus"

    .line 7
    .line 8
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 12
    .line 13
    move v1, p1

    .line 14
    move v2, p2

    .line 15
    move v3, p3

    .line 16
    move-object v4, p4

    .line 17
    move-object v5, p5

    .line 18
    move v6, p6

    .line 19
    move/from16 v7, p7

    .line 20
    .line 21
    move-object/from16 v8, p8

    .line 22
    .line 23
    invoke-direct/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;-><init>(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;)V

    .line 24
    .line 25
    .line 26
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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 12
    .line 13
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->numberOfAvailableParkingSlots:I

    .line 14
    .line 15
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->numberOfAvailableParkingSlots:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotId:I

    .line 21
    .line 22
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotId:I

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotIconId:I

    .line 28
    .line 29
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotIconId:I

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 35
    .line 36
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 42
    .line 43
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->isCurrentSelectedParkingSlot:Z

    .line 49
    .line 50
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->isCurrentSelectedParkingSlot:Z

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 56
    .line 57
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 58
    .line 59
    if-eq v1, v3, :cond_8

    .line 60
    .line 61
    return v2

    .line 62
    :cond_8
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->name:Ljava/lang/String;

    .line 63
    .line 64
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->name:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    if-nez p0, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    return v0
.end method

.method public final getAvailableScenario()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getNameLength()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 2
    .line 3
    return p0
.end method

.method public final getNumberOfAvailableParkingSlots()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->numberOfAvailableParkingSlots:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingSlotIconId()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotIconId:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingSlotId()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotId:I

    .line 2
    .line 3
    return p0
.end method

.method public final getTpaStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->numberOfAvailableParkingSlots:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

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
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotId:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotIconId:I

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    add-int/2addr v2, v0

    .line 29
    mul-int/2addr v2, v1

    .line 30
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    add-int/2addr v0, v2

    .line 37
    mul-int/2addr v0, v1

    .line 38
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->isCurrentSelectedParkingSlot:Z

    .line 39
    .line 40
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 45
    .line 46
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->name:Ljava/lang/String;

    .line 51
    .line 52
    if-nez p0, :cond_0

    .line 53
    .line 54
    const/4 p0, 0x0

    .line 55
    goto :goto_0

    .line 56
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    :goto_0
    add-int/2addr v0, p0

    .line 61
    return v0
.end method

.method public final isCurrentSelectedParkingSlot()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->isCurrentSelectedParkingSlot:Z

    .line 2
    .line 3
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x4

    .line 4
    .line 5
    new-array v0, v0, [B

    .line 6
    .line 7
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->numberOfAvailableParkingSlots:I

    .line 8
    .line 9
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->NUMBER_OF_AVAILABLE_PARKING_SLOTS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 10
    .line 11
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 12
    .line 13
    .line 14
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotId:I

    .line 15
    .line 16
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->PARKING_SLOT_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 19
    .line 20
    .line 21
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotIconId:I

    .line 22
    .line 23
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->PARKING_SLOT_ICON_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 24
    .line 25
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->AVAILABLE_SCENARIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->TPA_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 46
    .line 47
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 48
    .line 49
    .line 50
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->isCurrentSelectedParkingSlot:Z

    .line 51
    .line 52
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->IS_CURRENT_SELECTED_PARKING_SLOT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 55
    .line 56
    .line 57
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 58
    .line 59
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->NAME_LENGTH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 60
    .line 61
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 62
    .line 63
    .line 64
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->name:Ljava/lang/String;

    .line 65
    .line 66
    if-eqz v1, :cond_0

    .line 67
    .line 68
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;

    .line 69
    .line 70
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 71
    .line 72
    invoke-static {v2, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;->access$getNameBitPacket(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;I)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-static {v0, v1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BLjava/lang/String;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 77
    .line 78
    .line 79
    :cond_0
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 10

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->numberOfAvailableParkingSlots:I

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotId:I

    .line 4
    .line 5
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->parkingSlotIconId:I

    .line 6
    .line 7
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->availableScenario:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;

    .line 8
    .line 9
    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->tpaStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;

    .line 10
    .line 11
    iget-boolean v5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->isCurrentSelectedParkingSlot:Z

    .line 12
    .line 13
    iget v6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->nameLength:I

    .line 14
    .line 15
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->name:Ljava/lang/String;

    .line 16
    .line 17
    const-string v7, ", parkingSlotId="

    .line 18
    .line 19
    const-string v8, ", parkingSlotIconId="

    .line 20
    .line 21
    const-string v9, "C2PrTPAParkingSpaceInfoPPE(numberOfAvailableParkingSlots="

    .line 22
    .line 23
    invoke-static {v0, v1, v9, v7, v8}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", availableScenario="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string v1, ", tpaStatus="

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ", isCurrentSelectedParkingSlot="

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", nameLength="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, ", name="

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string p0, ")"

    .line 71
    .line 72
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0
.end method
