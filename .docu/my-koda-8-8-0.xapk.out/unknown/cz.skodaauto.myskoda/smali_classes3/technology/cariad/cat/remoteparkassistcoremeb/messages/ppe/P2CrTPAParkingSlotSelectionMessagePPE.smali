.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u0005\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 \u001b2\u00020\u0001:\u0001\u001bB\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u0008\u0010\u0010\u001a\u00020\u0011H\u0016J\t\u0010\u0012\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0013\u001a\u00020\u0005H\u00c6\u0003J\u001d\u0010\u0014\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0005H\u00c6\u0001J\u0013\u0010\u0015\u001a\u00020\u00052\u0008\u0010\u0016\u001a\u0004\u0018\u00010\u0017H\u00d6\u0003J\t\u0010\u0018\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\u0019\u001a\u00020\u001aH\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0008\u0010\tR\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0014\u0010\u000c\u001a\u00020\rX\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u001c"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;",
        "parkingSlotId",
        "",
        "selectParkingSlot",
        "",
        "<init>",
        "(IZ)V",
        "getParkingSlotId",
        "()I",
        "getSelectParkingSlot",
        "()Z",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getDefinition",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "toBytes",
        "",
        "component1",
        "component2",
        "copy",
        "equals",
        "other",
        "",
        "hashCode",
        "toString",
        "",
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
.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE$Companion;

.field private static final PARKING_SLOT_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SELECT_PARKING_SLOT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final parkingSlotId:I

.field private final selectParkingSlot:Z


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE$Companion;

    .line 8
    .line 9
    const/16 v0, 0x26

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->messageID:B

    .line 12
    .line 13
    const-wide v0, 0x5250410600000000L    # 3.233396316741368E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->address:J

    .line 19
    .line 20
    const/4 v0, 0x2

    .line 21
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->priority:B

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    sput v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->byteLength:I

    .line 25
    .line 26
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    const/4 v3, 0x4

    .line 30
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 31
    .line 32
    .line 33
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->PARKING_SLOT_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 34
    .line 35
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 36
    .line 37
    invoke-direct {v1, v3, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 38
    .line 39
    .line 40
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->SELECT_PARKING_SLOT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 41
    .line 42
    return-void
.end method

.method public constructor <init>(IZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->parkingSlotId:I

    .line 5
    .line 6
    iput-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->selectParkingSlot:Z

    .line 7
    .line 8
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE$Companion;

    .line 9
    .line 10
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 11
    .line 12
    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPARKING_SLOT_ID$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->PARKING_SLOT_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getSELECT_PARKING_SLOT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->SELECT_PARKING_SLOT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;IZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->parkingSlotId:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->selectParkingSlot:Z

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->copy(IZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->parkingSlotId:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->selectParkingSlot:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(IZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;
    .locals 0

    .line 1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;-><init>(IZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 12
    .line 13
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->parkingSlotId:I

    .line 14
    .line 15
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->parkingSlotId:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->selectParkingSlot:Z

    .line 21
    .line 22
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->selectParkingSlot:Z

    .line 23
    .line 24
    if-eq p0, p1, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    return v0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingSlotId()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->parkingSlotId:I

    .line 2
    .line 3
    return p0
.end method

.method public final getSelectParkingSlot()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->selectParkingSlot:Z

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->parkingSlotId:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->selectParkingSlot:Z

    .line 10
    .line 11
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->parkingSlotId:I

    .line 6
    .line 7
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->PARKING_SLOT_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 8
    .line 9
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 10
    .line 11
    .line 12
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->selectParkingSlot:Z

    .line 13
    .line 14
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->SELECT_PARKING_SLOT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 15
    .line 16
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 17
    .line 18
    .line 19
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->parkingSlotId:I

    .line 2
    .line 3
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->selectParkingSlot:Z

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "P2CrTPAParkingSlotSelectionMessagePPE(parkingSlotId="

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", selectParkingSlot="

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")"

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
