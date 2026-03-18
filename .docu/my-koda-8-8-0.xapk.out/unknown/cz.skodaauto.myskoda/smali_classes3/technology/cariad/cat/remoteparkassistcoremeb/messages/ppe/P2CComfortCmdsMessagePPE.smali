.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u0004\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 \u00162\u00020\u0001:\u0001\u0016B\u0011\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u0008\u0010\u000b\u001a\u00020\u000cH\u0016J\t\u0010\r\u001a\u00020\u0003H\u00c6\u0003J\u0013\u0010\u000e\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u000f\u001a\u00020\u00032\u0008\u0010\u0010\u001a\u0004\u0018\u00010\u0011H\u00d6\u0003J\t\u0010\u0012\u001a\u00020\u0013H\u00d6\u0001J\t\u0010\u0014\u001a\u00020\u0015H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0002\u0010\u0006R\u0014\u0010\u0007\u001a\u00020\u0008X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\n\u00a8\u0006\u0017"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;",
        "isComfortClosingRequested",
        "",
        "<init>",
        "(Z)V",
        "()Z",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getDefinition",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "toBytes",
        "",
        "component1",
        "copy",
        "equals",
        "other",
        "",
        "hashCode",
        "",
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
.field private static final COMFORT_CLOSING_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE$Companion;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final isComfortClosingRequested:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE$Companion;

    .line 8
    .line 9
    const/16 v0, 0x23

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->messageID:B

    .line 12
    .line 13
    const-wide v0, 0x5250410300000000L    # 3.233387210480936E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->address:J

    .line 19
    .line 20
    const/4 v0, 0x2

    .line 21
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->priority:B

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    sput v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->byteLength:I

    .line 25
    .line 26
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    invoke-direct {v1, v2, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->COMFORT_CLOSING_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 33
    .line 34
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    const/4 v0, 0x1

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {p0, v2, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;-><init>(ZILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Z)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested:Z

    .line 4
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(ZILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    const/4 p1, 0x0

    .line 5
    :cond_0
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;-><init>(Z)V

    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getCOMFORT_CLOSING_REQUEST$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->COMFORT_CLOSING_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested:Z

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->copy(Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final component1()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;
    .locals 0

    .line 1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;-><init>(Z)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 12
    .line 13
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested:Z

    .line 14
    .line 15
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested:Z

    .line 16
    .line 17
    if-eq p0, p1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    return v0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested:Z

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final isComfortClosingRequested()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested:Z

    .line 2
    .line 3
    return p0
.end method

.method public toBytes()[B
    .locals 2

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested:Z

    .line 6
    .line 7
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->COMFORT_CLOSING_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 8
    .line 9
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 10
    .line 11
    .line 12
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested:Z

    .line 2
    .line 3
    const-string v0, "P2CComfortCmdsMessagePPE(isComfortClosingRequested="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {v0, v1, p0}, Lvj/b;->j(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
