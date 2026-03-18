.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\t\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 +2\u00020\u0001:\u0001+BG\u0012\u000c\u0008\u0002\u0010\u0002\u001a\u00060\u0003j\u0002`\u0004\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0007\u0012\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\t\u001a\u00020\n\u0012\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u000c\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u0008\u0010\u001c\u001a\u00020\u001dH\u0016J\r\u0010\u001e\u001a\u00060\u0003j\u0002`\u0004H\u00c6\u0003J\t\u0010\u001f\u001a\u00020\u0003H\u00c6\u0003J\t\u0010 \u001a\u00020\u0007H\u00c6\u0003J\t\u0010!\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\"\u001a\u00020\nH\u00c6\u0003J\t\u0010#\u001a\u00020\u000cH\u00c6\u0003JI\u0010$\u001a\u00020\u00002\u000c\u0008\u0002\u0010\u0002\u001a\u00060\u0003j\u0002`\u00042\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u00032\u0008\u0008\u0002\u0010\t\u001a\u00020\n2\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u000cH\u00c6\u0001J\u0013\u0010%\u001a\u00020\u00072\u0008\u0010&\u001a\u0004\u0018\u00010\'H\u00d6\u0003J\t\u0010(\u001a\u00020\u0003H\u00d6\u0001J\t\u0010)\u001a\u00020*H\u00d6\u0001R\u0015\u0010\u0002\u001a\u00060\u0003j\u0002`\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u0010R\u0011\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u0010R\u0011\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0012R\u0011\u0010\u0008\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u0010R\u0011\u0010\t\u001a\u00020\n\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0015R\u0011\u0010\u000b\u001a\u00020\u000c\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0016\u0010\u0017R\u0014\u0010\u0018\u001a\u00020\u0019X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001a\u0010\u001b\u00a8\u0006,"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;",
        "aliveCounter",
        "",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/AliveCounterMLB;",
        "touchPositionX",
        "isEngineStartRequested",
        "",
        "touchPositionY",
        "userCommandStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;",
        "touchDiagnosisResponseStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;",
        "<init>",
        "(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;)V",
        "getAliveCounter",
        "()I",
        "getTouchPositionX",
        "()Z",
        "getTouchPositionY",
        "getUserCommandStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;",
        "getTouchDiagnosisResponseStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;",
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
.field private static final ALIVE_COUNTER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final APP_LOCK_STATE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;

.field private static final ENGINE_START_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final TOUCH_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final TOUCH_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final USER_COMMAND:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final USER_COMMAND_INVERTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final aliveCounter:I

.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final isEngineStartRequested:Z

.field private final touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

.field private final touchPositionX:I

.field private final touchPositionY:I

.field private final userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;

    .line 8
    .line 9
    const/16 v0, 0x21

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->messageID:B

    .line 12
    .line 13
    const-wide v0, 0x5250410100000000L    # 3.2333811396406476E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->address:J

    .line 19
    .line 20
    const/4 v0, 0x3

    .line 21
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->priority:B

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    sput-boolean v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->requiresQueuing:Z

    .line 25
    .line 26
    sput v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->byteLength:I

    .line 27
    .line 28
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    const/4 v4, 0x4

    .line 32
    invoke-direct {v2, v3, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 33
    .line 34
    .line 35
    sput-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->ALIVE_COUNTER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 36
    .line 37
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 38
    .line 39
    invoke-direct {v2, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 40
    .line 41
    .line 42
    sput-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->TOUCH_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 43
    .line 44
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    const/4 v2, 0x7

    .line 47
    invoke-direct {v0, v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 48
    .line 49
    .line 50
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->ENGINE_START_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 51
    .line 52
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 53
    .line 54
    const/16 v1, 0x8

    .line 55
    .line 56
    const/4 v2, 0x2

    .line 57
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 58
    .line 59
    .line 60
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->USER_COMMAND_INVERTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 61
    .line 62
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 63
    .line 64
    const/16 v1, 0xa

    .line 65
    .line 66
    const/4 v3, 0x5

    .line 67
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 68
    .line 69
    .line 70
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->TOUCH_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 71
    .line 72
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 73
    .line 74
    const/16 v1, 0xf

    .line 75
    .line 76
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 77
    .line 78
    .line 79
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->USER_COMMAND:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 80
    .line 81
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 82
    .line 83
    const/16 v1, 0x11

    .line 84
    .line 85
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 86
    .line 87
    .line 88
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->APP_LOCK_STATE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 89
    .line 90
    return-void
.end method

.method public constructor <init>()V
    .locals 9

    .line 1
    const/16 v7, 0x3f

    const/4 v8, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;-><init>(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;)V
    .locals 1

    const-string v0, "userCommandStatus"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "touchDiagnosisResponseStatus"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->aliveCounter:I

    .line 4
    iput p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionX:I

    .line 5
    iput-boolean p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested:Z

    .line 6
    iput p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionY:I

    .line 7
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 8
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 9
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p8, p7, 0x1

    const/4 v0, 0x0

    if-eqz p8, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p8, p7, 0x2

    if-eqz p8, :cond_1

    move p2, v0

    :cond_1
    and-int/lit8 p8, p7, 0x4

    if-eqz p8, :cond_2

    move p3, v0

    :cond_2
    and-int/lit8 p8, p7, 0x8

    if-eqz p8, :cond_3

    const/16 p4, 0x1f

    :cond_3
    and-int/lit8 p8, p7, 0x10

    if-eqz p8, :cond_4

    .line 10
    sget-object p5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    :cond_4
    and-int/lit8 p7, p7, 0x20

    if-eqz p7, :cond_5

    .line 11
    sget-object p6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 12
    :cond_5
    invoke-direct/range {p0 .. p6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;-><init>(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;)V

    return-void
.end method

.method public static final synthetic access$getALIVE_COUNTER$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->ALIVE_COUNTER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getAPP_LOCK_STATE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->APP_LOCK_STATE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getENGINE_START_REQUEST$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->ENGINE_START_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getTOUCH_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->TOUCH_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getTOUCH_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->TOUCH_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getUSER_COMMAND$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->USER_COMMAND:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getUSER_COMMAND_INVERTED$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->USER_COMMAND_INVERTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;
    .locals 0

    .line 1
    and-int/lit8 p8, p7, 0x1

    .line 2
    .line 3
    if-eqz p8, :cond_0

    .line 4
    .line 5
    iget p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->aliveCounter:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p8, p7, 0x2

    .line 8
    .line 9
    if-eqz p8, :cond_1

    .line 10
    .line 11
    iget p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionX:I

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p8, p7, 0x4

    .line 14
    .line 15
    if-eqz p8, :cond_2

    .line 16
    .line 17
    iget-boolean p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested:Z

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p8, p7, 0x8

    .line 20
    .line 21
    if-eqz p8, :cond_3

    .line 22
    .line 23
    iget p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionY:I

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p8, p7, 0x10

    .line 26
    .line 27
    if-eqz p8, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p7, p7, 0x20

    .line 32
    .line 33
    if-eqz p7, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 36
    .line 37
    :cond_5
    move-object p7, p5

    .line 38
    move-object p8, p6

    .line 39
    move p5, p3

    .line 40
    move p6, p4

    .line 41
    move p3, p1

    .line 42
    move p4, p2

    .line 43
    move-object p2, p0

    .line 44
    invoke-virtual/range {p2 .. p8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->copy(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->aliveCounter:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component4()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component5()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;
    .locals 7

    .line 1
    const-string p0, "userCommandStatus"

    .line 2
    .line 3
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "touchDiagnosisResponseStatus"

    .line 7
    .line 8
    invoke-static {p6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 12
    .line 13
    move v1, p1

    .line 14
    move v2, p2

    .line 15
    move v3, p3

    .line 16
    move v4, p4

    .line 17
    move-object v5, p5

    .line 18
    move-object v6, p6

    .line 19
    invoke-direct/range {v0 .. v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;-><init>(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;)V

    .line 20
    .line 21
    .line 22
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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 12
    .line 13
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->aliveCounter:I

    .line 14
    .line 15
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->aliveCounter:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionX:I

    .line 21
    .line 22
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionX:I

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionY:I

    .line 35
    .line 36
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionY:I

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 42
    .line 43
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 49
    .line 50
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 51
    .line 52
    if-eq p0, p1, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    return v0
.end method

.method public final getAliveCounter()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->aliveCounter:I

    .line 2
    .line 3
    return p0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTouchDiagnosisResponseStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTouchPositionX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getTouchPositionY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->aliveCounter:I

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
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionX:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionY:I

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    add-int/2addr p0, v2

    .line 43
    return p0
.end method

.method public final isEngineStartRequested()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested:Z

    .line 2
    .line 3
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->aliveCounter:I

    .line 6
    .line 7
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->ALIVE_COUNTER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 8
    .line 9
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 10
    .line 11
    .line 12
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionX:I

    .line 13
    .line 14
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->TOUCH_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 17
    .line 18
    .line 19
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested:Z

    .line 20
    .line 21
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->ENGINE_START_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 22
    .line 23
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 27
    .line 28
    invoke-static {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/SignalsMLBKt;->invert(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->USER_COMMAND_INVERTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 35
    .line 36
    .line 37
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionY:I

    .line 38
    .line 39
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->TOUCH_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 40
    .line 41
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 42
    .line 43
    .line 44
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 45
    .line 46
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->USER_COMMAND:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 51
    .line 52
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->APP_LOCK_STATE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 62
    .line 63
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 64
    .line 65
    .line 66
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 8

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->aliveCounter:I

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionX:I

    .line 4
    .line 5
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested:Z

    .line 6
    .line 7
    iget v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchPositionY:I

    .line 8
    .line 9
    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->userCommandStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->touchDiagnosisResponseStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 12
    .line 13
    const-string v5, ", touchPositionX="

    .line 14
    .line 15
    const-string v6, ", isEngineStartRequested="

    .line 16
    .line 17
    const-string v7, "P2CHighPrioMessageMLB(aliveCounter="

    .line 18
    .line 19
    invoke-static {v0, v1, v7, v5, v6}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string v1, ", touchPositionY="

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v1, ", userCommandStatus="

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, ", touchDiagnosisResponseStatus="

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p0, ")"

    .line 51
    .line 52
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0
.end method
