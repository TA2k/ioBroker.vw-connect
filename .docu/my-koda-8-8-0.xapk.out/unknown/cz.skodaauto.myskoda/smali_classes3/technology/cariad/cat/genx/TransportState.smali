.class public final enum Ltechnology/cariad/cat/genx/TransportState;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltechnology/cariad/cat/genx/TransportState;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u000b\u0008\u0086\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0014\u0010\u0002\u001a\u00020\u0003X\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\tj\u0002\u0008\nj\u0002\u0008\u000bj\u0002\u0008\u000cj\u0002\u0008\r\u00a8\u0006\u000e"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/TransportState;",
        "",
        "cgxValue",
        "",
        "<init>",
        "(Ljava/lang/String;II)V",
        "getCgxValue$genx_release",
        "()I",
        "DISCONNECTED",
        "AWAITING_PAIRING",
        "CONNECTING",
        "CONNECTED",
        "DISCONNECTING",
        "PERFORMING_KEY_EXCHANGE",
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


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Ltechnology/cariad/cat/genx/TransportState;

.field public static final enum AWAITING_PAIRING:Ltechnology/cariad/cat/genx/TransportState;

.field public static final enum CONNECTED:Ltechnology/cariad/cat/genx/TransportState;

.field public static final enum CONNECTING:Ltechnology/cariad/cat/genx/TransportState;

.field public static final enum DISCONNECTED:Ltechnology/cariad/cat/genx/TransportState;

.field public static final enum DISCONNECTING:Ltechnology/cariad/cat/genx/TransportState;

.field public static final enum PERFORMING_KEY_EXCHANGE:Ltechnology/cariad/cat/genx/TransportState;


# instance fields
.field private final cgxValue:I


# direct methods
.method private static final synthetic $values()[Ltechnology/cariad/cat/genx/TransportState;
    .locals 6

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/TransportState;->DISCONNECTED:Ltechnology/cariad/cat/genx/TransportState;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/genx/TransportState;->AWAITING_PAIRING:Ltechnology/cariad/cat/genx/TransportState;

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/genx/TransportState;->CONNECTING:Ltechnology/cariad/cat/genx/TransportState;

    .line 6
    .line 7
    sget-object v3, Ltechnology/cariad/cat/genx/TransportState;->CONNECTED:Ltechnology/cariad/cat/genx/TransportState;

    .line 8
    .line 9
    sget-object v4, Ltechnology/cariad/cat/genx/TransportState;->DISCONNECTING:Ltechnology/cariad/cat/genx/TransportState;

    .line 10
    .line 11
    sget-object v5, Ltechnology/cariad/cat/genx/TransportState;->PERFORMING_KEY_EXCHANGE:Ltechnology/cariad/cat/genx/TransportState;

    .line 12
    .line 13
    filled-new-array/range {v0 .. v5}, [Ltechnology/cariad/cat/genx/TransportState;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/TransportState;

    .line 2
    .line 3
    const-string v1, "DISCONNECTED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/TransportState;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ltechnology/cariad/cat/genx/TransportState;->DISCONNECTED:Ltechnology/cariad/cat/genx/TransportState;

    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/genx/TransportState;

    .line 12
    .line 13
    const-string v1, "AWAITING_PAIRING"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/TransportState;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Ltechnology/cariad/cat/genx/TransportState;->AWAITING_PAIRING:Ltechnology/cariad/cat/genx/TransportState;

    .line 20
    .line 21
    new-instance v0, Ltechnology/cariad/cat/genx/TransportState;

    .line 22
    .line 23
    const-string v1, "CONNECTING"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/TransportState;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Ltechnology/cariad/cat/genx/TransportState;->CONNECTING:Ltechnology/cariad/cat/genx/TransportState;

    .line 30
    .line 31
    new-instance v0, Ltechnology/cariad/cat/genx/TransportState;

    .line 32
    .line 33
    const-string v1, "CONNECTED"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/TransportState;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Ltechnology/cariad/cat/genx/TransportState;->CONNECTED:Ltechnology/cariad/cat/genx/TransportState;

    .line 40
    .line 41
    new-instance v0, Ltechnology/cariad/cat/genx/TransportState;

    .line 42
    .line 43
    const-string v1, "DISCONNECTING"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/TransportState;-><init>(Ljava/lang/String;II)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Ltechnology/cariad/cat/genx/TransportState;->DISCONNECTING:Ltechnology/cariad/cat/genx/TransportState;

    .line 50
    .line 51
    new-instance v0, Ltechnology/cariad/cat/genx/TransportState;

    .line 52
    .line 53
    const-string v1, "PERFORMING_KEY_EXCHANGE"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/TransportState;-><init>(Ljava/lang/String;II)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Ltechnology/cariad/cat/genx/TransportState;->PERFORMING_KEY_EXCHANGE:Ltechnology/cariad/cat/genx/TransportState;

    .line 60
    .line 61
    invoke-static {}, Ltechnology/cariad/cat/genx/TransportState;->$values()[Ltechnology/cariad/cat/genx/TransportState;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Ltechnology/cariad/cat/genx/TransportState;->$VALUES:[Ltechnology/cariad/cat/genx/TransportState;

    .line 66
    .line 67
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Ltechnology/cariad/cat/genx/TransportState;->$ENTRIES:Lsx0/a;

    .line 72
    .line 73
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Ltechnology/cariad/cat/genx/TransportState;->cgxValue:I

    .line 5
    .line 6
    return-void
.end method

.method public static getEntries()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/TransportState;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Ltechnology/cariad/cat/genx/TransportState;
    .locals 1

    .line 1
    const-class v0, Ltechnology/cariad/cat/genx/TransportState;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltechnology/cariad/cat/genx/TransportState;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltechnology/cariad/cat/genx/TransportState;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/TransportState;->$VALUES:[Ltechnology/cariad/cat/genx/TransportState;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltechnology/cariad/cat/genx/TransportState;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getCgxValue$genx_release()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/TransportState;->cgxValue:I

    .line 2
    .line 3
    return p0
.end method
