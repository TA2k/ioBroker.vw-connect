.class public final enum Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u0005\n\u0002\u0008\u0008\n\u0002\u0010\u0012\n\u0002\u0008\u0004\u0008\u0080\u0081\u0002\u0018\u0000 \u000f2\u0008\u0012\u0004\u0012\u00020\u00000\u0001:\u0001\u000fB\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007R\u0011\u0010\u000b\u001a\u00020\u000c\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000ej\u0002\u0008\u0008j\u0002\u0008\tj\u0002\u0008\n\u00a8\u0006\u0010"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;",
        "",
        "byte",
        "",
        "<init>",
        "(Ljava/lang/String;IB)V",
        "getByte",
        "()B",
        "SUCCEEDED",
        "FAILED",
        "CANCELED",
        "byteArray",
        "",
        "getByteArray",
        "()[B",
        "Companion",
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

.field private static final synthetic $VALUES:[Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

.field public static final enum CANCELED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

.field public static final Companion:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;

.field public static final EXPECTED_SIZE:I = 0x1

.field public static final enum FAILED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

.field public static final enum SUCCEEDED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;


# instance fields
.field private final byte:B

.field private final byteArray:[B


# direct methods
.method private static final synthetic $values()[Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->SUCCEEDED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->FAILED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->CANCELED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 2
    .line 3
    const-string v1, "SUCCEEDED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;-><init>(Ljava/lang/String;IB)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->SUCCEEDED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 12
    .line 13
    const-string v1, "FAILED"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;-><init>(Ljava/lang/String;IB)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->FAILED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 20
    .line 21
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 22
    .line 23
    const-string v1, "CANCELED"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;-><init>(Ljava/lang/String;IB)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->CANCELED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 30
    .line 31
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->$values()[Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->$VALUES:[Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 36
    .line 37
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->$ENTRIES:Lsx0/a;

    .line 42
    .line 43
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;

    .line 44
    .line 45
    const/4 v1, 0x0

    .line 46
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->Companion:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;

    .line 50
    .line 51
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;IB)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(B)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-byte p3, p0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->byte:B

    .line 5
    .line 6
    const/4 p1, 0x1

    .line 7
    new-array p1, p1, [B

    .line 8
    .line 9
    const/4 p2, 0x0

    .line 10
    aput-byte p3, p1, p2

    .line 11
    .line 12
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->byteArray:[B

    .line 13
    .line 14
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
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;
    .locals 1

    .line 1
    const-class v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->$VALUES:[Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getByte()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->byte:B

    .line 2
    .line 3
    return p0
.end method

.method public final getByteArray()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->byteArray:[B

    .line 2
    .line 3
    return-object p0
.end method
