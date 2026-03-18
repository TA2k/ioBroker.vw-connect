.class public final enum Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "ScanMode"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\t\u0008\u0086\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\tj\u0002\u0008\nj\u0002\u0008\u000b\u00a8\u0006\u000c"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;",
        "",
        "value",
        "",
        "<init>",
        "(Ljava/lang/String;II)V",
        "getValue",
        "()I",
        "OPPORTUNISTIC",
        "LOW_POWER",
        "BALANCED",
        "LOW_LATENCY",
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

.field private static final synthetic $VALUES:[Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

.field public static final enum BALANCED:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

.field public static final enum LOW_LATENCY:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

.field public static final enum LOW_POWER:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

.field public static final enum OPPORTUNISTIC:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;


# instance fields
.field private final value:I


# direct methods
.method private static final synthetic $values()[Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;
    .locals 4

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->OPPORTUNISTIC:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->LOW_POWER:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->BALANCED:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 6
    .line 7
    sget-object v3, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->LOW_LATENCY:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    const-string v2, "OPPORTUNISTIC"

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v2, v3, v1}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;-><init>(Ljava/lang/String;II)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->OPPORTUNISTIC:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 11
    .line 12
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 13
    .line 14
    const-string v1, "LOW_POWER"

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    invoke-direct {v0, v1, v2, v3}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;-><init>(Ljava/lang/String;II)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->LOW_POWER:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 21
    .line 22
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 23
    .line 24
    const-string v1, "BALANCED"

    .line 25
    .line 26
    const/4 v3, 0x2

    .line 27
    invoke-direct {v0, v1, v3, v2}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;-><init>(Ljava/lang/String;II)V

    .line 28
    .line 29
    .line 30
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->BALANCED:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 31
    .line 32
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 33
    .line 34
    const-string v1, "LOW_LATENCY"

    .line 35
    .line 36
    const/4 v2, 0x3

    .line 37
    invoke-direct {v0, v1, v2, v3}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;-><init>(Ljava/lang/String;II)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->LOW_LATENCY:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 41
    .line 42
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->$values()[Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->$VALUES:[Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 47
    .line 48
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    sput-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->$ENTRIES:Lsx0/a;

    .line 53
    .line 54
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
    iput p3, p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->value:I

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
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;
    .locals 1

    .line 1
    const-class v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->$VALUES:[Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getValue()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->value:I

    .line 2
    .line 3
    return p0
.end method
