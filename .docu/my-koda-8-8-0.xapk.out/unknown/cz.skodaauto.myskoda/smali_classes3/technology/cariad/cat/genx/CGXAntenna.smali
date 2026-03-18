.class public final enum Ltechnology/cariad/cat/genx/CGXAntenna;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltechnology/cariad/cat/genx/CGXAntenna;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0007\u0008\u0080\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\t\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/CGXAntenna;",
        "",
        "rawValue",
        "",
        "<init>",
        "(Ljava/lang/String;II)V",
        "getRawValue",
        "()I",
        "CGXAntennaInner",
        "CGXAntennaOuter",
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

.field private static final synthetic $VALUES:[Ltechnology/cariad/cat/genx/CGXAntenna;

.field public static final enum CGXAntennaInner:Ltechnology/cariad/cat/genx/CGXAntenna;

.field public static final enum CGXAntennaOuter:Ltechnology/cariad/cat/genx/CGXAntenna;


# instance fields
.field private final rawValue:I


# direct methods
.method private static final synthetic $values()[Ltechnology/cariad/cat/genx/CGXAntenna;
    .locals 2

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/CGXAntenna;->CGXAntennaInner:Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/genx/CGXAntenna;->CGXAntennaOuter:Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 2
    .line 3
    const-string v1, "CGXAntennaInner"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/CGXAntenna;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ltechnology/cariad/cat/genx/CGXAntenna;->CGXAntennaInner:Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 12
    .line 13
    const-string v1, "CGXAntennaOuter"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/CGXAntenna;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Ltechnology/cariad/cat/genx/CGXAntenna;->CGXAntennaOuter:Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 20
    .line 21
    invoke-static {}, Ltechnology/cariad/cat/genx/CGXAntenna;->$values()[Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Ltechnology/cariad/cat/genx/CGXAntenna;->$VALUES:[Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Ltechnology/cariad/cat/genx/CGXAntenna;->$ENTRIES:Lsx0/a;

    .line 32
    .line 33
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
    iput p3, p0, Ltechnology/cariad/cat/genx/CGXAntenna;->rawValue:I

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
    sget-object v0, Ltechnology/cariad/cat/genx/CGXAntenna;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Ltechnology/cariad/cat/genx/CGXAntenna;
    .locals 1

    .line 1
    const-class v0, Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltechnology/cariad/cat/genx/CGXAntenna;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/CGXAntenna;->$VALUES:[Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getRawValue()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/CGXAntenna;->rawValue:I

    .line 2
    .line 3
    return p0
.end method
