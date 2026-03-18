.class public final enum Ltechnology/cariad/cat/genx/protocol/Priority;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltechnology/cariad/cat/genx/protocol/Priority;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u0005\n\u0002\u0008\t\u0008\u0086\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0014\u0010\u0002\u001a\u00020\u0003X\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\tj\u0002\u0008\nj\u0002\u0008\u000b\u00a8\u0006\u000c"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/Priority;",
        "",
        "value",
        "",
        "<init>",
        "(Ljava/lang/String;IB)V",
        "getValue$genx_release",
        "()B",
        "LOW",
        "MIDDLE",
        "HIGH",
        "HIGHEST",
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

.field private static final synthetic $VALUES:[Ltechnology/cariad/cat/genx/protocol/Priority;

.field public static final enum HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

.field public static final enum HIGHEST:Ltechnology/cariad/cat/genx/protocol/Priority;

.field public static final enum LOW:Ltechnology/cariad/cat/genx/protocol/Priority;

.field public static final enum MIDDLE:Ltechnology/cariad/cat/genx/protocol/Priority;


# instance fields
.field private final value:B


# direct methods
.method private static final synthetic $values()[Ltechnology/cariad/cat/genx/protocol/Priority;
    .locals 4

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/protocol/Priority;->LOW:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/genx/protocol/Priority;->MIDDLE:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 6
    .line 7
    sget-object v3, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGHEST:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 2
    .line 3
    const-string v1, "LOW"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/protocol/Priority;-><init>(Ljava/lang/String;IB)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/Priority;->LOW:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 12
    .line 13
    const-string v1, "MIDDLE"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/protocol/Priority;-><init>(Ljava/lang/String;IB)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/Priority;->MIDDLE:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 20
    .line 21
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 22
    .line 23
    const-string v1, "HIGH"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/protocol/Priority;-><init>(Ljava/lang/String;IB)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 30
    .line 31
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 32
    .line 33
    const-string v1, "HIGHEST"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v2}, Ltechnology/cariad/cat/genx/protocol/Priority;-><init>(Ljava/lang/String;IB)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGHEST:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 40
    .line 41
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/Priority;->$values()[Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/Priority;->$VALUES:[Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 46
    .line 47
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/Priority;->$ENTRIES:Lsx0/a;

    .line 52
    .line 53
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
    iput-byte p3, p0, Ltechnology/cariad/cat/genx/protocol/Priority;->value:B

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
    sget-object v0, Ltechnology/cariad/cat/genx/protocol/Priority;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Ltechnology/cariad/cat/genx/protocol/Priority;
    .locals 1

    .line 1
    const-class v0, Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltechnology/cariad/cat/genx/protocol/Priority;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/protocol/Priority;->$VALUES:[Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getValue$genx_release()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/genx/protocol/Priority;->value:B

    .line 2
    .line 3
    return p0
.end method
