.class public final enum Lcz/myskoda/api/bff/v1/VehicleTypeDto;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lcom/squareup/moshi/JsonClass;
    generateAdapter = false
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff/v1/VehicleTypeDto$Companion;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcz/myskoda/api/bff/v1/VehicleTypeDto;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u000c\u0008\u0087\u0081\u0002\u0018\u0000 \u000e2\u0008\u0012\u0004\u0012\u00020\u00000\u0001:\u0001\u000eB\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u0008\u0010\r\u001a\u00020\u0003H\u0016R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\tj\u0002\u0008\nj\u0002\u0008\u000bj\u0002\u0008\u000c\u00a8\u0006\u000f"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/VehicleTypeDto;",
        "",
        "value",
        "",
        "<init>",
        "(Ljava/lang/String;ILjava/lang/String;)V",
        "getValue",
        "()Ljava/lang/String;",
        "ELECTRIC",
        "HYBRID",
        "GAS",
        "FUEL",
        "UNKNOWN",
        "toString",
        "Companion",
        "bff-api_release"
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

.field private static final synthetic $VALUES:[Lcz/myskoda/api/bff/v1/VehicleTypeDto;

.field public static final Companion:Lcz/myskoda/api/bff/v1/VehicleTypeDto$Companion;

.field public static final enum ELECTRIC:Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "ELECTRIC"
    .end annotation
.end field

.field public static final enum FUEL:Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "FUEL"
    .end annotation
.end field

.field public static final enum GAS:Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "GAS"
    .end annotation
.end field

.field public static final enum HYBRID:Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "HYBRID"
    .end annotation
.end field

.field public static final enum UNKNOWN:Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "UNKNOWN"
    .end annotation
.end field


# instance fields
.field private final value:Ljava/lang/String;


# direct methods
.method private static final synthetic $values()[Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .locals 5

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->ELECTRIC:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 2
    .line 3
    sget-object v1, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->HYBRID:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 4
    .line 5
    sget-object v2, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->GAS:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 6
    .line 7
    sget-object v3, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->FUEL:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 8
    .line 9
    sget-object v4, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->UNKNOWN:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 10
    .line 11
    filled-new-array {v0, v1, v2, v3, v4}, [Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 2
    .line 3
    const-string v1, "ELECTRIC"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/VehicleTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->ELECTRIC:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 10
    .line 11
    new-instance v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 12
    .line 13
    const-string v1, "HYBRID"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/VehicleTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->HYBRID:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 20
    .line 21
    new-instance v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 22
    .line 23
    const-string v1, "GAS"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/VehicleTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->GAS:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 30
    .line 31
    new-instance v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 32
    .line 33
    const-string v1, "FUEL"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/VehicleTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->FUEL:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 40
    .line 41
    new-instance v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 42
    .line 43
    const-string v1, "UNKNOWN"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/VehicleTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->UNKNOWN:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 50
    .line 51
    invoke-static {}, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->$values()[Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->$VALUES:[Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 56
    .line 57
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    sput-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->$ENTRIES:Lsx0/a;

    .line 62
    .line 63
    new-instance v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto$Companion;

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-direct {v0, v1}, Lcz/myskoda/api/bff/v1/VehicleTypeDto$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 67
    .line 68
    .line 69
    sput-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->Companion:Lcz/myskoda/api/bff/v1/VehicleTypeDto$Companion;

    .line 70
    .line 71
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->value:Ljava/lang/String;

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
    sget-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .locals 1

    .line 1
    const-class v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->$VALUES:[Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getValue()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/VehicleTypeDto;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
