.class public final enum Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lcom/squareup/moshi/JsonClass;
    generateAdapter = false
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff_garage/v2/ActivationStateDto$Companion;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u000b\u0008\u0087\u0081\u0002\u0018\u0000 \r2\u0008\u0012\u0004\u0012\u00020\u00000\u0001:\u0001\rB\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u0008\u0010\u000c\u001a\u00020\u0003H\u0016R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\tj\u0002\u0008\nj\u0002\u0008\u000b\u00a8\u0006\u000e"
    }
    d2 = {
        "Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;",
        "",
        "value",
        "",
        "<init>",
        "(Ljava/lang/String;ILjava/lang/String;)V",
        "getValue",
        "()Ljava/lang/String;",
        "DISABLED",
        "ENABLED",
        "IN_PROGRESS",
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

.field private static final synthetic $VALUES:[Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

.field public static final Companion:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto$Companion;

.field public static final enum DISABLED:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "DISABLED"
    .end annotation
.end field

.field public static final enum ENABLED:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "ENABLED"
    .end annotation
.end field

.field public static final enum IN_PROGRESS:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "IN_PROGRESS"
    .end annotation
.end field

.field public static final enum UNKNOWN:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "UNKNOWN"
    .end annotation
.end field


# instance fields
.field private final value:Ljava/lang/String;


# direct methods
.method private static final synthetic $values()[Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;
    .locals 4

    .line 1
    sget-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->DISABLED:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 2
    .line 3
    sget-object v1, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->ENABLED:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 4
    .line 5
    sget-object v2, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->IN_PROGRESS:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 6
    .line 7
    sget-object v3, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->UNKNOWN:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

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
    new-instance v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 2
    .line 3
    const-string v1, "DISABLED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->DISABLED:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 10
    .line 11
    new-instance v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 12
    .line 13
    const-string v1, "ENABLED"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->ENABLED:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 20
    .line 21
    new-instance v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 22
    .line 23
    const-string v1, "IN_PROGRESS"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->IN_PROGRESS:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 30
    .line 31
    new-instance v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 32
    .line 33
    const-string v1, "UNKNOWN"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->UNKNOWN:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 40
    .line 41
    invoke-static {}, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->$values()[Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->$VALUES:[Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 46
    .line 47
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->$ENTRIES:Lsx0/a;

    .line 52
    .line 53
    new-instance v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto$Companion;

    .line 54
    .line 55
    const/4 v1, 0x0

    .line 56
    invoke-direct {v0, v1}, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->Companion:Lcz/myskoda/api/bff_garage/v2/ActivationStateDto$Companion;

    .line 60
    .line 61
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
    iput-object p3, p0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->value:Ljava/lang/String;

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
    sget-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;
    .locals 1

    .line 1
    const-class v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->$VALUES:[Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getValue()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
