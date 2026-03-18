.class public final enum Lcz/myskoda/api/bff/v1/ViewTypeDto;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lcom/squareup/moshi/JsonClass;
    generateAdapter = false
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff/v1/ViewTypeDto$Companion;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcz/myskoda/api/bff/v1/ViewTypeDto;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0013\u0008\u0087\u0081\u0002\u0018\u0000 \u00152\u0008\u0012\u0004\u0012\u00020\u00000\u0001:\u0001\u0015B\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u0008\u0010\u0014\u001a\u00020\u0003H\u0016R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\tj\u0002\u0008\nj\u0002\u0008\u000bj\u0002\u0008\u000cj\u0002\u0008\rj\u0002\u0008\u000ej\u0002\u0008\u000fj\u0002\u0008\u0010j\u0002\u0008\u0011j\u0002\u0008\u0012j\u0002\u0008\u0013\u00a8\u0006\u0016"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/ViewTypeDto;",
        "",
        "value",
        "",
        "<init>",
        "(Ljava/lang/String;ILjava/lang/String;)V",
        "getValue",
        "()Ljava/lang/String;",
        "HOME",
        "CHARGING_LIGHT",
        "CHARGING_DARK",
        "PLUGGED_IN_LIGHT",
        "PLUGGED_IN_DARK",
        "UNMODIFIED_EXTERIOR_FRONT",
        "UNMODIFIED_EXTERIOR_SIDE",
        "UNMODIFIED_EXTERIOR_REAR",
        "UNMODIFIED_INTERIOR_FRONT",
        "UNMODIFIED_INTERIOR_SIDE",
        "UNMODIFIED_INTERIOR_BOOT",
        "DOWNSCALED_EXTERIOR_FRONT",
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

.field private static final synthetic $VALUES:[Lcz/myskoda/api/bff/v1/ViewTypeDto;

.field public static final enum CHARGING_DARK:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "CHARGING_DARK"
    .end annotation
.end field

.field public static final enum CHARGING_LIGHT:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "CHARGING_LIGHT"
    .end annotation
.end field

.field public static final Companion:Lcz/myskoda/api/bff/v1/ViewTypeDto$Companion;

.field public static final enum DOWNSCALED_EXTERIOR_FRONT:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "DOWNSCALED_EXTERIOR_FRONT"
    .end annotation
.end field

.field public static final enum HOME:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "HOME"
    .end annotation
.end field

.field public static final enum PLUGGED_IN_DARK:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "PLUGGED_IN_DARK"
    .end annotation
.end field

.field public static final enum PLUGGED_IN_LIGHT:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "PLUGGED_IN_LIGHT"
    .end annotation
.end field

.field public static final enum UNMODIFIED_EXTERIOR_FRONT:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "UNMODIFIED_EXTERIOR_FRONT"
    .end annotation
.end field

.field public static final enum UNMODIFIED_EXTERIOR_REAR:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "UNMODIFIED_EXTERIOR_REAR"
    .end annotation
.end field

.field public static final enum UNMODIFIED_EXTERIOR_SIDE:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "UNMODIFIED_EXTERIOR_SIDE"
    .end annotation
.end field

.field public static final enum UNMODIFIED_INTERIOR_BOOT:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "UNMODIFIED_INTERIOR_BOOT"
    .end annotation
.end field

.field public static final enum UNMODIFIED_INTERIOR_FRONT:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "UNMODIFIED_INTERIOR_FRONT"
    .end annotation
.end field

.field public static final enum UNMODIFIED_INTERIOR_SIDE:Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "UNMODIFIED_INTERIOR_SIDE"
    .end annotation
.end field


# instance fields
.field private final value:Ljava/lang/String;


# direct methods
.method private static final synthetic $values()[Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .locals 12

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->HOME:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 2
    .line 3
    sget-object v1, Lcz/myskoda/api/bff/v1/ViewTypeDto;->CHARGING_LIGHT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 4
    .line 5
    sget-object v2, Lcz/myskoda/api/bff/v1/ViewTypeDto;->CHARGING_DARK:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 6
    .line 7
    sget-object v3, Lcz/myskoda/api/bff/v1/ViewTypeDto;->PLUGGED_IN_LIGHT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 8
    .line 9
    sget-object v4, Lcz/myskoda/api/bff/v1/ViewTypeDto;->PLUGGED_IN_DARK:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 10
    .line 11
    sget-object v5, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_EXTERIOR_FRONT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 12
    .line 13
    sget-object v6, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_EXTERIOR_SIDE:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 14
    .line 15
    sget-object v7, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_EXTERIOR_REAR:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 16
    .line 17
    sget-object v8, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_INTERIOR_FRONT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 18
    .line 19
    sget-object v9, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_INTERIOR_SIDE:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 20
    .line 21
    sget-object v10, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_INTERIOR_BOOT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 22
    .line 23
    sget-object v11, Lcz/myskoda/api/bff/v1/ViewTypeDto;->DOWNSCALED_EXTERIOR_FRONT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 24
    .line 25
    filled-new-array/range {v0 .. v11}, [Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 2
    .line 3
    const-string v1, "HOME"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->HOME:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 10
    .line 11
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 12
    .line 13
    const-string v1, "CHARGING_LIGHT"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->CHARGING_LIGHT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 20
    .line 21
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 22
    .line 23
    const-string v1, "CHARGING_DARK"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->CHARGING_DARK:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 30
    .line 31
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 32
    .line 33
    const-string v1, "PLUGGED_IN_LIGHT"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->PLUGGED_IN_LIGHT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 40
    .line 41
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 42
    .line 43
    const-string v1, "PLUGGED_IN_DARK"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->PLUGGED_IN_DARK:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 50
    .line 51
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 52
    .line 53
    const-string v1, "UNMODIFIED_EXTERIOR_FRONT"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_EXTERIOR_FRONT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 60
    .line 61
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 62
    .line 63
    const-string v1, "UNMODIFIED_EXTERIOR_SIDE"

    .line 64
    .line 65
    const/4 v2, 0x6

    .line 66
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 67
    .line 68
    .line 69
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_EXTERIOR_SIDE:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 70
    .line 71
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 72
    .line 73
    const-string v1, "UNMODIFIED_EXTERIOR_REAR"

    .line 74
    .line 75
    const/4 v2, 0x7

    .line 76
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_EXTERIOR_REAR:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 80
    .line 81
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 82
    .line 83
    const-string v1, "UNMODIFIED_INTERIOR_FRONT"

    .line 84
    .line 85
    const/16 v2, 0x8

    .line 86
    .line 87
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_INTERIOR_FRONT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 91
    .line 92
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 93
    .line 94
    const-string v1, "UNMODIFIED_INTERIOR_SIDE"

    .line 95
    .line 96
    const/16 v2, 0x9

    .line 97
    .line 98
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 99
    .line 100
    .line 101
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_INTERIOR_SIDE:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 102
    .line 103
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 104
    .line 105
    const-string v1, "UNMODIFIED_INTERIOR_BOOT"

    .line 106
    .line 107
    const/16 v2, 0xa

    .line 108
    .line 109
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 110
    .line 111
    .line 112
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->UNMODIFIED_INTERIOR_BOOT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 113
    .line 114
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 115
    .line 116
    const-string v1, "DOWNSCALED_EXTERIOR_FRONT"

    .line 117
    .line 118
    const/16 v2, 0xb

    .line 119
    .line 120
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 121
    .line 122
    .line 123
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->DOWNSCALED_EXTERIOR_FRONT:Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 124
    .line 125
    invoke-static {}, Lcz/myskoda/api/bff/v1/ViewTypeDto;->$values()[Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->$VALUES:[Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 130
    .line 131
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->$ENTRIES:Lsx0/a;

    .line 136
    .line 137
    new-instance v0, Lcz/myskoda/api/bff/v1/ViewTypeDto$Companion;

    .line 138
    .line 139
    const/4 v1, 0x0

    .line 140
    invoke-direct {v0, v1}, Lcz/myskoda/api/bff/v1/ViewTypeDto$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 141
    .line 142
    .line 143
    sput-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->Companion:Lcz/myskoda/api/bff/v1/ViewTypeDto$Companion;

    .line 144
    .line 145
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
    iput-object p3, p0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->value:Ljava/lang/String;

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
    sget-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .locals 1

    .line 1
    const-class v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcz/myskoda/api/bff/v1/ViewTypeDto;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->$VALUES:[Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcz/myskoda/api/bff/v1/ViewTypeDto;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getValue()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ViewTypeDto;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
