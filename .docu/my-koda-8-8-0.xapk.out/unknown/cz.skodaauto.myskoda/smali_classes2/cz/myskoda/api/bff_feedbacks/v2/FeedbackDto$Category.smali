.class public final enum Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lcom/squareup/moshi/JsonClass;
    generateAdapter = false
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "Category"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u000e\u0008\u0087\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\tj\u0002\u0008\nj\u0002\u0008\u000bj\u0002\u0008\u000cj\u0002\u0008\rj\u0002\u0008\u000ej\u0002\u0008\u000fj\u0002\u0008\u0010\u00a8\u0006\u0011"
    }
    d2 = {
        "Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;",
        "",
        "value",
        "",
        "<init>",
        "(Ljava/lang/String;ILjava/lang/String;)V",
        "getValue",
        "()Ljava/lang/String;",
        "MOBILE_APP",
        "INFOTAINMENT",
        "EXTERIOR",
        "INTERIOR",
        "DRIVING_AND_CHARGING",
        "ASSISTANCE_SYSTEMS",
        "ENGINE_AND_TRANSMISSION",
        "APP_LOGS",
        "OTHER",
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

.field private static final synthetic $VALUES:[Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

.field public static final enum APP_LOGS:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "APP_LOGS"
    .end annotation
.end field

.field public static final enum ASSISTANCE_SYSTEMS:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "ASSISTANCE_SYSTEMS"
    .end annotation
.end field

.field public static final enum DRIVING_AND_CHARGING:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "DRIVING_AND_CHARGING"
    .end annotation
.end field

.field public static final enum ENGINE_AND_TRANSMISSION:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "ENGINE_AND_TRANSMISSION"
    .end annotation
.end field

.field public static final enum EXTERIOR:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "EXTERIOR"
    .end annotation
.end field

.field public static final enum INFOTAINMENT:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "INFOTAINMENT"
    .end annotation
.end field

.field public static final enum INTERIOR:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "INTERIOR"
    .end annotation
.end field

.field public static final enum MOBILE_APP:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "MOBILE_APP"
    .end annotation
.end field

.field public static final enum OTHER:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "OTHER"
    .end annotation
.end field


# instance fields
.field private final value:Ljava/lang/String;


# direct methods
.method private static final synthetic $values()[Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .locals 9

    .line 1
    sget-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->MOBILE_APP:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 2
    .line 3
    sget-object v1, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->INFOTAINMENT:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 4
    .line 5
    sget-object v2, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->EXTERIOR:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 6
    .line 7
    sget-object v3, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->INTERIOR:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 8
    .line 9
    sget-object v4, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->DRIVING_AND_CHARGING:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 10
    .line 11
    sget-object v5, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->ASSISTANCE_SYSTEMS:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 12
    .line 13
    sget-object v6, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->ENGINE_AND_TRANSMISSION:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 14
    .line 15
    sget-object v7, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->APP_LOGS:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 16
    .line 17
    sget-object v8, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->OTHER:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 18
    .line 19
    filled-new-array/range {v0 .. v8}, [Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 2
    .line 3
    const-string v1, "MOBILE_APP"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->MOBILE_APP:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 10
    .line 11
    new-instance v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 12
    .line 13
    const-string v1, "INFOTAINMENT"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->INFOTAINMENT:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 20
    .line 21
    new-instance v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 22
    .line 23
    const-string v1, "EXTERIOR"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->EXTERIOR:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 30
    .line 31
    new-instance v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 32
    .line 33
    const-string v1, "INTERIOR"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->INTERIOR:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 40
    .line 41
    new-instance v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 42
    .line 43
    const-string v1, "DRIVING_AND_CHARGING"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->DRIVING_AND_CHARGING:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 50
    .line 51
    new-instance v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 52
    .line 53
    const-string v1, "ASSISTANCE_SYSTEMS"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->ASSISTANCE_SYSTEMS:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 60
    .line 61
    new-instance v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 62
    .line 63
    const-string v1, "ENGINE_AND_TRANSMISSION"

    .line 64
    .line 65
    const/4 v2, 0x6

    .line 66
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 67
    .line 68
    .line 69
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->ENGINE_AND_TRANSMISSION:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 70
    .line 71
    new-instance v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 72
    .line 73
    const-string v1, "APP_LOGS"

    .line 74
    .line 75
    const/4 v2, 0x7

    .line 76
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->APP_LOGS:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 80
    .line 81
    new-instance v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 82
    .line 83
    const-string v1, "OTHER"

    .line 84
    .line 85
    const/16 v2, 0x8

    .line 86
    .line 87
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->OTHER:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 91
    .line 92
    invoke-static {}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->$values()[Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->$VALUES:[Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 97
    .line 98
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    sput-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->$ENTRIES:Lsx0/a;

    .line 103
    .line 104
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
    iput-object p3, p0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->value:Ljava/lang/String;

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
    sget-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .locals 1

    .line 1
    const-class v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->$VALUES:[Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getValue()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
