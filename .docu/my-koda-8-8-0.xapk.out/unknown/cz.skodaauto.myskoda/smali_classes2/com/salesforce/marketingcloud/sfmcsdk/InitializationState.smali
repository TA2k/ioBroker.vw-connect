.class public final enum Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0002\u0008\u0006\u0008\u0080\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002j\u0002\u0008\u0003j\u0002\u0008\u0004j\u0002\u0008\u0005j\u0002\u0008\u0006\u00a8\u0006\u0007"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;",
        "",
        "(Ljava/lang/String;I)V",
        "NONE",
        "INITIALIZING",
        "READY",
        "ERROR",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

.field public static final enum ERROR:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

.field public static final enum INITIALIZING:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

.field public static final enum NONE:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

.field public static final enum READY:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;


# direct methods
.method private static final synthetic $values()[Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->NONE:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->INITIALIZING:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->READY:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 6
    .line 7
    sget-object v3, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->ERROR:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

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
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 2
    .line 3
    const-string v1, "NONE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->NONE:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 12
    .line 13
    const-string v1, "INITIALIZING"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->INITIALIZING:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 20
    .line 21
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 22
    .line 23
    const-string v1, "READY"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->READY:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 30
    .line 31
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 32
    .line 33
    const-string v1, "ERROR"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->ERROR:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 40
    .line 41
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->$values()[Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->$VALUES:[Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 46
    .line 47
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->$ENTRIES:Lsx0/a;

    .line 52
    .line 53
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
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
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->$VALUES:[Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 8
    .line 9
    return-object v0
.end method
