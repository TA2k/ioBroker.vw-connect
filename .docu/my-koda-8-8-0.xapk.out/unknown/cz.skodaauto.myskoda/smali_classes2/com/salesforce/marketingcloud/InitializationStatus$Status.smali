.class public final enum Lcom/salesforce/marketingcloud/InitializationStatus$Status;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/InitializationStatus;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "Status"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/InitializationStatus$Status;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcom/salesforce/marketingcloud/InitializationStatus$Status;

.field public static final enum COMPLETED_WITH_DEGRADED_FUNCTIONALITY:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

.field public static final enum FAILED:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

.field public static final enum SUCCESS:Lcom/salesforce/marketingcloud/InitializationStatus$Status;


# direct methods
.method private static final synthetic $values()[Lcom/salesforce/marketingcloud/InitializationStatus$Status;
    .locals 3

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->SUCCESS:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->COMPLETED_WITH_DEGRADED_FUNCTIONALITY:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->FAILED:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Lcom/salesforce/marketingcloud/InitializationStatus$Status;

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
    new-instance v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 2
    .line 3
    const-string v1, "SUCCESS"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/InitializationStatus$Status;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->SUCCESS:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 12
    .line 13
    const-string v1, "COMPLETED_WITH_DEGRADED_FUNCTIONALITY"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/InitializationStatus$Status;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->COMPLETED_WITH_DEGRADED_FUNCTIONALITY:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 20
    .line 21
    new-instance v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 22
    .line 23
    const-string v1, "FAILED"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/InitializationStatus$Status;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->FAILED:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 30
    .line 31
    invoke-static {}, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->$values()[Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->$VALUES:[Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 36
    .line 37
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->$ENTRIES:Lsx0/a;

    .line 42
    .line 43
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
    sget-object v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/InitializationStatus$Status;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/InitializationStatus$Status;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->$VALUES:[Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 8
    .line 9
    return-object v0
.end method
