.class public final enum Lcom/salesforce/marketingcloud/k$e;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/k;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "e"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/k$e;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum b:Lcom/salesforce/marketingcloud/k$e;

.field public static final enum c:Lcom/salesforce/marketingcloud/k$e;

.field public static final enum d:Lcom/salesforce/marketingcloud/k$e;

.field public static final enum e:Lcom/salesforce/marketingcloud/k$e;

.field public static final enum f:Lcom/salesforce/marketingcloud/k$e;

.field private static final synthetic g:[Lcom/salesforce/marketingcloud/k$e;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/k$e;

    .line 2
    .line 3
    const-string v1, "blocked"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/k$e;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/k$e;->b:Lcom/salesforce/marketingcloud/k$e;

    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/k$e;

    .line 12
    .line 13
    const-string v1, "inAppMessages"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/k$e;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/k$e;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 20
    .line 21
    new-instance v0, Lcom/salesforce/marketingcloud/k$e;

    .line 22
    .line 23
    const-string v1, "triggers"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/k$e;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/salesforce/marketingcloud/k$e;->d:Lcom/salesforce/marketingcloud/k$e;

    .line 30
    .line 31
    new-instance v0, Lcom/salesforce/marketingcloud/k$e;

    .line 32
    .line 33
    const-string v1, "pushFeaturesInUse"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/k$e;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/salesforce/marketingcloud/k$e;->e:Lcom/salesforce/marketingcloud/k$e;

    .line 40
    .line 41
    new-instance v0, Lcom/salesforce/marketingcloud/k$e;

    .line 42
    .line 43
    const-string v1, "appConfig"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/k$e;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcom/salesforce/marketingcloud/k$e;->f:Lcom/salesforce/marketingcloud/k$e;

    .line 50
    .line 51
    invoke-static {}, Lcom/salesforce/marketingcloud/k$e;->a()[Lcom/salesforce/marketingcloud/k$e;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lcom/salesforce/marketingcloud/k$e;->g:[Lcom/salesforce/marketingcloud/k$e;

    .line 56
    .line 57
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

.method private static synthetic a()[Lcom/salesforce/marketingcloud/k$e;
    .locals 5

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->b:Lcom/salesforce/marketingcloud/k$e;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/k$e;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/k$e;->d:Lcom/salesforce/marketingcloud/k$e;

    .line 6
    .line 7
    sget-object v3, Lcom/salesforce/marketingcloud/k$e;->e:Lcom/salesforce/marketingcloud/k$e;

    .line 8
    .line 9
    sget-object v4, Lcom/salesforce/marketingcloud/k$e;->f:Lcom/salesforce/marketingcloud/k$e;

    .line 10
    .line 11
    filled-new-array {v0, v1, v2, v3, v4}, [Lcom/salesforce/marketingcloud/k$e;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/k$e;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/k$e;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/k$e;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/k$e;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->g:[Lcom/salesforce/marketingcloud/k$e;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/salesforce/marketingcloud/k$e;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/k$e;

    .line 8
    .line 9
    return-object v0
.end method
