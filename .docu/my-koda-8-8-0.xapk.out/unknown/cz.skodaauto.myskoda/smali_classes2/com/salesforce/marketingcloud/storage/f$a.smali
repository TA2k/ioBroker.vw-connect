.class public final enum Lcom/salesforce/marketingcloud/storage/f$a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/storage/f;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "a"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/storage/f$a;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum b:Lcom/salesforce/marketingcloud/storage/f$a;

.field public static final enum c:Lcom/salesforce/marketingcloud/storage/f$a;

.field public static final enum d:Lcom/salesforce/marketingcloud/storage/f$a;

.field public static final enum e:Lcom/salesforce/marketingcloud/storage/f$a;

.field private static final synthetic f:[Lcom/salesforce/marketingcloud/storage/f$a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/storage/f$a;

    .line 2
    .line 3
    const-string v1, "UNREAD"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/f$a;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->b:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/storage/f$a;

    .line 12
    .line 13
    const-string v1, "READ"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/f$a;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->c:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 20
    .line 21
    new-instance v0, Lcom/salesforce/marketingcloud/storage/f$a;

    .line 22
    .line 23
    const-string v1, "DELETED"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/f$a;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->d:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 30
    .line 31
    new-instance v0, Lcom/salesforce/marketingcloud/storage/f$a;

    .line 32
    .line 33
    const-string v1, "NOT_DELETED"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/f$a;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->e:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 40
    .line 41
    invoke-static {}, Lcom/salesforce/marketingcloud/storage/f$a;->a()[Lcom/salesforce/marketingcloud/storage/f$a;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->f:[Lcom/salesforce/marketingcloud/storage/f$a;

    .line 46
    .line 47
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

.method private static synthetic a()[Lcom/salesforce/marketingcloud/storage/f$a;
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->b:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/storage/f$a;->c:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/storage/f$a;->d:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 6
    .line 7
    sget-object v3, Lcom/salesforce/marketingcloud/storage/f$a;->e:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lcom/salesforce/marketingcloud/storage/f$a;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/storage/f$a;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/storage/f$a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/storage/f$a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/storage/f$a;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->f:[Lcom/salesforce/marketingcloud/storage/f$a;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/salesforce/marketingcloud/storage/f$a;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/storage/f$a;

    .line 8
    .line 9
    return-object v0
.end method
