.class public final enum Lcom/salesforce/marketingcloud/media/o$b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/media/o;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "b"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/media/o$b;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum c:Lcom/salesforce/marketingcloud/media/o$b;

.field public static final enum d:Lcom/salesforce/marketingcloud/media/o$b;

.field public static final enum e:Lcom/salesforce/marketingcloud/media/o$b;

.field private static final synthetic f:[Lcom/salesforce/marketingcloud/media/o$b;


# instance fields
.field final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/media/o$b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const v2, -0xff0100

    .line 5
    .line 6
    .line 7
    const-string v3, "MEMORY"

    .line 8
    .line 9
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/media/o$b;-><init>(Ljava/lang/String;II)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lcom/salesforce/marketingcloud/media/o$b;->c:Lcom/salesforce/marketingcloud/media/o$b;

    .line 13
    .line 14
    new-instance v0, Lcom/salesforce/marketingcloud/media/o$b;

    .line 15
    .line 16
    const/4 v1, 0x1

    .line 17
    const v2, -0xffff01

    .line 18
    .line 19
    .line 20
    const-string v3, "DISK"

    .line 21
    .line 22
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/media/o$b;-><init>(Ljava/lang/String;II)V

    .line 23
    .line 24
    .line 25
    sput-object v0, Lcom/salesforce/marketingcloud/media/o$b;->d:Lcom/salesforce/marketingcloud/media/o$b;

    .line 26
    .line 27
    new-instance v0, Lcom/salesforce/marketingcloud/media/o$b;

    .line 28
    .line 29
    const/4 v1, 0x2

    .line 30
    const/high16 v2, -0x10000

    .line 31
    .line 32
    const-string v3, "NETWORK"

    .line 33
    .line 34
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/media/o$b;-><init>(Ljava/lang/String;II)V

    .line 35
    .line 36
    .line 37
    sput-object v0, Lcom/salesforce/marketingcloud/media/o$b;->e:Lcom/salesforce/marketingcloud/media/o$b;

    .line 38
    .line 39
    invoke-static {}, Lcom/salesforce/marketingcloud/media/o$b;->a()[Lcom/salesforce/marketingcloud/media/o$b;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sput-object v0, Lcom/salesforce/marketingcloud/media/o$b;->f:[Lcom/salesforce/marketingcloud/media/o$b;

    .line 44
    .line 45
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
    iput p3, p0, Lcom/salesforce/marketingcloud/media/o$b;->b:I

    .line 5
    .line 6
    return-void
.end method

.method private static synthetic a()[Lcom/salesforce/marketingcloud/media/o$b;
    .locals 3

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/media/o$b;->c:Lcom/salesforce/marketingcloud/media/o$b;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/media/o$b;->d:Lcom/salesforce/marketingcloud/media/o$b;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/media/o$b;->e:Lcom/salesforce/marketingcloud/media/o$b;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Lcom/salesforce/marketingcloud/media/o$b;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/media/o$b;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/media/o$b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/media/o$b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/media/o$b;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/media/o$b;->f:[Lcom/salesforce/marketingcloud/media/o$b;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/salesforce/marketingcloud/media/o$b;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/media/o$b;

    .line 8
    .line 9
    return-object v0
.end method
