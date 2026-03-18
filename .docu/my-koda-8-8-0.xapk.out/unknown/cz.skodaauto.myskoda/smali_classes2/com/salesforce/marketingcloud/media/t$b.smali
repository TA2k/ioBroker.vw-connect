.class public final enum Lcom/salesforce/marketingcloud/media/t$b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/media/t;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "b"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/media/t$b;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum c:Lcom/salesforce/marketingcloud/media/t$b;

.field public static final enum d:Lcom/salesforce/marketingcloud/media/t$b;

.field public static final enum e:Lcom/salesforce/marketingcloud/media/t$b;

.field private static final synthetic f:[Lcom/salesforce/marketingcloud/media/t$b;


# instance fields
.field b:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/media/t$b;

    .line 2
    .line 3
    const-string v1, "NO_MEMORY_CACHE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    invoke-direct {v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/media/t$b;-><init>(Ljava/lang/String;II)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lcom/salesforce/marketingcloud/media/t$b;->c:Lcom/salesforce/marketingcloud/media/t$b;

    .line 11
    .line 12
    new-instance v0, Lcom/salesforce/marketingcloud/media/t$b;

    .line 13
    .line 14
    const-string v1, "NO_MEMORY_STORE"

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    invoke-direct {v0, v1, v3, v2}, Lcom/salesforce/marketingcloud/media/t$b;-><init>(Ljava/lang/String;II)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lcom/salesforce/marketingcloud/media/t$b;->d:Lcom/salesforce/marketingcloud/media/t$b;

    .line 21
    .line 22
    new-instance v0, Lcom/salesforce/marketingcloud/media/t$b;

    .line 23
    .line 24
    const-string v1, "NO_DISK_STORE"

    .line 25
    .line 26
    const/4 v3, 0x4

    .line 27
    invoke-direct {v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/media/t$b;-><init>(Ljava/lang/String;II)V

    .line 28
    .line 29
    .line 30
    sput-object v0, Lcom/salesforce/marketingcloud/media/t$b;->e:Lcom/salesforce/marketingcloud/media/t$b;

    .line 31
    .line 32
    invoke-static {}, Lcom/salesforce/marketingcloud/media/t$b;->a()[Lcom/salesforce/marketingcloud/media/t$b;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    sput-object v0, Lcom/salesforce/marketingcloud/media/t$b;->f:[Lcom/salesforce/marketingcloud/media/t$b;

    .line 37
    .line 38
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
    iput p3, p0, Lcom/salesforce/marketingcloud/media/t$b;->b:I

    .line 5
    .line 6
    return-void
.end method

.method public static a(I)Z
    .locals 1

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/media/t$b;->c:Lcom/salesforce/marketingcloud/media/t$b;

    iget v0, v0, Lcom/salesforce/marketingcloud/media/t$b;->b:I

    and-int/2addr p0, v0

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method private static synthetic a()[Lcom/salesforce/marketingcloud/media/t$b;
    .locals 3

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/media/t$b;->c:Lcom/salesforce/marketingcloud/media/t$b;

    sget-object v1, Lcom/salesforce/marketingcloud/media/t$b;->d:Lcom/salesforce/marketingcloud/media/t$b;

    sget-object v2, Lcom/salesforce/marketingcloud/media/t$b;->e:Lcom/salesforce/marketingcloud/media/t$b;

    filled-new-array {v0, v1, v2}, [Lcom/salesforce/marketingcloud/media/t$b;

    move-result-object v0

    return-object v0
.end method

.method public static b(I)Z
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/media/t$b;->d:Lcom/salesforce/marketingcloud/media/t$b;

    iget v0, v0, Lcom/salesforce/marketingcloud/media/t$b;->b:I

    and-int/2addr p0, v0

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static c(I)Z
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/media/t$b;->e:Lcom/salesforce/marketingcloud/media/t$b;

    .line 2
    .line 3
    iget v0, v0, Lcom/salesforce/marketingcloud/media/t$b;->b:I

    .line 4
    .line 5
    and-int/2addr p0, v0

    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    return p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/media/t$b;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/media/t$b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/media/t$b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/media/t$b;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/media/t$b;->f:[Lcom/salesforce/marketingcloud/media/t$b;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/salesforce/marketingcloud/media/t$b;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/media/t$b;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public b()I
    .locals 0

    .line 2
    iget p0, p0, Lcom/salesforce/marketingcloud/media/t$b;->b:I

    return p0
.end method
