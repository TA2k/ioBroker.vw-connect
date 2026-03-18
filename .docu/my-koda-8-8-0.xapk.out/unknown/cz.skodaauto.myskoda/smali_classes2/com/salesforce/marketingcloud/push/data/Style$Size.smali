.class public final enum Lcom/salesforce/marketingcloud/push/data/Style$Size;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/data/Style;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "Size"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/data/Style$Size$a;,
        Lcom/salesforce/marketingcloud/push/data/Style$Size$b;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/push/data/Style$Size;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcom/salesforce/marketingcloud/push/data/Style$Size;

.field public static final Companion:Lcom/salesforce/marketingcloud/push/data/Style$Size$a;

.field public static final enum L:Lcom/salesforce/marketingcloud/push/data/Style$Size;

.field public static final enum M:Lcom/salesforce/marketingcloud/push/data/Style$Size;

.field public static final enum S:Lcom/salesforce/marketingcloud/push/data/Style$Size;


# direct methods
.method private static final synthetic $values()[Lcom/salesforce/marketingcloud/push/data/Style$Size;
    .locals 3

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;->S:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/push/data/Style$Size;->M:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/push/data/Style$Size;->L:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Lcom/salesforce/marketingcloud/push/data/Style$Size;

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
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 2
    .line 3
    const-string v1, "S"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/push/data/Style$Size;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;->S:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 12
    .line 13
    const-string v1, "M"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/push/data/Style$Size;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;->M:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 20
    .line 21
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 22
    .line 23
    const-string v1, "L"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/push/data/Style$Size;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;->L:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 30
    .line 31
    invoke-static {}, Lcom/salesforce/marketingcloud/push/data/Style$Size;->$values()[Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;->$VALUES:[Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 36
    .line 37
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;->$ENTRIES:Lsx0/a;

    .line 42
    .line 43
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/Style$Size$a;

    .line 44
    .line 45
    const/4 v1, 0x0

    .line 46
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/data/Style$Size$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;->Companion:Lcom/salesforce/marketingcloud/push/data/Style$Size$a;

    .line 50
    .line 51
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
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/Style$Size;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/push/data/Style$Size;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size;->$VALUES:[Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final toSP()F
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/Style$Size$b;->a:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    aget p0, v0, p0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-eq p0, v0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x3

    .line 16
    if-ne p0, v0, :cond_0

    .line 17
    .line 18
    const/high16 p0, 0x41600000    # 14.0f

    .line 19
    .line 20
    return p0

    .line 21
    :cond_0
    new-instance p0, La8/r0;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    const/high16 p0, 0x41400000    # 12.0f

    .line 28
    .line 29
    return p0

    .line 30
    :cond_2
    const/high16 p0, 0x41200000    # 10.0f

    .line 31
    .line 32
    return p0
.end method
