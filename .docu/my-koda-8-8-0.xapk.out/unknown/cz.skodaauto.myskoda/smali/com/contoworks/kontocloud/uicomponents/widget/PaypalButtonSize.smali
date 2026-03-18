.class public final enum Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

.field public static final enum RESPONSIVE:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

.field public static final enum SMALL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;


# instance fields
.field private final value:Ljava/lang/String;


# direct methods
.method private static synthetic $values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;
    .locals 2

    .line 1
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->SMALL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 2
    .line 3
    sget-object v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->RESPONSIVE:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "small"

    .line 5
    .line 6
    const-string v3, "SMALL"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->SMALL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 12
    .line 13
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    const-string v2, "responsive"

    .line 17
    .line 18
    const-string v3, "RESPONSIVE"

    .line 19
    .line 20
    invoke-direct {v0, v3, v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->RESPONSIVE:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 24
    .line 25
    invoke-static {}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->$values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->$VALUES:[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 30
    .line 31
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
    iput-object p3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->value:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;
    .locals 1

    .line 1
    const-class v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;
    .locals 1

    .line 1
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->$VALUES:[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
