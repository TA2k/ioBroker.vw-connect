.class public final enum Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

.field public static final enum BUYNOW:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

.field public static final enum CHECKOUT:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

.field public static final enum PAY:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

.field public static final enum PAYPAL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;


# instance fields
.field private final value:Ljava/lang/String;


# direct methods
.method private static synthetic $values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;
    .locals 4

    .line 1
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->PAYPAL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 2
    .line 3
    sget-object v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->CHECKOUT:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 4
    .line 5
    sget-object v2, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->PAY:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 6
    .line 7
    sget-object v3, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->BUYNOW:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "paypal"

    .line 5
    .line 6
    const-string v3, "PAYPAL"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->PAYPAL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 12
    .line 13
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    const-string v2, "checkout"

    .line 17
    .line 18
    const-string v3, "CHECKOUT"

    .line 19
    .line 20
    invoke-direct {v0, v3, v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->CHECKOUT:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 24
    .line 25
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    const-string v2, "pay"

    .line 29
    .line 30
    const-string v3, "PAY"

    .line 31
    .line 32
    invoke-direct {v0, v3, v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->PAY:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 36
    .line 37
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 38
    .line 39
    const/4 v1, 0x3

    .line 40
    const-string v2, "buynow"

    .line 41
    .line 42
    const-string v3, "BUYNOW"

    .line 43
    .line 44
    invoke-direct {v0, v3, v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->BUYNOW:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 48
    .line 49
    invoke-static {}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->$values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->$VALUES:[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 54
    .line 55
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
    iput-object p3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->value:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;
    .locals 1

    .line 1
    const-class v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;
    .locals 1

    .line 1
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->$VALUES:[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
