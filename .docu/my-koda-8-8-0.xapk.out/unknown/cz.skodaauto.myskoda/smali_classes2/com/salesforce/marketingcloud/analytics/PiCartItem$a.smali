.class public final Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/analytics/PiCartItem;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;ID)Lcom/salesforce/marketingcloud/analytics/PiCartItem;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    const-string p0, "item"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;

    invoke-direct {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/PiCartItem;-><init>(Ljava/lang/String;ID)V

    return-object p0
.end method

.method public final a(Ljava/lang/String;IDLjava/lang/String;)Lcom/salesforce/marketingcloud/analytics/PiCartItem;
    .locals 6
    .annotation runtime Llx0/c;
    .end annotation

    const-string p0, "item"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;

    move-object v1, p1

    move v2, p2

    move-wide v3, p3

    move-object v5, p5

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/analytics/PiCartItem;-><init>(Ljava/lang/String;IDLjava/lang/String;)V

    return-object v0
.end method
