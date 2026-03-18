.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000<\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002J\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\u0007\u001a\u0004\u0018\u00010\u00082\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\t\u001a\u0004\u0018\u00010\n2\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\u000b\u001a\u0004\u0018\u00010\u000c2\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\r\u001a\u0004\u0018\u00010\u000e2\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\u000f\u001a\u0004\u0018\u00010\u00102\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\u0011\u001a\u0004\u0018\u00010\u00122\u0006\u0010\u0005\u001a\u00020\u0006H\u0007\u00a8\u0006\u0013"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;",
        "",
        "()V",
        "cancel",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CancelOrderEvent;",
        "order",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;",
        "deliver",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/DeliverOrderEvent;",
        "exchange",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ExchangeOrderEvent;",
        "preorder",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PreorderEvent;",
        "purchase",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PurchaseOrderEvent;",
        "returnOrder",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReturnOrderEvent;",
        "ship",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShipOrderEvent;",
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final cancel(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CancelOrderEvent;
    .locals 0

    .line 1
    const-string p0, "order"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CancelOrderEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CancelOrderEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final deliver(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/DeliverOrderEvent;
    .locals 0

    .line 1
    const-string p0, "order"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/DeliverOrderEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/DeliverOrderEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final exchange(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ExchangeOrderEvent;
    .locals 0

    .line 1
    const-string p0, "order"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ExchangeOrderEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ExchangeOrderEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final preorder(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PreorderEvent;
    .locals 0

    .line 1
    const-string p0, "order"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PreorderEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PreorderEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final purchase(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PurchaseOrderEvent;
    .locals 0

    .line 1
    const-string p0, "order"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PurchaseOrderEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PurchaseOrderEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final returnOrder(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReturnOrderEvent;
    .locals 0

    .line 1
    const-string p0, "order"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReturnOrderEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReturnOrderEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final ship(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShipOrderEvent;
    .locals 0

    .line 1
    const-string p0, "order"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShipOrderEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShipOrderEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method
