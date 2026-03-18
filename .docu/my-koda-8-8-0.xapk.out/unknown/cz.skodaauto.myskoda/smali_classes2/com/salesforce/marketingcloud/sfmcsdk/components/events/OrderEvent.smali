.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;
.super Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00086\u0018\u0000 \t2\u00020\u0001:\u0001\tB\u0017\u0008\u0004\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0002\u0010\u0006R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0007\u0010\u0008\u0082\u0001\u0007\n\u000b\u000c\r\u000e\u000f\u0010\u00a8\u0006\u0011"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;",
        "name",
        "",
        "order",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;",
        "(Ljava/lang/String;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V",
        "getOrder",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;",
        "Companion",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CancelOrderEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/DeliverOrderEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ExchangeOrderEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PreorderEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PurchaseOrderEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReturnOrderEvent;",
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


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;


# instance fields
.field private final order:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;-><init>(Ljava/lang/String;Lkotlin/jvm/internal/g;)V

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->order:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V

    return-void
.end method

.method public static final cancel(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CancelOrderEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;->cancel(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CancelOrderEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final deliver(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/DeliverOrderEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;->deliver(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/DeliverOrderEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final exchange(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ExchangeOrderEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;->exchange(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ExchangeOrderEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final preorder(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PreorderEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;->preorder(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PreorderEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final purchase(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PurchaseOrderEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;->purchase(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/PurchaseOrderEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final returnOrder(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReturnOrderEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;->returnOrder(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReturnOrderEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final ship(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShipOrderEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent$Companion;->ship(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShipOrderEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method


# virtual methods
.method public final getOrder()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;->order:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;

    .line 2
    .line 3
    return-object p0
.end method
