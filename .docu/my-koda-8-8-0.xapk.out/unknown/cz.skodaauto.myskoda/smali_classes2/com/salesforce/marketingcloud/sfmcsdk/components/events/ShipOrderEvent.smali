.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShipOrderEvent;
.super Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0018\u00002\u00020\u0001B\u000f\u0008\u0000\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShipOrderEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;",
        "order",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V",
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
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;)V
    .locals 2

    .line 1
    const-string v0, "order"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "Ship"

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {p0, v0, p1, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Order;Lkotlin/jvm/internal/g;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method
