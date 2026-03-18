.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002J\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\u0007\u001a\u0004\u0018\u00010\u00082\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0018\u0010\t\u001a\u0004\u0018\u00010\n2\u000c\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u000cH\u0007\u00a8\u0006\r"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;",
        "",
        "()V",
        "add",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/AddToCartEvent;",
        "lineItem",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;",
        "remove",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/RemoveFromCartEvent;",
        "replace",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReplaceCartEvent;",
        "lineItems",
        "",
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final add(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/AddToCartEvent;
    .locals 0

    .line 1
    const-string p0, "lineItem"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/AddToCartEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/AddToCartEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;)V
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

.method public final remove(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/RemoveFromCartEvent;
    .locals 0

    .line 1
    const-string p0, "lineItem"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/RemoveFromCartEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/RemoveFromCartEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;)V
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

.method public final replace(Ljava/util/List;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReplaceCartEvent;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;",
            ">;)",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReplaceCartEvent;"
        }
    .end annotation

    .line 1
    const-string p0, "lineItems"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReplaceCartEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReplaceCartEvent;-><init>(Ljava/util/List;)V
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
