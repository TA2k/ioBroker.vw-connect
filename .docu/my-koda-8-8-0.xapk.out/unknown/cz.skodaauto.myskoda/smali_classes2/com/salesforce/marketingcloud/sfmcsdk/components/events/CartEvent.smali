.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;
.super Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00086\u0018\u0000 \n2\u00020\u0001:\u0001\nB\u001d\u0008\u0004\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u000c\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u0005\u00a2\u0006\u0002\u0010\u0007R\u0017\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0008\u0010\t\u0082\u0001\u0003\u000b\u000c\r\u00a8\u0006\u000e"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;",
        "name",
        "",
        "lineItems",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;",
        "(Ljava/lang/String;Ljava/util/List;)V",
        "getLineItems",
        "()Ljava/util/List;",
        "Companion",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/AddToCartEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/RemoveFromCartEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReplaceCartEvent;",
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
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;


# instance fields
.field private final lineItems:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;",
            ">;)V"
        }
    .end annotation

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;-><init>(Ljava/lang/String;Lkotlin/jvm/internal/g;)V

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;->lineItems:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/util/List;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;-><init>(Ljava/lang/String;Ljava/util/List;)V

    return-void
.end method

.method public static final add(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/AddToCartEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;->add(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/AddToCartEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final remove(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/RemoveFromCartEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;->remove(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/RemoveFromCartEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final replace(Ljava/util/List;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReplaceCartEvent;
    .locals 1
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
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent$Companion;->replace(Ljava/util/List;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReplaceCartEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method


# virtual methods
.method public final getLineItems()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/LineItem;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;->lineItems:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method
