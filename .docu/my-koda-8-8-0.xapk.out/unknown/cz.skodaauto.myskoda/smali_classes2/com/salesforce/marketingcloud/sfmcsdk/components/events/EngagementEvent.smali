.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;
.super Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010$\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00086\u0018\u00002\u00020\u0001B\u000f\u0008\u0004\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004J\u0014\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\r0\u000cH\u0016J\u0008\u0010\u0002\u001a\u00020\u0003H\u0016R\u001a\u0010\u0005\u001a\u00020\u0006X\u0096\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0007\u0010\u0008\"\u0004\u0008\t\u0010\nR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u0082\u0001\u0003\u000e\u000f\u0010\u00a8\u0006\u0011"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;",
        "name",
        "",
        "(Ljava/lang/String;)V",
        "category",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;",
        "getCategory",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;",
        "setCategory",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;)V",
        "attributes",
        "",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CartEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/OrderEvent;",
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


# instance fields
.field private category:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

.field private final name:Ljava/lang/String;


# direct methods
.method private constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;->name:Ljava/lang/String;

    .line 4
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;->ENGAGEMENT:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;->category:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;-><init>(Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public attributes()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCategory()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;->category:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    .line 2
    .line 3
    return-object p0
.end method

.method public name()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public setCategory(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;->category:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    .line 7
    .line 8
    return-void
.end method
