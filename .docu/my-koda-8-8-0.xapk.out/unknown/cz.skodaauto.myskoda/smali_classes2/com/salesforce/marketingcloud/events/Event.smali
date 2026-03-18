.class public interface abstract Lcom/salesforce/marketingcloud/events/Event;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation


# direct methods
.method public static synthetic a(Lcom/salesforce/marketingcloud/events/Event;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/events/Event;->track$lambda$0(Lcom/salesforce/marketingcloud/events/Event;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static track$lambda$0(Lcom/salesforce/marketingcloud/events/Event;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 2

    .line 1
    const-string v0, "this$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "it"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getEventManager()Lcom/salesforce/marketingcloud/events/EventManager;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    const/4 v0, 0x1

    .line 16
    new-array v0, v0, [Lcom/salesforce/marketingcloud/events/Event;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    aput-object p0, v0, v1

    .line 20
    .line 21
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/events/EventManager;->track([Lcom/salesforce/marketingcloud/events/Event;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public abstract attributes()Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end method

.method public getProducer()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;->PUSH:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract name()Ljava/lang/String;
.end method

.method public track()V
    .locals 2

    .line 1
    new-instance v0, La8/t;

    .line 2
    .line 3
    const/16 v1, 0x12

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method
