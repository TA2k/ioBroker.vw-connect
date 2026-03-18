.class Lcom/salesforce/marketingcloud/proximity/d;
.super Lcom/salesforce/marketingcloud/proximity/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final i:Z

.field private final j:Lorg/json/JSONObject;


# direct methods
.method public constructor <init>(ZLorg/json/JSONObject;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/proximity/e;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/proximity/d;->i:Z

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/proximity/d;->j:Lorg/json/JSONObject;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/proximity/d;->i:Z

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->d(Z)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/proximity/e$a;)V
    .locals 1

    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    if-eqz p1, :cond_0

    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_0
    const-string p1, "null"

    :goto_0
    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 5
    const-string v0, "registerProximityEventListener(%s) call ignored because of unsupported device."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/proximity/c;",
            ">;)V"
        }
    .end annotation

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "monitorBeaconRegions call ignored because of unsupported device."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/proximity/e$a;)V
    .locals 1

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    if-eqz p1, :cond_0

    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_0
    const-string p1, "null"

    :goto_0
    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 4
    const-string v0, "unregisterProximityEventListener(%s) call ignored because of unsupported device."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public b(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/proximity/c;",
            ">;)V"
        }
    .end annotation

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "unmonitorBeaconRegions call ignored because of unsupported device."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public c()V
    .locals 2

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    new-array v0, v0, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v1, "stopMonitoringBeaconRegions() call ignored because of unsupported device."

    .line 7
    .line 8
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/d;->j:Lorg/json/JSONObject;

    .line 2
    .line 3
    return-object p0
.end method
