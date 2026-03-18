.class public final Lcom/salesforce/marketingcloud/analytics/piwama/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/analytics/piwama/c;


# instance fields
.field private final a:Ljava/util/Date;

.field private final b:Z

.field private final c:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/util/Date;ZLjava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Date;",
            "Z",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "timestamp"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "objectIds"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/e;->a:Ljava/util/Date;

    .line 15
    .line 16
    iput-boolean p2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/e;->b:Z

    .line 17
    .line 18
    iput-object p3, p0, Lcom/salesforce/marketingcloud/analytics/piwama/e;->c:Ljava/util/List;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public a()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "app_open"

    .line 2
    .line 3
    return-object p0
.end method

.method public b()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public c()Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->a(Lorg/json/JSONObject;)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lorg/json/JSONObject;

    .line 10
    .line 11
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 12
    .line 13
    .line 14
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/e;->b:Z

    .line 15
    .line 16
    const-string v3, "open_from_push"

    .line 17
    .line 18
    invoke-virtual {v1, v3, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 19
    .line 20
    .line 21
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/e;->c:Ljava/util/List;

    .line 22
    .line 23
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-nez v2, :cond_0

    .line 28
    .line 29
    new-instance v2, Lorg/json/JSONArray;

    .line 30
    .line 31
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/e;->c:Ljava/util/List;

    .line 32
    .line 33
    invoke-direct {v2, p0}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    .line 34
    .line 35
    .line 36
    const-string p0, "message_ids"

    .line 37
    .line 38
    invoke-virtual {v1, p0, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 39
    .line 40
    .line 41
    :cond_0
    const-string p0, "details"

    .line 42
    .line 43
    invoke-virtual {v0, p0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 44
    .line 45
    .line 46
    return-object v0
.end method

.method public d()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "track_event"

    .line 2
    .line 3
    return-object p0
.end method

.method public e()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/e;->a:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method
