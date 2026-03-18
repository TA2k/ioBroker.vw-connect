.class public final Lcom/salesforce/marketingcloud/analytics/piwama/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/analytics/piwama/c;


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/analytics/PiCart;

.field private final b:Ljava/util/Date;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/analytics/PiCart;Ljava/util/Date;)V
    .locals 1

    .line 1
    const-string v0, "piCart"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "timestamp"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/f;->a:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/f;->b:Ljava/util/Date;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public a()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, ""

    .line 2
    .line 3
    return-object p0
.end method

.method public b()I
    .locals 0

    .line 1
    const/16 p0, 0x378

    .line 2
    .line 3
    return p0
.end method

.method public c()Lorg/json/JSONObject;
    .locals 2

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/f;->a:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 10
    .line 11
    iget-object v1, v1, Lcom/salesforce/marketingcloud/analytics/PiCart;->cartItems:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/f;->a:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 20
    .line 21
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/PiCart;->toJson$sdk_release()Lorg/json/JSONArray;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string v1, "cart"

    .line 26
    .line 27
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 28
    .line 29
    .line 30
    return-object v0

    .line 31
    :cond_0
    const-string p0, "clear_cart"

    .line 32
    .line 33
    const/4 v1, 0x1

    .line 34
    invoke-virtual {v0, p0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 35
    .line 36
    .line 37
    return-object v0
.end method

.method public d()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "track_cart"

    .line 2
    .line 3
    return-object p0
.end method

.method public e()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/f;->b:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method
