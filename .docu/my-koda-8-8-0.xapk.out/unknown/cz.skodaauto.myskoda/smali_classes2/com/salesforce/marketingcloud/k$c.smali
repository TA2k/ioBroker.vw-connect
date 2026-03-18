.class Lcom/salesforce/marketingcloud/k$c;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/k;->a(Lorg/json/JSONArray;I)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/k$e;

.field final synthetic d:Lorg/json/JSONObject;

.field final synthetic e:Lcom/salesforce/marketingcloud/k;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/k;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/k$e;Lorg/json/JSONObject;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/k$c;->e:Lcom/salesforce/marketingcloud/k;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/k$c;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 4
    .line 5
    iput-object p5, p0, Lcom/salesforce/marketingcloud/k$c;->d:Lorg/json/JSONObject;

    .line 6
    .line 7
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/k$c;->e:Lcom/salesforce/marketingcloud/k;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/k;->l:Ljava/util/Map;

    .line 4
    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/k$c;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 6
    .line 7
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lcom/salesforce/marketingcloud/k$f;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-object v1, p0, Lcom/salesforce/marketingcloud/k$c;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 16
    .line 17
    iget-object p0, p0, Lcom/salesforce/marketingcloud/k$c;->d:Lorg/json/JSONObject;

    .line 18
    .line 19
    invoke-interface {v0, v1, p0}, Lcom/salesforce/marketingcloud/k$f;->onSyncReceived(Lcom/salesforce/marketingcloud/k$e;Lorg/json/JSONObject;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method
