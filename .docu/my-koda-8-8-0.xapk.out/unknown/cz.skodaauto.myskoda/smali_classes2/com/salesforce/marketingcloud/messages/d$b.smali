.class Lcom/salesforce/marketingcloud/messages/d$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/d;->j()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/d;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/d;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/d$b;->c:Lcom/salesforce/marketingcloud/messages/d;

    .line 2
    .line 3
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d$b;->c:Lcom/salesforce/marketingcloud/messages/d;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->m()Lcom/salesforce/marketingcloud/storage/g;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d$b;->c:Lcom/salesforce/marketingcloud/messages/d;

    .line 12
    .line 13
    iget-object v1, v1, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    .line 15
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/g;->e(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/location/LatLon;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d$b;->c:Lcom/salesforce/marketingcloud/messages/d;

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/messages/d;->b(Lcom/salesforce/marketingcloud/location/LatLon;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void
.end method
