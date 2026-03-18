.class Lcom/salesforce/marketingcloud/messages/geofence/a$c;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/geofence/a;->b()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/geofence/a;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/geofence/a;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$c;->c:Lcom/salesforce/marketingcloud/messages/geofence/a;

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
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$c;->c:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/j;->d(I)Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-nez v2, :cond_0

    .line 19
    .line 20
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$c;->c:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 21
    .line 22
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/geofence/a;->d:Lcom/salesforce/marketingcloud/location/f;

    .line 23
    .line 24
    invoke-virtual {v2, v0}, Lcom/salesforce/marketingcloud/location/f;->a(Ljava/util/List;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$c;->c:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 28
    .line 29
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 30
    .line 31
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p0, v1}, Lcom/salesforce/marketingcloud/storage/j;->f(I)I

    .line 36
    .line 37
    .line 38
    return-void
.end method
