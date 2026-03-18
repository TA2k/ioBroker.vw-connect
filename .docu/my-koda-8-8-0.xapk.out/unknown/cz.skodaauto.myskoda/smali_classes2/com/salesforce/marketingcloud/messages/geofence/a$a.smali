.class Lcom/salesforce/marketingcloud/messages/geofence/a$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/geofence/a;->a(Lcom/salesforce/marketingcloud/location/LatLon;Ljava/lang/String;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/messages/c$b;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field final synthetic b:Ljava/lang/String;

.field final synthetic c:Lcom/salesforce/marketingcloud/location/LatLon;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/geofence/a;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/geofence/a;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$a;->d:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$a;->a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$a;->b:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$a;->c:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public ready(Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 5

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$a;->d:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 2
    .line 3
    iget-object v0, p1, Lcom/salesforce/marketingcloud/messages/geofence/a;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 4
    .line 5
    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->n:Lcom/salesforce/marketingcloud/http/b;

    .line 6
    .line 7
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$a;->a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 8
    .line 9
    iget-object p1, p1, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 10
    .line 11
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$a;->a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 16
    .line 17
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$a;->b:Ljava/lang/String;

    .line 22
    .line 23
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$a;->c:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 24
    .line 25
    invoke-static {v3, v4, p0}, Lcom/salesforce/marketingcloud/http/b;->a(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;)[Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v1, v2, p1, p0}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;[Ljava/lang/Object;)Lcom/salesforce/marketingcloud/http/c;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/c;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method
