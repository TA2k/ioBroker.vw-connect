.class Lcom/salesforce/marketingcloud/messages/d$d;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/d;->a(Landroid/location/Location;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/location/LatLon;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/d;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/d;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/location/LatLon;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/d$d;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/d$d;->c:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 4

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d$d;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d$d;->c:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 4
    .line 5
    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 6
    .line 7
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/d$d;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 12
    .line 13
    iget-object v3, v3, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    .line 15
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-interface {v2, v3}, Lcom/salesforce/marketingcloud/storage/j;->l(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Region;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {v0, v1, v2}, Lcom/salesforce/marketingcloud/messages/d;->a(Lcom/salesforce/marketingcloud/location/LatLon;Lcom/salesforce/marketingcloud/messages/Region;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d$d;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 28
    .line 29
    iget-object v1, v1, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 30
    .line 31
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->m()Lcom/salesforce/marketingcloud/storage/g;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/d$d;->c:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 36
    .line 37
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/d$d;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 38
    .line 39
    iget-object v3, v3, Lcom/salesforce/marketingcloud/messages/d;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 40
    .line 41
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    invoke-interface {v1, v2, v3}, Lcom/salesforce/marketingcloud/storage/g;->a(Lcom/salesforce/marketingcloud/location/LatLon;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 46
    .line 47
    .line 48
    if-eqz v0, :cond_0

    .line 49
    .line 50
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d$d;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 51
    .line 52
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d$d;->c:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 53
    .line 54
    const/16 v2, 0x1388

    .line 55
    .line 56
    invoke-virtual {v0, v1, v2}, Lcom/salesforce/marketingcloud/messages/d;->a(Lcom/salesforce/marketingcloud/location/LatLon;I)V

    .line 57
    .line 58
    .line 59
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d$d;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 60
    .line 61
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/d$d;->c:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/messages/d;->a(Lcom/salesforce/marketingcloud/location/LatLon;)V

    .line 64
    .line 65
    .line 66
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/d$d;->d:Lcom/salesforce/marketingcloud/messages/d;

    .line 67
    .line 68
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/d$d;->c:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 69
    .line 70
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/messages/d;->b(Lcom/salesforce/marketingcloud/location/LatLon;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 71
    .line 72
    .line 73
    :cond_0
    return-void

    .line 74
    :catch_0
    move-exception p0

    .line 75
    sget-object v0, Lcom/salesforce/marketingcloud/messages/d;->B:Ljava/lang/String;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    new-array v1, v1, [Ljava/lang/Object;

    .line 79
    .line 80
    const-string v2, "Unable to store last location"

    .line 81
    .line 82
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    return-void
.end method
