.class Lcom/salesforce/marketingcloud/messages/geofence/a$e;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/geofence/a;->c()V
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
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$e;->c:Lcom/salesforce/marketingcloud/messages/geofence/a;

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
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$e;->c:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->i:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    sget-object v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    .line 13
    .line 14
    new-array v2, v1, [Ljava/lang/Object;

    .line 15
    .line 16
    const-string v3, "Attempt to monitor fences from DB ignored, because they\'re already monitored."

    .line 17
    .line 18
    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    .line 22
    .line 23
    new-array v2, v1, [Ljava/lang/Object;

    .line 24
    .line 25
    const-string v3, "monitorStoredRegions"

    .line 26
    .line 27
    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$e;->c:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 31
    .line 32
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 33
    .line 34
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$e;->c:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 39
    .line 40
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 41
    .line 42
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    const/4 v3, 0x1

    .line 47
    invoke-interface {v0, v3, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(ILcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-nez v2, :cond_1

    .line 56
    .line 57
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-eqz v2, :cond_1

    .line 66
    .line 67
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    check-cast v2, Lcom/salesforce/marketingcloud/messages/Region;

    .line 72
    .line 73
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$e;->c:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 74
    .line 75
    iget-object v3, v3, Lcom/salesforce/marketingcloud/messages/geofence/a;->d:Lcom/salesforce/marketingcloud/location/f;

    .line 76
    .line 77
    invoke-static {v2}, Lcom/salesforce/marketingcloud/messages/geofence/a;->a(Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/location/b;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/location/b;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    invoke-virtual {v3, v2}, Lcom/salesforce/marketingcloud/location/f;->a([Lcom/salesforce/marketingcloud/location/b;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :catch_0
    move-exception p0

    .line 90
    goto :goto_1

    .line 91
    :cond_1
    return-void

    .line 92
    :goto_1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    .line 93
    .line 94
    new-array v1, v1, [Ljava/lang/Object;

    .line 95
    .line 96
    const-string v2, "Unable to monitor stored geofence regions."

    .line 97
    .line 98
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    return-void
.end method
