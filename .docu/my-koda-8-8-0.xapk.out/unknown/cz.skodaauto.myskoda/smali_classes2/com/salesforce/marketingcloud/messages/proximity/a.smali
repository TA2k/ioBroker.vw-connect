.class public final Lcom/salesforce/marketingcloud/messages/proximity/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/messages/c;
.implements Lcom/salesforce/marketingcloud/proximity/e$a;
.implements Lcom/salesforce/marketingcloud/http/e$c;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field static final j:Ljava/lang/String;


# instance fields
.field final d:Lcom/salesforce/marketingcloud/storage/h;

.field final e:Lcom/salesforce/marketingcloud/proximity/e;

.field final f:Lcom/salesforce/marketingcloud/messages/c$a;

.field final g:Lcom/salesforce/marketingcloud/http/e;

.field private final h:Lcom/salesforce/marketingcloud/internal/n;

.field private i:Lcom/salesforce/marketingcloud/messages/c$b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "ProximityMessageManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/proximity/e;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/messages/c$a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/e;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 9
    .line 10
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    .line 11
    .line 12
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->f:Lcom/salesforce/marketingcloud/messages/c$a;

    .line 13
    .line 14
    sget-object p1, Lcom/salesforce/marketingcloud/http/b;->o:Lcom/salesforce/marketingcloud/http/b;

    .line 15
    .line 16
    invoke-virtual {p3, p1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/proximity/e;Lcom/salesforce/marketingcloud/http/e;Z)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/proximity/e;->c()V

    if-eqz p3, :cond_0

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    move-result-object p1

    const/4 p3, 0x3

    invoke-interface {p1, p3}, Lcom/salesforce/marketingcloud/storage/j;->f(I)I

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    move-result-object p0

    const/4 p1, 0x5

    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/storage/i;->e(I)I

    .line 4
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/http/b;->o:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {p2, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/e;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/proximity/e;->a(Lcom/salesforce/marketingcloud/proximity/e$a;)V

    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->g:Lcom/salesforce/marketingcloud/http/e;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->o:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {v0, v1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 1

    .line 12
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result p1

    if-eqz p1, :cond_0

    .line 13
    :try_start_0
    new-instance p1, Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;

    new-instance v0, Lorg/json/JSONObject;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->j()Ljava/lang/String;

    move-result-object p2

    invoke-direct {v0, p2}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    invoke-direct {p1, v0}, Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;-><init>(Lorg/json/JSONObject;)V

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/proximity/a;->a(Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 14
    sget-object p1, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string v0, "Error parsing response."

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 15
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object p2

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Request failed: %d - %s"

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/location/LatLon;Ljava/lang/String;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/messages/c$b;)V
    .locals 0

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->i:Lcom/salesforce/marketingcloud/messages/c$b;

    .line 6
    :try_start_0
    new-instance p4, Lcom/salesforce/marketingcloud/messages/proximity/a$a;

    invoke-direct {p4, p0, p3, p2, p1}, Lcom/salesforce/marketingcloud/messages/proximity/a$a;-><init>(Lcom/salesforce/marketingcloud/messages/proximity/a;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;)V

    invoke-static {p4}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 7
    sget-object p1, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string p3, "Failed to update proximity messages"

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;)V
    .locals 4

    .line 16
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;->beacons()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Proximity message request contained %d regions"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->i:Lcom/salesforce/marketingcloud/messages/c$b;

    if-eqz v0, :cond_0

    .line 18
    invoke-interface {v0, p1}, Lcom/salesforce/marketingcloud/messages/c$b;->a(Lcom/salesforce/marketingcloud/messages/MessageResponse;)V

    .line 19
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/proximity/a$e;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "beacon_response"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/proximity/a$e;-><init>(Lcom/salesforce/marketingcloud/messages/proximity/a;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/proximity/c;)V
    .locals 3

    .line 10
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/proximity/c;->n()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Proximity region (%s) exited."

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/proximity/a$d;

    invoke-direct {v1, p0, p1}, Lcom/salesforce/marketingcloud/messages/proximity/a$d;-><init>(Lcom/salesforce/marketingcloud/messages/proximity/a;Lcom/salesforce/marketingcloud/proximity/c;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public b()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/e;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/proximity/e;->c()V

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/e;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/proximity/e;->b(Lcom/salesforce/marketingcloud/proximity/e$a;)V

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->g:Lcom/salesforce/marketingcloud/http/e;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->o:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/proximity/a$b;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "disable_beacon_tracking"

    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/messages/proximity/a$b;-><init>(Lcom/salesforce/marketingcloud/messages/proximity/a;Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/proximity/c;)V
    .locals 4

    .line 5
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/proximity/c;->n()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Proximity region (%s) entered."

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->h:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/proximity/a$c;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, ""

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/proximity/a$c;-><init>(Lcom/salesforce/marketingcloud/messages/proximity/a;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/proximity/c;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public c()V
    .locals 5

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v3, "monitorStoredRegions"

    .line 7
    .line 8
    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 12
    .line 13
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 18
    .line 19
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const/4 v3, 0x3

    .line 24
    invoke-interface {v0, v3, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(ILcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-nez v2, :cond_1

    .line 33
    .line 34
    new-instance v2, Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 41
    .line 42
    .line 43
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-eqz v3, :cond_0

    .line 52
    .line 53
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    check-cast v3, Lcom/salesforce/marketingcloud/messages/Region;

    .line 58
    .line 59
    new-instance v4, Lcom/salesforce/marketingcloud/proximity/c;

    .line 60
    .line 61
    invoke-direct {v4, v3}, Lcom/salesforce/marketingcloud/proximity/c;-><init>(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 69
    .line 70
    const-string v3, "Monitoring beacons [%s]"

    .line 71
    .line 72
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    invoke-static {v0, v3, v4}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/e;

    .line 80
    .line 81
    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/proximity/e;->a(Ljava/util/List;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 82
    .line 83
    .line 84
    :cond_1
    return-void

    .line 85
    :catch_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 86
    .line 87
    new-array v0, v1, [Ljava/lang/Object;

    .line 88
    .line 89
    const-string v1, "Unable to monitor stored proximity regions."

    .line 90
    .line 91
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    return-void
.end method

.method public d()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/e;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/proximity/e;->b()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
