.class Lcom/salesforce/marketingcloud/messages/iam/m$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/iam/m;->canDisplay(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/iam/m;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/m;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

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
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->k()Lcom/salesforce/marketingcloud/storage/e;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 10
    .line 11
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/e;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 15
    .line 16
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/iam/m;->f:Lcom/salesforce/marketingcloud/analytics/f;

    .line 17
    .line 18
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 19
    .line 20
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/analytics/f;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 24
    .line 25
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/m;->d()V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 29
    .line 30
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/iam/m;->g:Ljava/lang/Object;

    .line 31
    .line 32
    monitor-enter v0

    .line 33
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 34
    .line 35
    iget-object v1, v1, Lcom/salesforce/marketingcloud/messages/iam/m;->p:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    .line 37
    if-eqz v1, :cond_0

    .line 38
    .line 39
    :try_start_1
    new-instance v1, Landroid/os/Handler;

    .line 40
    .line 41
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-direct {v1, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 46
    .line 47
    .line 48
    new-instance v2, Lcom/salesforce/marketingcloud/messages/iam/m$b$a;

    .line 49
    .line 50
    invoke-direct {v2, p0}, Lcom/salesforce/marketingcloud/messages/iam/m$b$a;-><init>(Lcom/salesforce/marketingcloud/messages/iam/m$b;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :catchall_0
    move-exception p0

    .line 58
    goto :goto_1

    .line 59
    :catch_0
    move-exception p0

    .line 60
    :try_start_2
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 61
    .line 62
    const-string v2, "InAppMessage EventListener threw an exception"

    .line 63
    .line 64
    const/4 v3, 0x0

    .line 65
    new-array v3, v3, [Ljava/lang/Object;

    .line 66
    .line 67
    invoke-static {v1, p0, v2, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :cond_0
    :goto_0
    monitor-exit v0

    .line 71
    return-void

    .line 72
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 73
    throw p0
.end method
