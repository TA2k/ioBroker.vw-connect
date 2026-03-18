.class Lcom/salesforce/marketingcloud/media/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field final b:Lcom/salesforce/marketingcloud/media/o;

.field final c:Lcom/salesforce/marketingcloud/media/d;

.field final d:Lcom/salesforce/marketingcloud/media/h;

.field private e:Ljava/lang/Exception;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/media/h;Lcom/salesforce/marketingcloud/media/d;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/media/d;->c()Lcom/salesforce/marketingcloud/media/o;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lcom/salesforce/marketingcloud/media/e;->b:Lcom/salesforce/marketingcloud/media/o;

    .line 9
    .line 10
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/e;->d:Lcom/salesforce/marketingcloud/media/h;

    .line 11
    .line 12
    iput-object p2, p0, Lcom/salesforce/marketingcloud/media/e;->c:Lcom/salesforce/marketingcloud/media/d;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public a()Ljava/lang/Exception;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/e;->e:Ljava/lang/Exception;

    .line 2
    .line 3
    return-object p0
.end method

.method public b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/e;->e:Ljava/lang/Exception;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public run()V
    .locals 4

    .line 1
    const-string v0, "CacheCleaner - Idle"

    .line 2
    .line 3
    :try_start_0
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const-string v2, "CacheCleaner - Cleaning"

    .line 8
    .line 9
    invoke-virtual {v1, v2}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/e;->c:Lcom/salesforce/marketingcloud/media/d;

    .line 13
    .line 14
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/media/d;->a()Lcom/salesforce/marketingcloud/media/s;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/e;->c:Lcom/salesforce/marketingcloud/media/d;

    .line 19
    .line 20
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/media/d;->d()Ljava/util/Collection;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    check-cast v3, Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v1, v3}, Lcom/salesforce/marketingcloud/media/s;->b(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    goto :goto_3

    .line 46
    :catch_0
    move-exception v1

    .line 47
    goto :goto_1

    .line 48
    :cond_0
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/media/s;->a()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    .line 50
    .line 51
    goto :goto_2

    .line 52
    :goto_1
    :try_start_1
    iput-object v1, p0, Lcom/salesforce/marketingcloud/media/e;->e:Ljava/lang/Exception;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 53
    .line 54
    :goto_2
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-virtual {v1, v0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/e;->d:Lcom/salesforce/marketingcloud/media/h;

    .line 62
    .line 63
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/media/h;->a(Lcom/salesforce/marketingcloud/media/e;)V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :goto_3
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    invoke-virtual {v1, v0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw p0
.end method
