.class public Lcom/salesforce/marketingcloud/analytics/etanalytics/a;
.super Lcom/salesforce/marketingcloud/analytics/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final f:I


# instance fields
.field private final d:Lcom/salesforce/marketingcloud/storage/h;

.field private final e:Lcom/salesforce/marketingcloud/internal/n;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/analytics/i;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->e:Lcom/salesforce/marketingcloud/internal/n;

    .line 7
    .line 8
    return-void
.end method

.method private static a(Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/storage/h;)V
    .locals 3

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p0

    new-instance v0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a$a;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "delete_analytics"

    invoke-direct {v0, v2, v1, p1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a$a;-><init>(Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/storage/h;)V

    invoke-interface {p0, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;Z)V
    .locals 0

    if-eqz p2, :cond_0

    .line 1
    invoke-static {p1, p0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->a(Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/storage/h;)V

    :cond_0
    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 9

    .line 15
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/analytics/a;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object v2

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    new-instance v3, Ljava/util/Date;

    invoke-direct {v3}, Ljava/util/Date;-><init>()V

    .line 17
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id()Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v6

    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/d;->b(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)Ljava/lang/String;

    move-result-object v7

    const/16 v5, 0xe

    const/4 v8, 0x1

    const/4 v4, 0x0

    .line 18
    invoke-static/range {v3 .. v8}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p1

    invoke-direct {v1, v2, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 19
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)V
    .locals 7

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region()Lcom/salesforce/marketingcloud/messages/Region;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 5
    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 6
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v4, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 7
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region()Lcom/salesforce/marketingcloud/messages/Region;

    move-result-object v0

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v4, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 8
    new-instance v1, Ljava/util/Date;

    invoke-direct {v1}, Ljava/util/Date;-><init>()V

    .line 9
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId()Ljava/lang/String;

    move-result-object v5

    const/16 v3, 0x11

    const/4 v6, 0x1

    const/4 v2, 0x0

    .line 10
    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p1

    .line 11
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/analytics/b;->b(I)V

    .line 12
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p2

    new-instance v0, Lcom/salesforce/marketingcloud/analytics/a;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 13
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object v1

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    invoke-direct {v0, v1, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 14
    invoke-interface {p2, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    :cond_0
    return-void
.end method

.method public a(Z)V
    .locals 0

    if-eqz p1, :cond_0

    .line 3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->e:Lcom/salesforce/marketingcloud/internal/n;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-static {p1, p0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->a(Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/storage/h;)V

    :cond_0
    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region()Lcom/salesforce/marketingcloud/messages/Region;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    new-instance v2, Ljava/util/Date;

    .line 18
    .line 19
    invoke-direct {v2}, Ljava/util/Date;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    filled-new-array {v1, v0}, [Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    const/4 v4, 0x3

    .line 43
    const/4 v7, 0x1

    .line 44
    const/4 v3, 0x0

    .line 45
    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/analytics/b;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->e:Lcom/salesforce/marketingcloud/internal/n;

    .line 50
    .line 51
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/a;

    .line 56
    .line 57
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 58
    .line 59
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 64
    .line 65
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-direct {v1, v2, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 70
    .line 71
    .line 72
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 73
    .line 74
    .line 75
    :cond_0
    return-void
.end method
