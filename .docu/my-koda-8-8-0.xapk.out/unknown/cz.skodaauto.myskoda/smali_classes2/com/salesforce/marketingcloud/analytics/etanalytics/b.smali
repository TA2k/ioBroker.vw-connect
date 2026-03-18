.class public Lcom/salesforce/marketingcloud/analytics/etanalytics/b;
.super Lcom/salesforce/marketingcloud/analytics/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final f:I


# instance fields
.field final d:Lcom/salesforce/marketingcloud/storage/h;

.field private final e:Lcom/salesforce/marketingcloud/internal/n;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/analytics/i;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    .line 7
    .line 8
    return-void
.end method

.method private static a(Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/storage/h;)V
    .locals 3

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p0

    new-instance v0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$a;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "delete_analytics"

    invoke-direct {v0, v2, v1, p1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$a;-><init>(Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/storage/h;)V

    invoke-interface {p0, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/messages/Region;Ljava/util/Date;)V
    .locals 5

    .line 18
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Region;->regionType()I

    move-result v0

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    const/16 v0, 0xb

    goto :goto_0

    :cond_0
    const/16 v0, 0xd

    .line 19
    :goto_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    new-instance v2, Lcom/salesforce/marketingcloud/analytics/a;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 20
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object v3

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    .line 21
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    const/4 v4, 0x0

    .line 22
    invoke-static {p2, v4, v0, p1, v4}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p1

    invoke-direct {v2, v3, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 23
    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;Z)V
    .locals 0

    if-eqz p2, :cond_0

    .line 1
    invoke-static {p1, p0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/storage/h;)V

    :cond_0
    return-void
.end method

.method private b(Lcom/salesforce/marketingcloud/messages/Region;Ljava/util/Date;)V
    .locals 7

    .line 10
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;

    const/4 v2, 0x0

    new-array v4, v2, [Ljava/lang/Object;

    const-string v3, "end_region_counter"

    move-object v2, p0

    move-object v5, p1

    move-object v6, p2

    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$e;-><init>(Lcom/salesforce/marketingcloud/analytics/etanalytics/b;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/Region;Ljava/util/Date;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method


# virtual methods
.method public a(J)V
    .locals 7

    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;

    const/4 v2, 0x0

    new-array v4, v2, [Ljava/lang/Object;

    const-string v3, "end_app_counter"

    move-object v2, p0

    move-wide v5, p1

    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$c;-><init>(Lcom/salesforce/marketingcloud/analytics/etanalytics/b;Ljava/lang/String;[Ljava/lang/Object;J)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/Region;)V
    .locals 7

    .line 10
    new-instance v0, Ljava/util/Date;

    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 11
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Lcom/salesforce/marketingcloud/messages/Region;Ljava/util/Date;)V

    .line 12
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Region;->regionType()I

    move-result v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_0

    const/4 v1, 0x6

    goto :goto_0

    :cond_0
    const/16 v1, 0xc

    .line 13
    :goto_0
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v3

    new-instance v4, Lcom/salesforce/marketingcloud/analytics/a;

    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object v5

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    .line 15
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    const/4 v6, 0x0

    .line 16
    invoke-static {v0, v6, v1, p1, v2}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p1

    invoke-direct {v4, v5, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 17
    invoke-interface {v3, v4}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 6

    .line 5
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    invoke-virtual {p0, v0, v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(J)V

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/analytics/a;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 7
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object v2

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    new-instance v3, Ljava/util/Date;

    invoke-direct {v3}, Ljava/util/Date;-><init>()V

    const/4 v4, 0x0

    const/4 v5, 0x5

    .line 8
    invoke-static {v3, v4, v5, p1, v4}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p1

    invoke-direct {v1, v2, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 9
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Z)V
    .locals 0

    if-eqz p1, :cond_0

    .line 3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-static {p1, p0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/storage/h;)V

    :cond_0
    return-void
.end method

.method public b(J)V
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$b;

    const/4 v2, 0x0

    new-array v4, v2, [Ljava/lang/Object;

    const-string v3, "start_app_counter"

    move-object v2, p0

    move-wide v5, p1

    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$b;-><init>(Lcom/salesforce/marketingcloud/analytics/etanalytics/b;Ljava/lang/String;[Ljava/lang/Object;J)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/messages/Region;)V
    .locals 7

    .line 2
    new-instance v0, Ljava/util/Date;

    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 3
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->b(Lcom/salesforce/marketingcloud/messages/Region;Ljava/util/Date;)V

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Region;->regionType()I

    move-result v1

    const/4 v2, 0x3

    if-ne v1, v2, :cond_0

    return-void

    .line 5
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    new-instance v2, Lcom/salesforce/marketingcloud/analytics/a;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 6
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object v3

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    .line 7
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    const/4 v4, 0x7

    const/4 v5, 0x1

    const/4 v6, 0x0

    .line 8
    invoke-static {v0, v6, v4, p1, v5}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p1

    invoke-direct {v2, v3, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 9
    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public c(J)V
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$d;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    new-array v4, v2, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string v3, "end_region_counter"

    .line 13
    .line 14
    move-object v2, p0

    .line 15
    move-wide v5, p1

    .line 16
    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b$d;-><init>(Lcom/salesforce/marketingcloud/analytics/etanalytics/b;Ljava/lang/String;[Ljava/lang/Object;J)V

    .line 17
    .line 18
    .line 19
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public trackInboxOpenEvent(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 9

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    new-array p1, p1, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string v0, "InboxMessage was null. Call to trackInboxOpenEvent() ignored."

    .line 9
    .line 10
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->e:Lcom/salesforce/marketingcloud/internal/n;

    .line 15
    .line 16
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/a;

    .line 21
    .line 22
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 23
    .line 24
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 29
    .line 30
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    new-instance v3, Ljava/util/Date;

    .line 35
    .line 36
    invoke-direct {v3}, Ljava/util/Date;-><init>()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    invoke-static {v4}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/d;->b(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    const/16 v5, 0xf

    .line 52
    .line 53
    const/4 v8, 0x1

    .line 54
    const/4 v4, 0x0

    .line 55
    invoke-static/range {v3 .. v8}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/analytics/b;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-direct {v1, v2, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 60
    .line 61
    .line 62
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 63
    .line 64
    .line 65
    return-void
.end method
