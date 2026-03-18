.class Lcom/salesforce/marketingcloud/messages/inbox/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;


# static fields
.field private static final p:Ljava/lang/String; = "inbox_watermark_key"


# instance fields
.field final d:Lcom/salesforce/marketingcloud/storage/h;

.field final e:Lcom/salesforce/marketingcloud/analytics/g;

.field final f:Lcom/salesforce/marketingcloud/http/e;

.field final g:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field final h:Ljava/lang/String;

.field private final i:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;",
            ">;"
        }
    .end annotation
.end field

.field private final j:Lcom/salesforce/marketingcloud/alarms/b;

.field private final k:Lcom/salesforce/marketingcloud/internal/n;

.field private final l:Ljava/lang/Object;

.field private final m:Ljava/lang/Object;

.field private n:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;

.field private o:Z


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/analytics/g;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroidx/collection/g;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->i:Ljava/util/Set;

    .line 11
    .line 12
    new-instance v0, Ljava/lang/Object;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->l:Ljava/lang/Object;

    .line 18
    .line 19
    new-instance v0, Ljava/lang/Object;

    .line 20
    .line 21
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->m:Ljava/lang/Object;

    .line 25
    .line 26
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->g:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 27
    .line 28
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 29
    .line 30
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->h:Ljava/lang/String;

    .line 31
    .line 32
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 33
    .line 34
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->f:Lcom/salesforce/marketingcloud/http/e;

    .line 35
    .line 36
    iput-object p6, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->e:Lcom/salesforce/marketingcloud/analytics/g;

    .line 37
    .line 38
    iput-object p7, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    .line 39
    .line 40
    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;Z)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->g:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    if-eqz p3, :cond_0

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    move-result-object p0

    .line 3
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p1

    new-instance p2, Lcom/salesforce/marketingcloud/messages/inbox/c$d;

    const/4 p3, 0x0

    new-array p3, p3, [Ljava/lang/Object;

    const-string v0, "inbox_shutdown"

    invoke-direct {p2, v0, p3, p0}, Lcom/salesforce/marketingcloud/messages/inbox/c$d;-><init>(Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/storage/f;)V

    invoke-interface {p1, p2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    :cond_0
    return-void
.end method

.method private a(Z)V
    .locals 4

    .line 45
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$b;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "fetch_inbox_messages"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c$b;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Z)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    const/4 v0, 0x0

    .line 4
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->o:Z

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->e()V

    return-void
.end method

.method public a(ILjava/lang/String;)V
    .locals 1

    .line 30
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Request failed: %d - %s"

    invoke-static {v0, p2, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 31
    new-instance p1, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object p2

    invoke-direct {p1, p2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    new-instance p2, Lcom/salesforce/marketingcloud/messages/inbox/c$k;

    invoke-direct {p2, p0}, Lcom/salesforce/marketingcloud/messages/inbox/c$k;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;)V

    invoke-virtual {p1, p2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;)V
    .locals 4

    .line 41
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 42
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->g:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v1

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/alarms/b;->c([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 43
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object p1

    .line 44
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$a;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "inbox_status_updated"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c$a;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    :cond_0
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/f;)V
    .locals 9

    const/4 v0, 0x0

    .line 12
    :try_start_0
    new-instance v1, Lorg/json/JSONObject;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/f;->j()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v1, p1}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 13
    const-string p1, "messages"

    invoke-virtual {v1, p1}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object p1

    .line 14
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    if-eqz p1, :cond_0

    .line 15
    invoke-virtual {p1}, Lorg/json/JSONArray;->length()I

    move-result v3

    if-lez v3, :cond_0

    .line 16
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    move v4, v0

    :goto_0
    if-ge v4, v3, :cond_0

    .line 17
    :try_start_1
    invoke-virtual {p1, v4}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    move-result-object v5

    .line 18
    new-instance v6, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    const-string v7, "isDeleted"

    invoke-virtual {v5, v7}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;)Z

    move-result v7

    invoke-direct {v6, v5, v7}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;-><init>(Lorg/json/JSONObject;Z)V

    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_1

    :catch_0
    move-exception v5

    .line 19
    :try_start_2
    sget-object v6, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const-string v7, "Failed to parse inbox message"

    new-array v8, v0, [Ljava/lang/Object;

    invoke-static {v6, v5, v7, v8}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_1
    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :catch_1
    move-exception p1

    goto :goto_2

    .line 20
    :cond_0
    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/messages/inbox/c;->b(Ljava/util/List;)V

    .line 21
    const-string p1, "waterMark"

    invoke-virtual {v1, p1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Ljava/lang/String;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    goto :goto_3

    .line 22
    :goto_2
    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v2, "Failed to parse inbox messages response"

    invoke-static {v1, p1, v2, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p1, -0x1

    .line 23
    const-string v0, "Failed to parse response"

    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(ILjava/lang/String;)V

    :goto_3
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 5

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$e;

    const/4 v2, 0x0

    new-array v3, v2, [Ljava/lang/Object;

    const-string v4, "inbox_push_received"

    invoke-direct {v1, p0, v4, v3, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c$e;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 7
    iget-boolean p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->o:Z

    if-eqz p1, :cond_0

    .line 8
    invoke-direct {p0, v2}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Z)V

    :cond_0
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 4

    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->g:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 10
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object p1

    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$f;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "inbox_notification_opened"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c$f;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    :cond_0
    return-void
.end method

.method public a(Ljava/lang/String;)V
    .locals 2

    .line 24
    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/j;->f(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 25
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "Could not convert watermark to a date"

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 26
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->l:Ljava/lang/Object;

    monitor-enter v0

    .line 27
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    const-string v1, "inbox_watermark_key"

    invoke-interface {p0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 28
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    .line 29
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public a(Ljava/util/List;)V
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;)V"
        }
    .end annotation

    .line 32
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->i:Ljava/util/Set;

    monitor-enter v0

    .line 33
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->i:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    .line 34
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->i:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_0

    .line 35
    :try_start_1
    invoke-interface {v1, p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;->onInboxMessagesChanged(Ljava/util/List;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :catch_0
    move-exception v2

    .line 36
    :try_start_2
    sget-object v3, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const-string v4, "%s threw an exception while processing the inbox messages response"

    .line 37
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    .line 38
    invoke-static {v3, v2, v4, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 39
    :cond_1
    monitor-exit v0

    return-void

    .line 40
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method public b()V
    .locals 1

    const/4 v0, 0x1

    .line 1
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->o:Z

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Z)V

    return-void
.end method

.method public b(ILjava/lang/String;)V
    .locals 1

    .line 11
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Request failed: %d - %s"

    invoke-static {v0, p2, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->g:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    return-void
.end method

.method public b(Ljava/util/List;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;)V"
        }
    .end annotation

    .line 10
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$l;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "inbox_updated"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c$l;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Ljava/util/List;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public b(Z)V
    .locals 4

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->m:Ljava/lang/Object;

    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->n:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_0

    .line 5
    :try_start_1
    invoke-interface {v1, p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;->onRefreshComplete(Z)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :catch_0
    move-exception p1

    .line 6
    :try_start_2
    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const-string v2, "InboxRefreshListener threw an exception"

    const/4 v3, 0x0

    new-array v3, v3, [Ljava/lang/Object;

    invoke-static {v1, p1, v2, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_0
    const/4 p1, 0x0

    .line 7
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->n:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;

    .line 8
    :cond_0
    monitor-exit v0

    return-void

    .line 9
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method public c()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    const-string v1, "inbox_messages"

    .line 7
    .line 8
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 9
    .line 10
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 15
    .line 16
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-interface {v2, p0}, Lcom/salesforce/marketingcloud/storage/f;->m(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 25
    .line 26
    .line 27
    return-object v0

    .line 28
    :catch_0
    move-exception p0

    .line 29
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    new-array v1, v1, [Ljava/lang/Object;

    .line 33
    .line 34
    const-string v2, "Failed to create our component state JSONObject."

    .line 35
    .line 36
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    const/4 p0, 0x0

    .line 40
    return-object p0
.end method

.method public d()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->l:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const-string v1, "inbox_watermark_key"

    .line 11
    .line 12
    new-instance v2, Ljava/util/Date;

    .line 13
    .line 14
    const-wide/16 v3, 0x0

    .line 15
    .line 16
    invoke-direct {v2, v3, v4}, Ljava/util/Date;-><init>(J)V

    .line 17
    .line 18
    .line 19
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-interface {p0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    monitor-exit v0

    .line 28
    return-object p0

    .line 29
    :catchall_0
    move-exception p0

    .line 30
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    throw p0
.end method

.method public deleteMessage(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 1

    if-nez p1, :cond_0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "InboxMessage was null and could not be updated.  Call to deleteMessage() ignored."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    :cond_0
    const/4 v0, 0x1

    .line 2
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/internal/d;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V

    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->deleteMessage(Ljava/lang/String;)V

    return-void
.end method

.method public deleteMessage(Ljava/lang/String;)V
    .locals 4

    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$g;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "inbox_delete"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c$g;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public disableInbox()V
    .locals 0

    .line 1
    return-void
.end method

.method public e()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$c;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    new-array v2, v2, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string v3, "send_inbox_message_status"

    .line 13
    .line 14
    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/messages/inbox/c$c;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public enableInbox()V
    .locals 0

    .line 1
    return-void
.end method

.method public getDeletedMessageCount()I
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->d:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 8
    .line 9
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/storage/f$a;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public getDeletedMessages()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object v1, Lcom/salesforce/marketingcloud/storage/f$a;->d:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 14
    .line 15
    invoke-interface {v0, p0, v1}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/storage/f$a;)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public getMessageCount()I
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->e:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 8
    .line 9
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/storage/f$a;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public getMessages()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object v1, Lcom/salesforce/marketingcloud/storage/f$a;->e:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 14
    .line 15
    invoke-interface {v0, p0, v1}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/storage/f$a;)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public getReadMessageCount()I
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->c:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 8
    .line 9
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/storage/f$a;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public getReadMessages()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object v1, Lcom/salesforce/marketingcloud/storage/f$a;->c:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 14
    .line 15
    invoke-interface {v0, p0, v1}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/storage/f$a;)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public getUnreadMessageCount()I
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object v0, Lcom/salesforce/marketingcloud/storage/f$a;->b:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 8
    .line 9
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/storage/f$a;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public getUnreadMessages()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object v1, Lcom/salesforce/marketingcloud/storage/f$a;->b:Lcom/salesforce/marketingcloud/storage/f$a;

    .line 14
    .line 15
    invoke-interface {v0, p0, v1}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/storage/f$a;)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public isInboxEnabled()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public markAllMessagesDeleted()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$j;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    new-array v2, v2, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string v3, "delete_all"

    .line 13
    .line 14
    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/messages/inbox/c$j;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public markAllMessagesRead()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$i;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    new-array v2, v2, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string v3, "mark_all_read"

    .line 13
    .line 14
    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/messages/inbox/c$i;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public refreshInbox(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->m:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->n:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 10
    .line 11
    const-string v1, "Refresh already in progress."

    .line 12
    .line 13
    new-array v3, v2, [Ljava/lang/Object;

    .line 14
    .line 15
    invoke-static {p0, v1, v3}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    .line 17
    .line 18
    :try_start_1
    invoke-interface {p1, v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;->onRefreshComplete(Z)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_1

    .line 24
    :catch_0
    move-exception p0

    .line 25
    :try_start_2
    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 26
    .line 27
    const-string v2, "Error delivering Refresh Complete result to %s"

    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-static {v1, p0, v2, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    :goto_0
    monitor-exit v0

    .line 45
    return-void

    .line 46
    :cond_0
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->n:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;

    .line 47
    .line 48
    sget-object p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 49
    .line 50
    const-string v1, "Refreshing inbox messages"

    .line 51
    .line 52
    new-array v2, v2, [Ljava/lang/Object;

    .line 53
    .line 54
    invoke-static {p1, v1, v2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    const/4 p1, 0x1

    .line 58
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Z)V

    .line 59
    .line 60
    .line 61
    monitor-exit v0

    .line 62
    return-void

    .line 63
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 64
    throw p0
.end method

.method public registerInboxResponseListener(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->i:Ljava/util/Set;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->i:Ljava/util/Set;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    monitor-exit v0

    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0

    .line 16
    :cond_0
    return-void
.end method

.method public setMessageRead(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 1

    if-nez p1, :cond_0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "InboxMessage was null and could not be updated.  Call to setMessageRead() ignored."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    :cond_0
    const/4 v0, 0x1

    .line 2
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/internal/d;->c(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V

    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->setMessageRead(Ljava/lang/String;)V

    return-void
.end method

.method public setMessageRead(Ljava/lang/String;)V
    .locals 4

    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->k:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$h;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "mark_read"

    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c$h;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public unregisterInboxResponseListener(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->i:Ljava/util/Set;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->i:Ljava/util/Set;

    .line 5
    .line 6
    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method
