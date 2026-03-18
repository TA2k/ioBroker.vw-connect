.class public Lcom/salesforce/marketingcloud/messages/push/a;
.super Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/e;
.implements Lcom/salesforce/marketingcloud/alarms/b$b;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/push/a$b;
    }
.end annotation


# static fields
.field private static final A:Ljava/lang/String; = "content-available"

.field private static final B:Ljava/lang/String; = "_c"

.field private static final C:Ljava/lang/String; = "_p"

.field private static final D:J

.field static final y:Ljava/lang/String; = "et_push_enabled"

.field private static final z:Ljava/lang/String; = "last_push_token_refresh"


# instance fields
.field private final j:Landroid/content/Context;

.field private final k:Lcom/salesforce/marketingcloud/notifications/a;

.field private final l:Lcom/salesforce/marketingcloud/alarms/b;

.field private final m:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$SilentPushListener;",
            ">;"
        }
    .end annotation
.end field

.field private final n:Lcom/salesforce/marketingcloud/storage/h;

.field private final o:Ljava/lang/String;

.field private final p:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$PushTokenRefreshListener;",
            ">;"
        }
    .end annotation
.end field

.field private final q:Lcom/salesforce/marketingcloud/analytics/j;

.field private final r:Lcom/salesforce/marketingcloud/internal/n;

.field private final s:Lcom/salesforce/marketingcloud/push/i;

.field t:Lcom/salesforce/marketingcloud/push/h;

.field private u:Lcom/salesforce/marketingcloud/media/o;

.field private v:I

.field private w:Landroid/content/BroadcastReceiver;

.field private x:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->HOURS:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    const-wide/16 v1, 0x30

    .line 4
    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    sput-wide v0, Lcom/salesforce/marketingcloud/messages/push/a;->D:J

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/notifications/a;Lcom/salesforce/marketingcloud/alarms/b;Ljava/lang/String;Lcom/salesforce/marketingcloud/analytics/j;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/salesforce/marketingcloud/push/i;->a:Lcom/salesforce/marketingcloud/push/i;

    .line 5
    .line 6
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->s:Lcom/salesforce/marketingcloud/push/i;

    .line 7
    .line 8
    const-string v1, "Content is null"

    .line 9
    .line 10
    invoke-static {p1, v1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Landroid/content/Context;

    .line 15
    .line 16
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    .line 17
    .line 18
    const-string p1, "Storage is null"

    .line 19
    .line 20
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, Lcom/salesforce/marketingcloud/storage/h;

    .line 25
    .line 26
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    .line 27
    .line 28
    const-string p1, "NotificationManager is null"

    .line 29
    .line 30
    invoke-static {p3, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    check-cast p1, Lcom/salesforce/marketingcloud/notifications/a;

    .line 35
    .line 36
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->k:Lcom/salesforce/marketingcloud/notifications/a;

    .line 37
    .line 38
    const-string p1, "AlarmScheduler is null"

    .line 39
    .line 40
    invoke-static {p4, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    check-cast p1, Lcom/salesforce/marketingcloud/alarms/b;

    .line 45
    .line 46
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->l:Lcom/salesforce/marketingcloud/alarms/b;

    .line 47
    .line 48
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/push/a;->o:Ljava/lang/String;

    .line 49
    .line 50
    iput-object p6, p0, Lcom/salesforce/marketingcloud/messages/push/a;->q:Lcom/salesforce/marketingcloud/analytics/j;

    .line 51
    .line 52
    iput-object p7, p0, Lcom/salesforce/marketingcloud/messages/push/a;->u:Lcom/salesforce/marketingcloud/media/o;

    .line 53
    .line 54
    iput-object p8, p0, Lcom/salesforce/marketingcloud/messages/push/a;->r:Lcom/salesforce/marketingcloud/internal/n;

    .line 55
    .line 56
    new-instance p1, Landroidx/collection/g;

    .line 57
    .line 58
    const/4 p2, 0x0

    .line 59
    invoke-direct {p1, p2}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->m:Ljava/util/Set;

    .line 63
    .line 64
    new-instance p1, Landroidx/collection/g;

    .line 65
    .line 66
    invoke-direct {p1, p2}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

    .line 70
    .line 71
    invoke-virtual {v0, p7}, Lcom/salesforce/marketingcloud/push/i;->a(Lcom/salesforce/marketingcloud/media/o;)V

    .line 72
    .line 73
    .line 74
    new-instance p1, Lcom/salesforce/marketingcloud/push/h;

    .line 75
    .line 76
    invoke-direct {p1, p7}, Lcom/salesforce/marketingcloud/push/h;-><init>(Lcom/salesforce/marketingcloud/media/o;)V

    .line 77
    .line 78
    .line 79
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->t:Lcom/salesforce/marketingcloud/push/h;

    .line 80
    .line 81
    return-void
.end method

.method public static bridge synthetic a(Lcom/salesforce/marketingcloud/messages/push/a;)Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    return-object p0
.end method

.method private a()V
    .locals 3

    .line 36
    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 37
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->x:Z

    const-string v2, "com.salesforce.marketingcloud.notifications.PUSH_ENABLED"

    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 38
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->o:Lcom/salesforce/marketingcloud/behaviors/a;

    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    return-void
.end method

.method public static a(Landroid/content/Context;ZLjava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 2
    new-instance v0, Landroid/content/Intent;

    const-string v1, "com.salesforce.marketingcloud.messages.push.TOKEN_REFRESHED"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 3
    const-string v1, "com.salesforce.marketingcloud.push.TOKEN_REFRESH_SUCCESSFUL"

    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    move-result-object p1

    .line 4
    const-string v0, "com.salesforce.marketingcloud.push.TOKEN_SENDER_ID"

    invoke-virtual {p1, v0, p2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    .line 5
    const-string p2, "com.salesforce.marketingcloud.push.TOKEN"

    invoke-virtual {p1, p2, p3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    .line 6
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    return-void
.end method

.method private a(Ljava/lang/String;)V
    .locals 5

    .line 28
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

    monitor-enter v0

    .line 29
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$PushTokenRefreshListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_0

    .line 30
    :try_start_1
    invoke-interface {v1, p1}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$PushTokenRefreshListener;->onTokenRefreshed(Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :catch_0
    move-exception v2

    .line 31
    :try_start_2
    sget-object v3, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    const-string v4, "%s threw an exception while processing the token refresh"

    .line 32
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    .line 33
    invoke-static {v3, v2, v4, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 34
    :cond_1
    monitor-exit v0

    return-void

    .line 35
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method public static a(Ljava/util/Map;)Z
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)Z"
        }
    .end annotation

    .line 7
    const-string v0, "_m"

    invoke-interface {p0, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    const-string v0, "_mt"

    invoke-interface {p0, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    .line 8
    :cond_0
    const-string v0, "messageDateUtc"

    invoke-interface {p0, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result p0

    if-nez p0, :cond_1

    .line 9
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    new-array v0, v1, [Ljava/lang/Object;

    const-string v1, "Optional key is missing for Delivery Receipt"

    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_1
    const/4 p0, 0x1

    return p0

    .line 10
    :cond_2
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    new-array v0, v1, [Ljava/lang/Object;

    const-string v2, "Mandatory keys are missing, Delivery Receipt Event cannot be processed"

    invoke-static {p0, v2, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1
.end method

.method private static b(Ljava/util/Map;)Landroid/os/Bundle;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)",
            "Landroid/os/Bundle;"
        }
    .end annotation

    .line 2
    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 3
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_0

    .line 4
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map$Entry;

    .line 5
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    return-object v0
.end method

.method public static bridge synthetic b(Lcom/salesforce/marketingcloud/messages/push/a;)Lcom/salesforce/marketingcloud/notifications/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->k:Lcom/salesforce/marketingcloud/notifications/a;

    return-object p0
.end method

.method private b()V
    .locals 5

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->getPushDebugInfo()Lorg/json/JSONObject;

    move-result-object p0

    const-string v0, "messagingService"

    invoke-virtual {p0, v0}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object p0

    if-eqz p0, :cond_1

    .line 7
    invoke-virtual {p0}, Lorg/json/JSONArray;->length()I

    move-result v0

    const/4 v1, 0x2

    if-le v0, v1, :cond_1

    .line 8
    sget-object v0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Object;

    const-string v3, "Possible Multiple Push Provider implementation issue detected in your application. This may lead to the malfunctioning of the Push SDK."

    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    move v0, v1

    .line 9
    :goto_0
    invoke-virtual {p0}, Lorg/json/JSONArray;->length()I

    move-result v2

    if-ge v0, v2, :cond_1

    .line 10
    invoke-virtual {p0, v0}, Lorg/json/JSONArray;->optJSONObject(I)Lorg/json/JSONObject;

    move-result-object v2

    .line 11
    const-string v3, "priority"

    invoke-virtual {v2, v3}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;)I

    move-result v3

    .line 12
    const-string v4, "name"

    invoke-virtual {v2, v4}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    const/4 v4, -0x1

    if-le v3, v4, :cond_0

    .line 13
    sget-object v3, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    const-string v4, " is having higher priority than the Push SDK"

    .line 14
    invoke-static {v2, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    .line 15
    new-array v4, v1, [Ljava/lang/Object;

    invoke-static {v3, v2, v4}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method private b(Ljava/lang/String;)V
    .locals 2

    .line 21
    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 22
    const-string v1, "com.salesforce.marketingcloud.push.TOKEN"

    invoke-virtual {v0, v1, p1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 23
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    sget-object p1, Lcom/salesforce/marketingcloud/behaviors/a;->q:Lcom/salesforce/marketingcloud/behaviors/a;

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    return-void
.end method

.method public static bridge synthetic c(Lcom/salesforce/marketingcloud/messages/push/a;)Lcom/salesforce/marketingcloud/analytics/j;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->q:Lcom/salesforce/marketingcloud/analytics/j;

    return-object p0
.end method

.method private c()V
    .locals 3

    .line 2
    new-instance v0, Lcom/salesforce/marketingcloud/messages/push/a$b;

    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/messages/push/a$b;-><init>(Lcom/salesforce/marketingcloud/messages/push/a;)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->w:Landroid/content/BroadcastReceiver;

    .line 3
    new-instance v0, Landroid/content/IntentFilter;

    invoke-direct {v0}, Landroid/content/IntentFilter;-><init>()V

    .line 4
    const-string v1, "com.salesforce.marketingcloud.messages.push.TOKEN_REFRESHED"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->w:Landroid/content/BroadcastReceiver;

    const/4 v2, 0x4

    invoke-static {v1, p0, v0, v2}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    return-void
.end method

.method private c(Ljava/util/Map;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 6
    const-string v0, "content-available"

    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_0

    .line 7
    :try_start_0
    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v1

    .line 8
    sget-object v2, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v3, "Unable to parse content available flag: %s"

    invoke-static {v2, v1, v3, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    const/4 v0, 0x0

    :goto_0
    const/4 v1, 0x1

    if-ne v0, v1, :cond_1

    .line 9
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/push/a;->e(Ljava/util/Map;)V

    :cond_1
    return-void
.end method

.method private d()V
    .locals 2

    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    if-eqz v0, :cond_0

    .line 6
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->x:Z

    const-string v1, "et_push_enabled"

    invoke-interface {v0, v1, p0}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    :cond_0
    return-void
.end method

.method public static bridge synthetic d(Lcom/salesforce/marketingcloud/messages/push/a;Ljava/util/Map;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/push/a;->c(Ljava/util/Map;)V

    return-void
.end method

.method private d(Ljava/util/Map;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 2
    const-string v0, "_c"

    invoke-interface {p1, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 3
    const-string v0, "_p"

    invoke-interface {p1, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/push/a;->e(Ljava/util/Map;)V

    return-void
.end method

.method public static bridge synthetic e(Lcom/salesforce/marketingcloud/messages/push/a;Ljava/util/Map;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/push/a;->d(Ljava/util/Map;)V

    return-void
.end method

.method private e(Ljava/util/Map;)V
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->m:Ljava/util/Set;

    monitor-enter v0

    .line 3
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->m:Ljava/util/Set;

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$SilentPushListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_0

    .line 4
    :try_start_1
    invoke-interface {v1, p1}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$SilentPushListener;->silentPushReceived(Ljava/util/Map;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :catch_0
    move-exception v2

    .line 5
    :try_start_2
    sget-object v3, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    const-string v4, "%s threw an exception while processing the silent push message"

    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    .line 7
    invoke-static {v3, v2, v4, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 8
    :cond_1
    monitor-exit v0

    return-void

    .line 9
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method private f(Ljava/util/Map;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/push/a;->g(Ljava/util/Map;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->r:Lcom/salesforce/marketingcloud/internal/n;

    .line 11
    .line 12
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->a()Ljava/util/concurrent/ExecutorService;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    new-instance v1, Lcom/salesforce/marketingcloud/messages/push/a$a;

    .line 17
    .line 18
    invoke-direct {v1, p0, p1}, Lcom/salesforce/marketingcloud/messages/push/a$a;-><init>(Lcom/salesforce/marketingcloud/messages/push/a;Ljava/util/Map;)V

    .line 19
    .line 20
    .line 21
    invoke-interface {v0, v1}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 22
    .line 23
    .line 24
    :cond_1
    :goto_0
    return-void
.end method

.method private g(Ljava/util/Map;)Z
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)Z"
        }
    .end annotation

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->v:I

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 13
    .line 14
    new-array p1, v2, [Ljava/lang/Object;

    .line 15
    .line 16
    const-string v0, "Blocking push message.  Received a push message when the push feature is blocked."

    .line 17
    .line 18
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return v1

    .line 22
    :cond_0
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->v:I

    .line 23
    .line 24
    const/16 v0, 0x80

    .line 25
    .line 26
    invoke-static {p0, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eqz p0, :cond_1

    .line 31
    .line 32
    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/inbox/a;->a(Ljava/util/Map;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_1

    .line 37
    .line 38
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 39
    .line 40
    new-array p1, v2, [Ljava/lang/Object;

    .line 41
    .line 42
    const-string v0, "Blocking push message.  Received an inbox message when the inbox feature is blocked."

    .line 43
    .line 44
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return v1

    .line 48
    :cond_1
    return v2
.end method

.method public static bridge synthetic h(Ljava/util/Map;)Landroid/os/Bundle;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->b(Ljava/util/Map;)Landroid/os/Bundle;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public a(Landroid/os/Bundle;)V
    .locals 5

    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object v0

    .line 12
    const-string v1, "com.salesforce.marketingcloud.push.TOKEN_REFRESH_SUCCESSFUL"

    const/4 v2, 0x0

    invoke-virtual {p1, v1, v2}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    move-result v1

    const-string v2, "sender_id"

    if-eqz v1, :cond_0

    .line 13
    const-string v1, "com.salesforce.marketingcloud.push.TOKEN"

    const-string v3, ""

    invoke-virtual {p1, v1, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 14
    const-string v4, "gcm_reg_id_key"

    invoke-interface {v0, v4, v1}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 15
    const-string v4, "com.salesforce.marketingcloud.push.TOKEN_SENDER_ID"

    invoke-virtual {p1, v4, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 16
    invoke-interface {v0, v2, p1}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 17
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/messages/push/a;->b(Ljava/lang/String;)V

    .line 18
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->l:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->f:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 19
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p1

    .line 20
    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    .line 21
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v2

    const-string v0, "last_push_token_refresh"

    invoke-interface {p1, v0, v2, v3}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    .line 22
    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 23
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/messages/push/a;->a(Ljava/lang/String;)V

    return-void

    .line 24
    :cond_0
    invoke-interface {v0, v2}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;)V

    .line 25
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->l:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->f:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 1

    .line 26
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->f:Lcom/salesforce/marketingcloud/alarms/a$a;

    if-ne p1, v0, :cond_0

    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->o:Ljava/lang/String;

    if-eqz p1, :cond_0

    .line 27
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/MCService;->b(Landroid/content/Context;Ljava/lang/String;)V

    :cond_0
    return-void
.end method

.method public componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "PushMessageManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 5

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    const-string v1, "pushEnabled"

    .line 7
    .line 8
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/messages/push/a;->x:Z

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    const-string v1, "pushPermissionsAllowed"

    .line 14
    .line 15
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    .line 16
    .line 17
    new-instance v3, Landroidx/core/app/h0;

    .line 18
    .line 19
    invoke-direct {v3, v2}, Landroidx/core/app/h0;-><init>(Landroid/content/Context;)V

    .line 20
    .line 21
    .line 22
    iget-object v2, v3, Landroidx/core/app/h0;->a:Landroid/app/NotificationManager;

    .line 23
    .line 24
    invoke-virtual {v2}, Landroid/app/NotificationManager;->areNotificationsEnabled()Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 29
    .line 30
    .line 31
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

    .line 32
    .line 33
    monitor-enter v1
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 34
    :try_start_1
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

    .line 35
    .line 36
    invoke-interface {v2}, Ljava/util/Set;->isEmpty()Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-nez v2, :cond_2

    .line 41
    .line 42
    new-instance v2, Lorg/json/JSONArray;

    .line 43
    .line 44
    invoke-direct {v2}, Lorg/json/JSONArray;-><init>()V

    .line 45
    .line 46
    .line 47
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

    .line 48
    .line 49
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    :cond_0
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    if-eqz v4, :cond_1

    .line 58
    .line 59
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    check-cast v4, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$PushTokenRefreshListener;

    .line 64
    .line 65
    if-eqz v4, :cond_0

    .line 66
    .line 67
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    invoke-virtual {v2, v4}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :catchall_0
    move-exception v2

    .line 80
    goto :goto_1

    .line 81
    :cond_1
    const-string v3, "tokenRefreshListeners"

    .line 82
    .line 83
    invoke-virtual {v0, v3, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 84
    .line 85
    .line 86
    :cond_2
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 87
    :try_start_2
    const-string v1, "debugInfo"

    .line 88
    .line 89
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->getPushDebugInfo()Lorg/json/JSONObject;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_2
    .catch Lorg/json/JSONException; {:try_start_2 .. :try_end_2} :catch_0

    .line 94
    .line 95
    .line 96
    return-object v0

    .line 97
    :catch_0
    move-exception v1

    .line 98
    goto :goto_2

    .line 99
    :goto_1
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 100
    :try_start_4
    throw v2
    :try_end_4
    .catch Lorg/json/JSONException; {:try_start_4 .. :try_end_4} :catch_0

    .line 101
    :goto_2
    sget-object v2, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 102
    .line 103
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->componentName()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    const-string v3, "Unable to create component state for $s"

    .line 112
    .line 113
    invoke-static {v2, v1, v3, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    return-object v0
.end method

.method public controlChannelInit(I)V
    .locals 4

    .line 1
    const/4 v0, 0x4

    .line 2
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    if-eqz v1, :cond_2

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->disablePush()V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->w:Landroid/content/BroadcastReceiver;

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    .line 16
    .line 17
    invoke-virtual {v2, v1}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->l:Lcom/salesforce/marketingcloud/alarms/b;

    .line 21
    .line 22
    sget-object v2, Lcom/salesforce/marketingcloud/alarms/a$a;->f:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 23
    .line 24
    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-virtual {v1, v3}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 29
    .line 30
    .line 31
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->l:Lcom/salesforce/marketingcloud/alarms/b;

    .line 32
    .line 33
    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 38
    .line 39
    .line 40
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_1

    .line 45
    .line 46
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    .line 47
    .line 48
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    const-string v1, "sender_id"

    .line 53
    .line 54
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string v1, "gcm_reg_id_key"

    .line 58
    .line 59
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    :cond_1
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->v:I

    .line 63
    .line 64
    return-void

    .line 65
    :cond_2
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->v:I

    .line 66
    .line 67
    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_3

    .line 72
    .line 73
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->v:I

    .line 74
    .line 75
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->c()V

    .line 76
    .line 77
    .line 78
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->l:Lcom/salesforce/marketingcloud/alarms/b;

    .line 79
    .line 80
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->f:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 81
    .line 82
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    invoke-virtual {p1, p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->enablePush()V

    .line 90
    .line 91
    .line 92
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->o:Ljava/lang/String;

    .line 93
    .line 94
    if-eqz p1, :cond_3

    .line 95
    .line 96
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    .line 97
    .line 98
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/MCService;->b(Landroid/content/Context;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    :cond_3
    return-void
.end method

.method public declared-synchronized disablePush()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->x:Z

    .line 3
    .line 4
    if-eqz v0, :cond_1

    .line 5
    .line 6
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->v:I

    .line 7
    .line 8
    const/4 v1, 0x4

    .line 9
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v0, 0x0

    .line 17
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->x:Z

    .line 18
    .line 19
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->a()V

    .line 20
    .line 21
    .line 22
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->d()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    .line 25
    monitor-exit p0

    .line 26
    return-void

    .line 27
    :catchall_0
    move-exception v0

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    :goto_0
    monitor-exit p0

    .line 30
    return-void

    .line 31
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 32
    throw v0
.end method

.method public declared-synchronized enablePush()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->v:I

    .line 3
    .line 4
    const/4 v1, 0x4

    .line 5
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 6
    .line 7
    .line 8
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    monitor-exit p0

    .line 12
    return-void

    .line 13
    :cond_0
    const/4 v0, 0x1

    .line 14
    :try_start_1
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->x:Z

    .line 15
    .line 16
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->a()V

    .line 17
    .line 18
    .line 19
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->d()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 20
    .line 21
    .line 22
    monitor-exit p0

    .line 23
    return-void

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 26
    throw v0
.end method

.method public getPushDebugInfo()Lorg/json/JSONObject;
    .locals 4

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->o:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v2, "gcm_reg_id_key"

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-interface {p0, v2, v3}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {v0, v1, p0}, Lcom/salesforce/marketingcloud/messages/push/b;->a(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Lorg/json/JSONObject;

    .line 19
    .line 20
    .line 21
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    return-object p0

    .line 23
    :catch_0
    move-exception p0

    .line 24
    sget-object v0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    new-array v1, v1, [Ljava/lang/Object;

    .line 28
    .line 29
    const-string v2, "Unable to acquire push debug info."

    .line 30
    .line 31
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    new-instance p0, Lorg/json/JSONObject;

    .line 35
    .line 36
    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 37
    .line 38
    .line 39
    return-object p0
.end method

.method public getPushToken()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "gcm_reg_id_key"

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-interface {p0, v0, v1}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public handleMessage(Lcom/google/firebase/messaging/v;)Z
    .locals 4

    .line 1
    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->isMarketingCloudPush(Lcom/google/firebase/messaging/v;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    const/4 p1, 0x0

    new-array v0, p1, [Ljava/lang/Object;

    const-string v1, "Message was not sent from the Marketing Cloud.  Message ignored."

    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return p1

    .line 3
    :cond_0
    invoke-virtual {p1}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    move-result-object v0

    .line 4
    new-instance v1, Ljava/util/Date;

    .line 5
    iget-object p1, p1, Lcom/google/firebase/messaging/v;->d:Landroid/os/Bundle;

    const-string v2, "google.sent_time"

    invoke-virtual {p1, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    .line 6
    instance-of v2, p1, Ljava/lang/Long;

    if-eqz v2, :cond_1

    .line 7
    check-cast p1, Ljava/lang/Long;

    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    move-result-wide v2

    goto :goto_0

    .line 8
    :cond_1
    instance-of v2, p1, Ljava/lang/String;

    if-eqz v2, :cond_2

    .line 9
    :try_start_0
    move-object v2, p1

    check-cast v2, Ljava/lang/String;

    invoke-static {v2}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v2
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    .line 10
    :catch_0
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Invalid sent time: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    const-string v2, "FirebaseMessaging"

    invoke-static {v2, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    :cond_2
    const-wide/16 v2, 0x0

    .line 11
    :goto_0
    invoke-direct {v1, v2, v3}, Ljava/util/Date;-><init>(J)V

    invoke-static {v1}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    move-result-object p1

    const-string v1, "messageDateUtc"

    invoke-interface {v0, v1, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/messages/push/a;->f(Ljava/util/Map;)V

    const/4 p0, 0x1

    return p0
.end method

.method public handleMessage(Ljava/util/Map;)Z
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)Z"
        }
    .end annotation

    .line 13
    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->isMarketingCloudPush(Ljava/util/Map;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 14
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    const/4 p1, 0x0

    new-array v0, p1, [Ljava/lang/Object;

    const-string v1, "Message was not sent from the Marketing Cloud.  Message ignored."

    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return p1

    .line 15
    :cond_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/push/a;->f(Ljava/util/Map;)V

    const/4 p0, 0x1

    return p0
.end method

.method public init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 4

    .line 1
    iput p2, p0, Lcom/salesforce/marketingcloud/messages/push/a;->v:I

    .line 2
    .line 3
    const/4 p1, 0x4

    .line 4
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/b;->b(II)Z

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    if-eqz p1, :cond_2

    .line 9
    .line 10
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    .line 11
    .line 12
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const-string p2, "et_push_enabled"

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    invoke-interface {p1, p2, v0}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->x:Z

    .line 24
    .line 25
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->c()V

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->l:Lcom/salesforce/marketingcloud/alarms/b;

    .line 29
    .line 30
    sget-object p2, Lcom/salesforce/marketingcloud/alarms/a$a;->f:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 31
    .line 32
    filled-new-array {p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-virtual {p1, p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->o:Ljava/lang/String;

    .line 40
    .line 41
    const-string v0, "sender_id"

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    if-eqz p1, :cond_1

    .line 45
    .line 46
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/push/a;->b()V

    .line 47
    .line 48
    .line 49
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->o:Ljava/lang/String;

    .line 50
    .line 51
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    .line 52
    .line 53
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    const/4 v2, 0x0

    .line 58
    invoke-interface {p2, v0, v2}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    if-nez p1, :cond_0

    .line 67
    .line 68
    sget-object p1, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 69
    .line 70
    new-array p2, v1, [Ljava/lang/Object;

    .line 71
    .line 72
    const-string v0, "Sender Id has changed.  Refresh system token."

    .line 73
    .line 74
    invoke-static {p1, v0, p2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    .line 78
    .line 79
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->o:Ljava/lang/String;

    .line 80
    .line 81
    invoke-static {p1, p0}, Lcom/salesforce/marketingcloud/MCService;->b(Landroid/content/Context;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    return-void

    .line 85
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    .line 86
    .line 87
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    const-string p2, "last_push_token_refresh"

    .line 92
    .line 93
    const-wide/16 v2, 0x0

    .line 94
    .line 95
    invoke-interface {p1, p2, v2, v3}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 96
    .line 97
    .line 98
    move-result-wide p1

    .line 99
    sget-wide v2, Lcom/salesforce/marketingcloud/messages/push/a;->D:J

    .line 100
    .line 101
    add-long/2addr p1, v2

    .line 102
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 103
    .line 104
    .line 105
    move-result-wide v2

    .line 106
    cmp-long p1, p1, v2

    .line 107
    .line 108
    if-gez p1, :cond_2

    .line 109
    .line 110
    sget-object p1, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 111
    .line 112
    new-array p2, v1, [Ljava/lang/Object;

    .line 113
    .line 114
    const-string v0, "Push token refresh cool down expired.  Refresh system token."

    .line 115
    .line 116
    invoke-static {p1, v0, p2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    .line 120
    .line 121
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->o:Ljava/lang/String;

    .line 122
    .line 123
    invoke-static {p1, p0}, Lcom/salesforce/marketingcloud/MCService;->b(Landroid/content/Context;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    return-void

    .line 127
    :cond_1
    sget-object p1, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 128
    .line 129
    new-array v1, v1, [Ljava/lang/Object;

    .line 130
    .line 131
    const-string v2, "No sender id was provided during initialization.  You will not receive push messages until a token is manually set."

    .line 132
    .line 133
    invoke-static {p1, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->l:Lcom/salesforce/marketingcloud/alarms/b;

    .line 137
    .line 138
    filled-new-array {p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 139
    .line 140
    .line 141
    move-result-object p2

    .line 142
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 143
    .line 144
    .line 145
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    .line 146
    .line 147
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    :cond_2
    return-void
.end method

.method public declared-synchronized isPushEnabled()Z
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->x:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    monitor-exit p0

    .line 5
    return v0

    .line 6
    :catchall_0
    move-exception v0

    .line 7
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 8
    throw v0
.end method

.method public registerSilentPushListener(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$SilentPushListener;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->m:Ljava/util/Set;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->m:Ljava/util/Set;

    .line 8
    .line 9
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public registerTokenRefreshListener(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$PushTokenRefreshListener;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

    .line 8
    .line 9
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public setPushToken(Ljava/lang/String;)V
    .locals 3

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->v:I

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->b(II)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_2

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 14
    .line 15
    new-array p1, v0, [Ljava/lang/Object;

    .line 16
    .line 17
    const-string v0, "Provided pushToken was null"

    .line 18
    .line 19
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->o:Ljava/lang/String;

    .line 24
    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    sget-object v1, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 28
    .line 29
    new-array v0, v0, [Ljava/lang/Object;

    .line 30
    .line 31
    const-string v2, "Setting the SenderId during SDK initialization and setting the push token will cause conflicts in the system and could prevent the device from receiving push messages."

    .line 32
    .line 33
    invoke-static {v1, v2, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->n:Lcom/salesforce/marketingcloud/storage/h;

    .line 37
    .line 38
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    const-string v1, "sender_id"

    .line 43
    .line 44
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const-string v1, "gcm_reg_id_key"

    .line 48
    .line 49
    invoke-interface {v0, v1, p1}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->l:Lcom/salesforce/marketingcloud/alarms/b;

    .line 53
    .line 54
    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->f:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 55
    .line 56
    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 61
    .line 62
    .line 63
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/push/a;->b(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    :cond_2
    return-void
.end method

.method public tearDown(Z)V
    .locals 0

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a;->w:Landroid/content/BroadcastReceiver;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->j:Landroid/content/Context;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public unregisterSilentPushListener(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$SilentPushListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->m:Ljava/util/Set;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->m:Ljava/util/Set;

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

.method public unregisterTokenRefreshListener(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$PushTokenRefreshListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a;->p:Ljava/util/Set;

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
