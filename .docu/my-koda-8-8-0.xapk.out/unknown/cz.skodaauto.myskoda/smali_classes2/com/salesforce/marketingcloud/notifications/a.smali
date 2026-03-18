.class public Lcom/salesforce/marketingcloud/notifications/a;
.super Lcom/salesforce/marketingcloud/notifications/NotificationManager;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/e;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/notifications/a$c;,
        Lcom/salesforce/marketingcloud/notifications/a$b;
    }
.end annotation


# static fields
.field public static final n:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.OPENED"

.field public static final o:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.open.RECEIVED"

.field public static final p:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.MESSAGE"

.field public static final q:I = -0x1

.field static final r:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.EXTRA_OPEN_INTENT"

.field static final s:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.EXTRA_AUTO_CANCEL"

.field static final t:Ljava/lang/String; = "com.marketingcloud.salesforce.notifications.TAG"

.field static final u:Ljava/lang/String; = "com.marketingcloud.salesforce.notifications.ENABLED"

.field static final v:Ljava/lang/String; = "notification_id_key"


# instance fields
.field final f:Lcom/salesforce/marketingcloud/notifications/b;

.field final g:Landroid/content/Context;

.field private final h:Lcom/salesforce/marketingcloud/storage/h;

.field private final i:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationMessageDisplayedListener;",
            ">;"
        }
    .end annotation
.end field

.field private final j:Lcom/salesforce/marketingcloud/analytics/j;

.field private k:Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;

.field private l:Landroid/content/BroadcastReceiver;

.field private m:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/notifications/b;Lcom/salesforce/marketingcloud/analytics/j;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/notifications/NotificationManager;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->m:Z

    .line 6
    .line 7
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/a;->g:Landroid/content/Context;

    .line 8
    .line 9
    iput-object p2, p0, Lcom/salesforce/marketingcloud/notifications/a;->h:Lcom/salesforce/marketingcloud/storage/h;

    .line 10
    .line 11
    iput-object p3, p0, Lcom/salesforce/marketingcloud/notifications/a;->f:Lcom/salesforce/marketingcloud/notifications/b;

    .line 12
    .line 13
    const-string p1, "MessageAnalyticEventListener is null."

    .line 14
    .line 15
    invoke-static {p4, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    check-cast p1, Lcom/salesforce/marketingcloud/analytics/j;

    .line 20
    .line 21
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/a;->j:Lcom/salesforce/marketingcloud/analytics/j;

    .line 22
    .line 23
    new-instance p1, Landroidx/collection/g;

    .line 24
    .line 25
    const/4 p2, 0x0

    .line 26
    invoke-direct {p1, p2}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/a;->i:Ljava/util/Set;

    .line 30
    .line 31
    return-void
.end method

.method public static a(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;Lcom/salesforce/marketingcloud/analytics/j;)Lcom/salesforce/marketingcloud/notifications/a;
    .locals 4
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "LambdaLast"
        }
    .end annotation

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/b;

    iget v1, p2, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->smallIconResId:I

    iget-object v2, p2, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->launchIntentProvider:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;

    iget-object v3, p2, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->notificationBuilder:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;

    iget-object p2, p2, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->channelIdProvider:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;

    invoke-direct {v0, v1, v2, v3, p2}, Lcom/salesforce/marketingcloud/notifications/b;-><init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;)V

    .line 2
    new-instance p2, Lcom/salesforce/marketingcloud/notifications/a;

    invoke-direct {p2, p0, p1, v0, p3}, Lcom/salesforce/marketingcloud/notifications/a;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/notifications/b;Lcom/salesforce/marketingcloud/analytics/j;)V

    return-object p2
.end method

.method private a()V
    .locals 2

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->h:Lcom/salesforce/marketingcloud/storage/h;

    if-eqz v0, :cond_0

    .line 9
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    .line 10
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->m:Z

    .line 11
    const-string v1, "com.marketingcloud.salesforce.notifications.ENABLED"

    invoke-interface {v0, v1, p0}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    .line 12
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    :cond_0
    return-void
.end method

.method private a(Landroid/content/Context;)V
    .locals 3

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->h:Lcom/salesforce/marketingcloud/storage/h;

    if-nez v0, :cond_0

    goto :goto_1

    .line 4
    :cond_0
    new-instance v0, Landroidx/core/app/h0;

    invoke-direct {v0, p1}, Landroidx/core/app/h0;-><init>(Landroid/content/Context;)V

    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->h:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p0

    const-string p1, "notification_id_key"

    const/4 v1, -0x1

    invoke-interface {p0, p1, v1}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    move-result p0

    const/4 p1, 0x0

    :goto_0
    if-ltz p0, :cond_1

    const/16 v1, 0x64

    if-ge p1, v1, :cond_1

    .line 6
    const-string v1, "com.marketingcloud.salesforce.notifications.TAG"

    .line 7
    iget-object v2, v0, Landroidx/core/app/h0;->a:Landroid/app/NotificationManager;

    invoke-virtual {v2, v1, p0}, Landroid/app/NotificationManager;->cancel(Ljava/lang/String;I)V

    add-int/lit8 p0, p0, -0x1

    add-int/lit8 p1, p1, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    return-void
.end method

.method public static bridge synthetic b(Lcom/salesforce/marketingcloud/notifications/a;)Lcom/salesforce/marketingcloud/analytics/j;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->j:Lcom/salesforce/marketingcloud/analytics/j;

    return-object p0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroidx/core/app/x;
    .locals 2

    .line 40
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->f:Lcom/salesforce/marketingcloud/notifications/b;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/a;->g:Landroid/content/Context;

    invoke-virtual {v0, v1, p1}, Lcom/salesforce/marketingcloud/notifications/b;->setupNotificationBuilder(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroidx/core/app/x;

    move-result-object p0
    :try_end_0
    .catch Lcom/salesforce/marketingcloud/push/f; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception v0

    .line 41
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->j:Lcom/salesforce/marketingcloud/analytics/j;

    iget-object p1, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

    invoke-interface {p0, v0, p1}, Lcom/salesforce/marketingcloud/analytics/j;->a(Lcom/salesforce/marketingcloud/push/f;Ljava/lang/String;)V

    const/4 p0, 0x0

    return-object p0
.end method

.method public a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Landroid/app/PendingIntent;Landroid/os/Bundle;Z)V
    .locals 5

    .line 42
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Notification open Event Logged for id : (%s)"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 43
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/a;->j:Lcom/salesforce/marketingcloud/analytics/j;

    invoke-interface {v1, p2}, Lcom/salesforce/marketingcloud/analytics/j;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 44
    const-string v1, "com.salesforce.marketingcloud.notifications.INTENT_KEY_ANALYTIC_TYPE"

    const/4 v2, -0x1

    invoke-virtual {p4, v1, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    move-result v1

    .line 45
    const-string v2, "com.salesforce.marketingcloud.notifications.INTENT_KEY_ANALYTIC_CLICKED_ID"

    const/4 v3, 0x0

    invoke-virtual {p4, v2, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    .line 46
    const-string v4, "com.salesforce.marketingcloud.notifications.INTENT_KEY_ANALYTIC_TITLE"

    invoke-virtual {p4, v4, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p4

    if-ltz v1, :cond_0

    if-eqz v2, :cond_0

    .line 47
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->j:Lcom/salesforce/marketingcloud/analytics/j;

    invoke-interface {p0, p2, v1, v2, p4}, Lcom/salesforce/marketingcloud/analytics/j;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/String;Ljava/lang/String;)V

    .line 48
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string p4, "Notification click Event Logged for id : (%s)"

    invoke-static {v0, p4, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    if-eqz p3, :cond_1

    .line 49
    :try_start_0
    invoke-virtual {p3}, Landroid/app/PendingIntent;->send()V
    :try_end_0
    .catch Landroid/app/PendingIntent$CanceledException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p0

    .line 50
    sget-object p3, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    const/4 p4, 0x0

    new-array p4, p4, [Ljava/lang/Object;

    const-string v0, "Failed to send notification\'s open action PendingIntent."

    invoke-static {p3, p0, v0, p4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_1
    :goto_0
    if-eqz p5, :cond_2

    .line 51
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->cancelNotificationMessage(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 52
    :cond_2
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 p3, 0x1e

    if-gt p0, p3, :cond_3

    .line 53
    new-instance p0, Landroid/content/Intent;

    const-string p3, "android.intent.action.CLOSE_SYSTEM_DIALOGS"

    invoke-direct {p0, p3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    .line 54
    :cond_3
    new-instance p0, Landroid/os/Bundle;

    invoke-direct {p0}, Landroid/os/Bundle;-><init>()V

    .line 55
    const-string p3, "com.salesforce.marketingcloud.notifications.MESSAGE"

    invoke-virtual {p0, p3, p2}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 56
    sget-object p2, Lcom/salesforce/marketingcloud/behaviors/a;->p:Lcom/salesforce/marketingcloud/behaviors/a;

    invoke-static {p1, p2, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    return-void
.end method

.method public declared-synchronized a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/notifications/a$b;)V
    .locals 8

    monitor-enter p0

    .line 13
    :try_start_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/notifications/a;->areNotificationsEnabled()Z

    move-result v0

    const/4 v1, -0x1

    if-nez v0, :cond_1

    .line 14
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v2, "Notifications are not enabled.  Message %s will not be displayed"

    invoke-static {v0, v2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    if-eqz p2, :cond_0

    .line 15
    invoke-interface {p2, v1}, Lcom/salesforce/marketingcloud/notifications/a$b;->a(I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_4

    :cond_0
    :goto_0
    monitor-exit p0

    return-void

    .line 16
    :cond_1
    :try_start_1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    move-result v0

    const/4 v2, 0x0

    if-nez v0, :cond_3

    .line 17
    sget-object p1, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    new-array v0, v2, [Ljava/lang/Object;

    const-string v2, "Notifications with no alert message are not shown."

    invoke-static {p1, v2, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    if-eqz p2, :cond_2

    .line 18
    invoke-interface {p2, v1}, Lcom/salesforce/marketingcloud/notifications/a$b;->a(I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_2
    monitor-exit p0

    return-void

    .line 19
    :cond_3
    :try_start_2
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId()I

    move-result v0

    if-ltz v0, :cond_5

    if-eqz p2, :cond_4

    .line 20
    invoke-interface {p2, v1}, Lcom/salesforce/marketingcloud/notifications/a$b;->a(I)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :cond_4
    monitor-exit p0

    return-void

    .line 21
    :cond_5
    :try_start_3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->k:Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    const/4 v3, 0x1

    if-eqz v0, :cond_6

    .line 22
    :try_start_4
    invoke-interface {v0, p1}, Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;->shouldShowNotification(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Z

    move-result v0
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    goto :goto_1

    :catch_0
    move-exception v0

    .line 23
    :try_start_5
    sget-object v4, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    iget-object v5, p0, Lcom/salesforce/marketingcloud/notifications/a;->k:Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;

    .line 24
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object v6

    filled-new-array {v5, v6}, [Ljava/lang/Object;

    move-result-object v5

    .line 25
    const-string v6, "%s threw an exception while processing shouldShowNotification() for messageId: %s"

    invoke-static {v4, v0, v6, v5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    move v0, v3

    .line 26
    :goto_1
    :try_start_6
    iget-object v4, p0, Lcom/salesforce/marketingcloud/notifications/a;->j:Lcom/salesforce/marketingcloud/analytics/j;

    invoke-interface {v4, p1, v0}, Lcom/salesforce/marketingcloud/analytics/j;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_1
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    goto :goto_2

    :catch_1
    move-exception v4

    .line 27
    :try_start_7
    sget-object v5, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object v6

    filled-new-array {v6}, [Ljava/lang/Object;

    move-result-object v6

    const-string v7, "Failed to log Should Show Notification analytic for messageId: %s"

    invoke-static {v5, v4, v7, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_2

    :cond_6
    move v0, v3

    :goto_2
    if-eqz v0, :cond_8

    .line 28
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->h:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    .line 29
    const-string v1, "notification_id_key"

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    move-result v1

    invoke-static {p1, v1}, Lcom/salesforce/marketingcloud/internal/j;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;I)V

    .line 30
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    const-string v1, "notification_id_key"

    .line 31
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId()I

    move-result v4

    const v5, 0x7fffffff

    if-ge v4, v5, :cond_7

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId()I

    move-result v2

    add-int/2addr v2, v3

    .line 32
    :cond_7
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 33
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 34
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/a$a;

    invoke-direct {v0, p0, p1, p2}, Lcom/salesforce/marketingcloud/notifications/a$a;-><init>(Lcom/salesforce/marketingcloud/notifications/a;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/notifications/a$b;)V

    .line 35
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    goto :goto_3

    .line 36
    :cond_8
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/a;->k:Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;

    .line 37
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object p1

    filled-new-array {v2, p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 38
    const-string v2, "%s responded false to shouldShowNotification() for messageId: %s"

    invoke-static {v0, v2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    if-eqz p2, :cond_9

    .line 39
    invoke-interface {p2, v1}, Lcom/salesforce/marketingcloud/notifications/a$b;->a(I)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    :cond_9
    :goto_3
    monitor-exit p0

    return-void

    :goto_4
    :try_start_8
    monitor-exit p0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    throw p1
.end method

.method public final declared-synchronized areNotificationsEnabled()Z
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->m:Z
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

.method public b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 7

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->i:Ljava/util/Set;

    monitor-enter v0

    .line 3
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/a;->i:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    .line 4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/a;->i:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationMessageDisplayedListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v2, :cond_0

    .line 5
    :try_start_1
    invoke-interface {v2, p1}, Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationMessageDisplayedListener;->onNotificationMessageDisplayed(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_2

    :catch_0
    move-exception v3

    .line 6
    :try_start_2
    sget-object v4, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    const-string v5, "%s threw an exception while processing notification message (%s)"

    .line 7
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object v6

    filled-new-array {v2, v6}, [Ljava/lang/Object;

    move-result-object v2

    .line 8
    invoke-static {v4, v3, v5, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 9
    :cond_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 10
    :try_start_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->j:Lcom/salesforce/marketingcloud/analytics/j;

    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/analytics/j;->b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_1

    goto :goto_1

    :catch_1
    move-exception p0

    .line 11
    sget-object p1, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Failed to log analytics for message displayed."

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_1
    return-void

    .line 12
    :goto_2
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    throw p0
.end method

.method public final componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "NotificationManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public final componentState()Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    const-string v1, "notificationsEnabled"

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/notifications/a;->areNotificationsEnabled()Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 13
    .line 14
    .line 15
    const-string v1, "displayMetrics"

    .line 16
    .line 17
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/a;->g:Landroid/content/Context;

    .line 18
    .line 19
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {v2}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v2}, Landroid/util/DisplayMetrics;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 32
    .line 33
    .line 34
    const-string v1, "Dpi Density"

    .line 35
    .line 36
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/a;->g:Landroid/content/Context;

    .line 37
    .line 38
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    invoke-virtual {v2}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    iget v2, v2, Landroid/util/DisplayMetrics;->densityDpi:I

    .line 47
    .line 48
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 49
    .line 50
    .line 51
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/a;->k:Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;

    .line 52
    .line 53
    if-eqz v1, :cond_0

    .line 54
    .line 55
    const-string v2, "shouldShowNotificationListener"

    .line 56
    .line 57
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 66
    .line 67
    .line 68
    return-object v0

    .line 69
    :catch_0
    move-exception v1

    .line 70
    goto :goto_0

    .line 71
    :cond_0
    return-object v0

    .line 72
    :goto_0
    sget-object v2, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    .line 73
    .line 74
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/notifications/a;->componentName()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    const-string v3, "Unable to create component state for %s"

    .line 83
    .line 84
    invoke-static {v2, v1, v3, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    return-object v0
.end method

.method public controlChannelInit(I)V
    .locals 0

    .line 1
    return-void
.end method

.method public final declared-synchronized disableNotifications()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->m:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    :try_start_1
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->m:Z

    .line 10
    .line 11
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/notifications/a;->a()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 12
    .line 13
    .line 14
    monitor-exit p0

    .line 15
    return-void

    .line 16
    :catchall_0
    move-exception v0

    .line 17
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 18
    throw v0
.end method

.method public final declared-synchronized enableNotifications()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->m:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    const/4 v0, 0x1

    .line 9
    :try_start_1
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->m:Z

    .line 10
    .line 11
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/notifications/a;->a()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 12
    .line 13
    .line 14
    monitor-exit p0

    .line 15
    return-void

    .line 16
    :catchall_0
    move-exception v0

    .line 17
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 18
    throw v0
.end method

.method public final init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 1

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/notifications/a;->h:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const-string p2, "com.marketingcloud.salesforce.notifications.ENABLED"

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    invoke-interface {p1, p2, v0}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/notifications/a;->m:Z

    .line 15
    .line 16
    new-instance p1, Landroid/content/IntentFilter;

    .line 17
    .line 18
    invoke-direct {p1}, Landroid/content/IntentFilter;-><init>()V

    .line 19
    .line 20
    .line 21
    const-string p2, "com.salesforce.marketingcloud.notifications.OPENED"

    .line 22
    .line 23
    invoke-virtual {p1, p2}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance p2, Lcom/salesforce/marketingcloud/notifications/a$c;

    .line 27
    .line 28
    invoke-direct {p2, p0}, Lcom/salesforce/marketingcloud/notifications/a$c;-><init>(Lcom/salesforce/marketingcloud/notifications/a;)V

    .line 29
    .line 30
    .line 31
    iput-object p2, p0, Lcom/salesforce/marketingcloud/notifications/a;->l:Landroid/content/BroadcastReceiver;

    .line 32
    .line 33
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->g:Landroid/content/Context;

    .line 34
    .line 35
    const/4 v0, 0x4

    .line 36
    invoke-static {p0, p2, p1, v0}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public final registerNotificationMessageDisplayedListener(Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationMessageDisplayedListener;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->i:Ljava/util/Set;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->i:Ljava/util/Set;

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

.method public setShouldShowNotificationListener(Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/a;->k:Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;

    .line 2
    .line 3
    return-void
.end method

.method public final tearDown(Z)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/notifications/a;->g:Landroid/content/Context;

    .line 4
    .line 5
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/notifications/a;->a(Landroid/content/Context;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/notifications/a;->g:Landroid/content/Context;

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->l:Landroid/content/BroadcastReceiver;

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 15
    .line 16
    .line 17
    :cond_1
    return-void
.end method

.method public final unregisterNotificationMessageDisplayedListener(Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationMessageDisplayedListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a;->i:Ljava/util/Set;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a;->i:Ljava/util/Set;

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
