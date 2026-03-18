.class public abstract Lcom/salesforce/marketingcloud/notifications/NotificationManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;,
        Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;,
        Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;,
        Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationMessageDisplayedListener;,
        Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;
    }
.end annotation


# static fields
.field public static final ACTION_NOTIFICATION_CLICKED:Ljava/lang/String; = "com.salesforce.marketingcloud.NOTIFICATION_CLICKED"
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end field

.field public static final DEFAULT_CHANNEL_ID:Ljava/lang/String; = "com.salesforce.marketingcloud.DEFAULT_CHANNEL"
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end field

.field public static final DEFAULT_FOREGROUND_CHANNEL_ID:Ljava/lang/String; = "com.salesforce.marketingcloud.DEFAULT_FOREGROUND_CHANNEL"
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end field

.field static final d:Ljava/lang/String;

.field private static final e:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.EXTRA_MESSAGE"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "NotificationManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static a(Landroid/content/Intent;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroid/content/Intent;
    .locals 1

    .line 1
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/k;->a(Landroid/os/Parcelable;)[B

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const-string v0, "com.salesforce.marketingcloud.notifications.EXTRA_MESSAGE"

    .line 6
    .line 7
    invoke-virtual {p0, v0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;[B)Landroid/content/Intent;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public static cancelNotificationMessage(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-ltz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "notification"

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Landroid/app/NotificationManager;

    .line 14
    .line 15
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    const-string v0, "com.marketingcloud.salesforce.notifications.TAG"

    .line 20
    .line 21
    invoke-virtual {p0, v0, p1}, Landroid/app/NotificationManager;->cancel(Ljava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public static createDefaultNotificationChannel(Landroid/content/Context;)Ljava/lang/String;
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    const/4 v0, 0x0

    .line 2
    invoke-static {p0, v0}, Lcom/salesforce/marketingcloud/notifications/b;->b(Landroid/content/Context;Z)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static createDefaultNotificationChannel(Landroid/content/Context;Z)Ljava/lang/String;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/notifications/b;->b(Landroid/content/Context;Z)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static createForegroundNotificationChannel(Landroid/content/Context;)Ljava/lang/String;
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {p0, v0}, Lcom/salesforce/marketingcloud/notifications/b;->a(Landroid/content/Context;Z)Ljava/lang/String;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public static extractMessage(Landroid/content/Intent;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
    .locals 3
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    :try_start_0
    const-string v0, "com.salesforce.marketingcloud.notifications.EXTRA_MESSAGE"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/content/Intent;->getByteArrayExtra(Ljava/lang/String;)[B

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/internal/k;->a([BLandroid/os/Parcelable$Creator;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    return-object v0

    .line 16
    :catch_0
    move-exception v0

    .line 17
    sget-object v1, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    .line 18
    .line 19
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string v2, "Unable to retrieve NotificationMessage from Intent (%s)."

    .line 24
    .line 25
    invoke-static {v1, v0, v2, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    return-object p0
.end method

.method public static getDefaultNotificationBuilder(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Ljava/lang/String;I)Landroidx/core/app/x;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/notifications/b;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Ljava/lang/String;I)Landroidx/core/app/x;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static redirectIntentForAnalytics(Landroid/content/Context;Landroid/app/PendingIntent;Lcom/google/firebase/messaging/v;Z)Landroid/app/PendingIntent;
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    const/4 v0, 0x0

    .line 1
    :try_start_0
    invoke-virtual {p2}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    move-result-object p2

    invoke-static {p2}, Lcom/salesforce/marketingcloud/internal/j;->a(Ljava/util/Map;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    move-result-object p2

    .line 2
    invoke-static {p0, p1, p2, p3, v0}, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->redirectIntentForAnalytics(Landroid/content/Context;Landroid/app/PendingIntent;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ZLandroid/os/Bundle;)Landroid/app/PendingIntent;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    .line 3
    sget-object p1, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string p3, "Failed to create {NotificationMessage} from {RemoteMessage}, not processing {PendingIntent} for analytics."

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v0
.end method

.method public static redirectIntentForAnalytics(Landroid/content/Context;Landroid/app/PendingIntent;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)Landroid/app/PendingIntent;
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    const/4 v0, 0x0

    .line 4
    invoke-static {p0, p1, p2, p3, v0}, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->redirectIntentForAnalytics(Landroid/content/Context;Landroid/app/PendingIntent;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ZLandroid/os/Bundle;)Landroid/app/PendingIntent;

    move-result-object p0

    return-object p0
.end method

.method public static redirectIntentForAnalytics(Landroid/content/Context;Landroid/app/PendingIntent;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ZLandroid/os/Bundle;)Landroid/app/PendingIntent;
    .locals 2
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    if-nez p4, :cond_0

    .line 5
    new-instance p4, Landroid/os/Bundle;

    invoke-direct {p4}, Landroid/os/Bundle;-><init>()V

    .line 6
    :cond_0
    invoke-static {p2}, Lcom/salesforce/marketingcloud/internal/k;->a(Landroid/os/Parcelable;)[B

    move-result-object p2

    const-string v0, "com.salesforce.marketingcloud.notifications.EXTRA_MESSAGE"

    invoke-virtual {p4, v0, p2}, Landroid/os/Bundle;->putByteArray(Ljava/lang/String;[B)V

    .line 7
    const-string p2, "com.salesforce.marketingcloud.notifications.EXTRA_OPEN_INTENT"

    invoke-virtual {p4, p2, p1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 8
    const-string p1, "com.salesforce.marketingcloud.notifications.EXTRA_AUTO_CANCEL"

    invoke-virtual {p4, p1, p3}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 9
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide p1

    invoke-static {p1, p2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object p1

    const-string p2, "mcsdk"

    const-string p3, "pushOpen"

    invoke-static {p2, p3, p1}, Landroid/net/Uri;->fromParts(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;

    move-result-object p1

    const/high16 p2, 0x40000000    # 2.0f

    .line 10
    invoke-static {p2}, Lcom/salesforce/marketingcloud/util/j;->a(I)I

    move-result p2

    .line 11
    sget p3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1f

    const/4 v1, 0x0

    if-lt p3, v0, :cond_1

    .line 12
    invoke-static {p0, p4}, Lcom/salesforce/marketingcloud/notifications/NotificationOpenActivity;->a(Landroid/content/Context;Landroid/os/Bundle;)Landroid/content/Intent;

    move-result-object p3

    invoke-virtual {p3, p1}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    move-result-object p1

    .line 13
    invoke-static {p0, v1, p1, p2}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object p0

    return-object p0

    .line 14
    :cond_1
    invoke-static {p0, p4}, Lcom/salesforce/marketingcloud/NotificationOpenedService;->b(Landroid/content/Context;Landroid/os/Bundle;)Landroid/content/Intent;

    move-result-object p3

    invoke-virtual {p3, p1}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    move-result-object p1

    .line 15
    invoke-static {p0, v1, p1, p2}, Landroid/app/PendingIntent;->getService(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public abstract areNotificationsEnabled()Z
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract disableNotifications()V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract enableNotifications()V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract registerNotificationMessageDisplayedListener(Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationMessageDisplayedListener;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract setShouldShowNotificationListener(Lcom/salesforce/marketingcloud/notifications/NotificationManager$ShouldShowNotificationListener;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract unregisterNotificationMessageDisplayedListener(Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationMessageDisplayedListener;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method
