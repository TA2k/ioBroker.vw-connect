.class public final Lcom/salesforce/marketingcloud/notifications/PushNotificationActionHandler;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 4

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "intent"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-wide/16 v0, 0xbb8

    .line 12
    .line 13
    const-wide/16 v2, 0x32

    .line 14
    .line 15
    invoke-static {v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/util/j;->a(JJ)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    if-eqz p0, :cond_1

    .line 26
    .line 27
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    const-string v0, "com.salesforce.marketingcloud.notifications.INTENT_KEY_DATA_NOTIFICATION_MESSAGE"

    .line 34
    .line 35
    invoke-virtual {p2, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 40
    .line 41
    if-eqz v0, :cond_1

    .line 42
    .line 43
    const-string v1, "notification"

    .line 44
    .line 45
    invoke-virtual {p1, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    const-string v1, "null cannot be cast to non-null type android.app.NotificationManager"

    .line 50
    .line 51
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    check-cast p1, Landroid/app/NotificationManager;

    .line 55
    .line 56
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    const-string v2, "com.salesforce.marketingcloud.notifications.ACTION_CAROUSEL_PREVIOUS"

    .line 61
    .line 62
    const/4 v3, 0x0

    .line 63
    invoke-static {v1, v2, v3}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-nez v1, :cond_0

    .line 68
    .line 69
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    const-string v1, "com.salesforce.marketingcloud.notifications.ACTION_CAROUSEL_NEXT"

    .line 74
    .line 75
    invoke-static {p2, v1, v3}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    if-eqz p2, :cond_1

    .line 80
    .line 81
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getMarketingCloudConfig()Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    iget-object p2, p2, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 86
    .line 87
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->getNotificationBuilder()Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getNotificationManager()Lcom/salesforce/marketingcloud/notifications/NotificationManager;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    const-string p2, "<get-notificationManager>(...)"

    .line 95
    .line 96
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    instance-of p2, p0, Lcom/salesforce/marketingcloud/notifications/a;

    .line 100
    .line 101
    if-eqz p2, :cond_1

    .line 102
    .line 103
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->getNotificationId$sdk_release()I

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    check-cast p0, Lcom/salesforce/marketingcloud/notifications/a;

    .line 108
    .line 109
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/notifications/a;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroidx/core/app/x;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    invoke-virtual {p0}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    const-string v0, "com.marketingcloud.salesforce.notifications.TAG"

    .line 118
    .line 119
    invoke-virtual {p1, v0, p2, p0}, Landroid/app/NotificationManager;->notify(Ljava/lang/String;ILandroid/app/Notification;)V

    .line 120
    .line 121
    .line 122
    :cond_1
    return-void
.end method
