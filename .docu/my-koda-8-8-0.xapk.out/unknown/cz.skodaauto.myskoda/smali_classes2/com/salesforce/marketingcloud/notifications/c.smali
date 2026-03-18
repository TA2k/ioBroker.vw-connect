.class public Lcom/salesforce/marketingcloud/notifications/c;
.super Lcom/salesforce/marketingcloud/notifications/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0, v0, p2}, Lcom/salesforce/marketingcloud/notifications/b;-><init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public setupNotificationBuilder(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroidx/core/app/x;
    .locals 2

    .line 1
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/notifications/b;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget v1, p0, Lcom/salesforce/marketingcloud/notifications/b;->a:I

    .line 6
    .line 7
    invoke-static {p1, p2, v0, v1}, Lcom/salesforce/marketingcloud/notifications/b;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Ljava/lang/String;I)Landroidx/core/app/x;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/notifications/b;->c(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroid/app/PendingIntent;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    invoke-static {p1, p0, p2, v1}, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->redirectIntentForAnalytics(Landroid/content/Context;Landroid/app/PendingIntent;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)Landroid/app/PendingIntent;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    iput-object p0, v0, Landroidx/core/app/x;->g:Landroid/app/PendingIntent;

    .line 23
    .line 24
    :cond_0
    return-object v0
.end method
