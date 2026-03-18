.class Lcom/salesforce/marketingcloud/notifications/a$c;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/notifications/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "c"
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/notifications/a;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/notifications/a;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/a$c;->a:Lcom/salesforce/marketingcloud/notifications/a;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p2, :cond_0

    .line 3
    .line 4
    sget-object p0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    .line 5
    .line 6
    new-array p1, v0, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string p2, "Received null intent"

    .line 9
    .line 10
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    new-instance v1, Landroid/content/Intent;

    .line 15
    .line 16
    const-string v2, "com.salesforce.marketingcloud.notifications.open.RECEIVED"

    .line 17
    .line 18
    invoke-direct {v1, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-virtual {p1, v1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    if-nez v1, :cond_1

    .line 37
    .line 38
    sget-object p0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    .line 39
    .line 40
    new-array p1, v0, [Ljava/lang/Object;

    .line 41
    .line 42
    const-string p2, "Received null action"

    .line 43
    .line 44
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_1
    const-string v0, "com.salesforce.marketingcloud.notifications.OPENED"

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_2

    .line 55
    .line 56
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/a$c;->a:Lcom/salesforce/marketingcloud/notifications/a;

    .line 57
    .line 58
    invoke-static {p2}, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->extractMessage(Landroid/content/Intent;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    const-string p0, "com.salesforce.marketingcloud.notifications.EXTRA_OPEN_INTENT"

    .line 63
    .line 64
    invoke-virtual {p2, p0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    move-object v5, p0

    .line 69
    check-cast v5, Landroid/app/PendingIntent;

    .line 70
    .line 71
    invoke-virtual {p2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    const-string p0, "com.salesforce.marketingcloud.notifications.EXTRA_AUTO_CANCEL"

    .line 76
    .line 77
    const/4 v0, 0x1

    .line 78
    invoke-virtual {p2, p0, v0}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z

    .line 79
    .line 80
    .line 81
    move-result v7

    .line 82
    move-object v3, p1

    .line 83
    invoke-virtual/range {v2 .. v7}, Lcom/salesforce/marketingcloud/notifications/a;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Landroid/app/PendingIntent;Landroid/os/Bundle;Z)V

    .line 84
    .line 85
    .line 86
    return-void

    .line 87
    :cond_2
    sget-object p0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    .line 88
    .line 89
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    const-string p2, "Received unknown action: %s"

    .line 94
    .line 95
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    return-void
.end method
