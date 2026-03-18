.class Lcom/salesforce/marketingcloud/notifications/a$a;
.super Ljava/lang/Thread;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/notifications/a;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/notifications/a$b;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

.field final synthetic c:Lcom/salesforce/marketingcloud/notifications/a$b;

.field final synthetic d:Lcom/salesforce/marketingcloud/notifications/a;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/notifications/a;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/notifications/a$b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->d:Lcom/salesforce/marketingcloud/notifications/a;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->c:Lcom/salesforce/marketingcloud/notifications/a$b;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Thread;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public run()V
    .locals 4
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "NewApi"
        }
    .end annotation

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->d:Lcom/salesforce/marketingcloud/notifications/a;

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/notifications/a;->f:Lcom/salesforce/marketingcloud/notifications/b;

    .line 4
    .line 5
    iget-object v0, v0, Lcom/salesforce/marketingcloud/notifications/a;->g:Landroid/content/Context;

    .line 6
    .line 7
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 8
    .line 9
    invoke-virtual {v1, v0, v2}, Lcom/salesforce/marketingcloud/notifications/b;->setupNotificationBuilder(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroidx/core/app/x;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->d:Lcom/salesforce/marketingcloud/notifications/a;

    .line 14
    .line 15
    iget-object v1, v1, Lcom/salesforce/marketingcloud/notifications/a;->g:Landroid/content/Context;

    .line 16
    .line 17
    const-string v2, "notification"

    .line 18
    .line 19
    invoke-virtual {v1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    check-cast v1, Landroid/app/NotificationManager;

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    const-string v2, "com.marketingcloud.salesforce.notifications.TAG"

    .line 28
    .line 29
    iget-object v3, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 30
    .line 31
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    invoke-virtual {v0}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {v1, v2, v3, v0}, Landroid/app/NotificationManager;->notify(Ljava/lang/String;ILandroid/app/Notification;)V

    .line 40
    .line 41
    .line 42
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->d:Lcom/salesforce/marketingcloud/notifications/a;

    .line 43
    .line 44
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/notifications/a;->b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 47
    .line 48
    .line 49
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 50
    .line 51
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId()I

    .line 52
    .line 53
    .line 54
    move-result v0
    :try_end_0
    .catch Lcom/salesforce/marketingcloud/push/f; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 55
    goto :goto_3

    .line 56
    :catch_0
    move-exception v0

    .line 57
    goto :goto_0

    .line 58
    :catch_1
    move-exception v0

    .line 59
    goto :goto_1

    .line 60
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    new-array v2, v2, [Ljava/lang/Object;

    .line 64
    .line 65
    const-string v3, "Unable to show notification due to an exception thrown by Android."

    .line 66
    .line 67
    invoke-static {v1, v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_2

    .line 71
    :goto_1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->d:Lcom/salesforce/marketingcloud/notifications/a;

    .line 72
    .line 73
    invoke-static {v1}, Lcom/salesforce/marketingcloud/notifications/a;->b(Lcom/salesforce/marketingcloud/notifications/a;)Lcom/salesforce/marketingcloud/analytics/j;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 78
    .line 79
    iget-object v2, v2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

    .line 80
    .line 81
    invoke-interface {v1, v0, v2}, Lcom/salesforce/marketingcloud/analytics/j;->a(Lcom/salesforce/marketingcloud/push/f;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    :cond_0
    :goto_2
    const/4 v0, -0x1

    .line 85
    :goto_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/a$a;->c:Lcom/salesforce/marketingcloud/notifications/a$b;

    .line 86
    .line 87
    if-eqz p0, :cond_1

    .line 88
    .line 89
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/notifications/a$b;->a(I)V

    .line 90
    .line 91
    .line 92
    :cond_1
    return-void
.end method
