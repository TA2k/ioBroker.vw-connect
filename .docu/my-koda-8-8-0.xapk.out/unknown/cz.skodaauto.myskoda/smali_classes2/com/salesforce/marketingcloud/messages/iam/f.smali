.class abstract Lcom/salesforce/marketingcloud/messages/iam/f;
.super Landroidx/fragment/app/o0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;
.implements Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;


# static fields
.field private static final d:I = 0x7b

.field private static final e:Ljava/lang/String; = "completedEvent"

.field private static final f:Ljava/lang/String;


# instance fields
.field private a:Lcom/salesforce/marketingcloud/messages/iam/k;

.field private b:Lcom/salesforce/marketingcloud/messages/iam/j;

.field private c:Lb/a0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "IamBaseActivity"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/fragment/app/o0;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V
    .locals 3

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    move-result-object v0

    invoke-virtual {v0, p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/k;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)Landroid/app/PendingIntent;

    move-result-object p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    .line 6
    :try_start_0
    invoke-virtual {p1}, Landroid/app/PendingIntent;->send()V
    :try_end_0
    .catch Landroid/app/PendingIntent$CanceledException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    .line 7
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v2, "Unable to launch url for button click"

    invoke-static {v1, p1, v2, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 8
    :cond_0
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "No PendingIntent returned for button click."

    invoke-static {p1, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    :goto_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    return-void
.end method

.method private d()V
    .locals 4
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->isReady()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getRegionMessageManager()Lcom/salesforce/marketingcloud/messages/RegionMessageManager;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const/4 v0, 0x0

    .line 22
    :try_start_0
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/messages/RegionMessageManager;->enableGeofenceMessaging()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    .line 29
    .line 30
    const-string v2, "Geofence messaging enabled from IAM action"

    .line 31
    .line 32
    new-array v3, v0, [Ljava/lang/Object;

    .line 33
    .line 34
    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :catch_0
    move-exception p0

    .line 39
    goto :goto_1

    .line 40
    :cond_0
    :goto_0
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/messages/RegionMessageManager;->enableProximityMessaging()Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-eqz p0, :cond_1

    .line 45
    .line 46
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    .line 47
    .line 48
    const-string v1, "Proximity messaging enabled from IAM action"

    .line 49
    .line 50
    new-array v2, v0, [Ljava/lang/Object;

    .line 51
    .line 52
    invoke-static {p0, v1, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :goto_1
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    .line 57
    .line 58
    new-array v0, v0, [Ljava/lang/Object;

    .line 59
    .line 60
    const-string v2, "Unable to enable region messaging"

    .line 61
    .line 62
    invoke-static {v1, p0, v2, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_1
    return-void
.end method

.method private e()V
    .locals 6

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    const-string v0, "android.permission.ACCESS_FINE_LOCATION"

    .line 9
    .line 10
    invoke-static {p0, v0}, Landroidx/core/app/b;->f(Landroid/app/Activity;Ljava/lang/String;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/16 v2, 0x7b

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    sget-object v0, Lcom/salesforce/marketingcloud/util/f;->a:[Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {p0, v0, v2}, Landroidx/core/app/b;->e(Landroid/app/Activity;[Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    :try_start_0
    new-instance v0, Landroid/content/Intent;

    .line 25
    .line 26
    const-string v3, "android.settings.APPLICATION_DETAILS_SETTINGS"

    .line 27
    .line 28
    invoke-direct {v0, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v3, "package"

    .line 32
    .line 33
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    const/4 v5, 0x0

    .line 38
    invoke-static {v3, v4, v5}, Landroid/net/Uri;->fromParts(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    invoke-virtual {v0, v3}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {p0, v0, v2}, Lb/r;->startActivityForResult(Landroid/content/Intent;I)V
    :try_end_0
    .catch Landroid/content/ActivityNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :catch_0
    move-exception v0

    .line 51
    sget-object v2, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    .line 52
    .line 53
    new-array v1, v1, [Ljava/lang/Object;

    .line 54
    .line 55
    const-string v3, "Unable to launch application settings page for location permission request."

    .line 56
    .line 57
    invoke-static {v2, v0, v3, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    .line 65
    .line 66
    new-array v1, v1, [Ljava/lang/Object;

    .line 67
    .line 68
    const-string v2, "Location permission already allowed.  Skipping action from button click."

    .line 69
    .line 70
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->d()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    .line 77
    .line 78
    .line 79
    return-void
.end method

.method private f()V
    .locals 4

    .line 1
    new-instance v0, Landroid/content/Intent;

    .line 2
    .line 3
    const-string v1, "android.settings.APP_NOTIFICATION_SETTINGS"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const-string v2, "android.provider.extra.APP_PACKAGE"

    .line 13
    .line 14
    invoke-virtual {v0, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v1, 0x0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    :try_start_0
    invoke-virtual {p0, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_0
    .catch Landroid/content/ActivityNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catch_0
    move-exception v0

    .line 26
    sget-object v2, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    .line 27
    .line 28
    new-array v1, v1, [Ljava/lang/Object;

    .line 29
    .line 30
    const-string v3, "Unable to handle push settings button action."

    .line 31
    .line 32
    invoke-static {v2, v0, v3, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    .line 37
    .line 38
    new-array v1, v1, [Ljava/lang/Object;

    .line 39
    .line 40
    const-string v2, "Unable to launch notification settings for this device."

    .line 41
    .line 42
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    :goto_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public static bridge synthetic g(Lcom/salesforce/marketingcloud/messages/iam/f;)Lcom/salesforce/marketingcloud/messages/iam/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    return-object p0
.end method

.method private g()V
    .locals 3

    .line 2
    :try_start_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    move-result-object v0

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/k;->q()I

    move-result v0

    if-eqz v0, :cond_0

    .line 3
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object p0

    invoke-virtual {p0, v0}, Landroid/view/Window;->setStatusBarColor(I)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :cond_0
    return-void

    :catch_0
    move-exception p0

    .line 4
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/f;->f:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Failed to find status bar color from meta-data"

    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static bridge synthetic h(Lcom/salesforce/marketingcloud/messages/iam/f;Lcom/salesforce/marketingcloud/messages/iam/j;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->b:Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 2
    .line 3
    return-void
.end method


# virtual methods
.method public a()J
    .locals 2

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    move-result-object p0

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/k;->r()V

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/k;->j()J

    move-result-wide v0

    return-wide v0
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/iam/j;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->b:Lcom/salesforce/marketingcloud/messages/iam/j;

    return-void
.end method

.method public b()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/k;->l()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    move-result-object p0

    return-object p0
.end method

.method public b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V
    .locals 3

    if-eqz p1, :cond_3

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/k;->k()Ljava/util/Date;

    move-result-object v0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->a()J

    move-result-wide v1

    invoke-static {v0, v1, v2, p1}, Lcom/salesforce/marketingcloud/messages/iam/j;->a(Ljava/util/Date;JLcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)Lcom/salesforce/marketingcloud/messages/iam/j;

    move-result-object v0

    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->b:Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/f$b;->a:[I

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x1

    if-eq v0, v1, :cond_2

    const/4 p1, 0x2

    if-eq v0, p1, :cond_1

    const/4 p1, 0x3

    if-eq v0, p1, :cond_0

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    return-void

    .line 5
    :cond_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->e()V

    return-void

    .line 6
    :cond_1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->f()V

    return-void

    .line 7
    :cond_2
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/f;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V

    :cond_3
    return-void
.end method

.method public c()Lcom/salesforce/marketingcloud/messages/iam/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public finish()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->b:Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/messages/iam/k;->a(Lcom/salesforce/marketingcloud/messages/iam/j;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-super {p0}, Landroid/app/Activity;->finish()V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    invoke-virtual {p0, v0, v0}, Landroid/app/Activity;->overridePendingTransition(II)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public onActivityResult(IILandroid/content/Intent;)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3}, Landroidx/fragment/app/o0;->onActivityResult(IILandroid/content/Intent;)V

    .line 2
    .line 3
    .line 4
    const/16 p2, 0x7b

    .line 5
    .line 6
    if-ne p1, p2, :cond_0

    .line 7
    .line 8
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->d()V

    .line 9
    .line 10
    .line 11
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public onClick(Landroid/view/View;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getTag()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getTag()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    instance-of v0, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p1}, Landroid/view/View;->getTag()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    check-cast p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/f;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getTag()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    instance-of p1, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 30
    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 34
    .line 35
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/k;->k()Ljava/util/Date;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->a()J

    .line 40
    .line 41
    .line 42
    move-result-wide v0

    .line 43
    invoke-static {p1, v0, v1}, Lcom/salesforce/marketingcloud/messages/iam/j;->b(Ljava/util/Date;J)Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->b:Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 48
    .line 49
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    .line 50
    .line 51
    .line 52
    :cond_1
    return-void
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroidx/fragment/app/o0;->onCreate(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const-string v1, "messageHandler"

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 21
    .line 22
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 23
    .line 24
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 25
    .line 26
    if-eqz v0, :cond_3

    .line 27
    .line 28
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/k;->h()Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->g()V

    .line 36
    .line 37
    .line 38
    if-eqz p1, :cond_2

    .line 39
    .line 40
    const-string v0, "completedEvent"

    .line 41
    .line 42
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    check-cast p1, Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 47
    .line 48
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->b:Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 49
    .line 50
    :cond_2
    new-instance p1, Lcom/salesforce/marketingcloud/messages/iam/f$a;

    .line 51
    .line 52
    const/4 v0, 0x1

    .line 53
    invoke-direct {p1, p0, v0}, Lcom/salesforce/marketingcloud/messages/iam/f$a;-><init>(Lcom/salesforce/marketingcloud/messages/iam/f;Z)V

    .line 54
    .line 55
    .line 56
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->c:Lb/a0;

    .line 57
    .line 58
    invoke-virtual {p0}, Lb/r;->getOnBackPressedDispatcher()Lb/h0;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->c:Lb/a0;

    .line 63
    .line 64
    invoke-virtual {p1, p0, v0}, Lb/h0;->a(Landroidx/lifecycle/x;Lb/a0;)V

    .line 65
    .line 66
    .line 67
    return-void

    .line 68
    :cond_3
    :goto_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public onDestroy()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->c:Lb/a0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {v0, v1}, Lb/a0;->setEnabled(Z)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->c:Lb/a0;

    .line 10
    .line 11
    invoke-virtual {v0}, Lb/a0;->remove()V

    .line 12
    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->c:Lb/a0;

    .line 16
    .line 17
    :cond_0
    invoke-super {p0}, Landroidx/fragment/app/o0;->onDestroy()V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public onDismissed()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->a:Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/k;->k()Ljava/util/Date;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->a()J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/messages/iam/j;->b(Ljava/util/Date;J)Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->b:Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public onPause()V
    .locals 0

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/o0;->onPause()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/k;->n()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public onRequestPermissionsResult(I[Ljava/lang/String;[I)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3}, Landroidx/fragment/app/o0;->onRequestPermissionsResult(I[Ljava/lang/String;[I)V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->d()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->finish()V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public onResume()V
    .locals 0

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/o0;->onResume()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/f;->c()Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/k;->o()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public onSaveInstanceState(Landroid/os/Bundle;)V
    .locals 1

    .line 1
    invoke-super {p0, p1}, Lb/r;->onSaveInstanceState(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/f;->b:Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 5
    .line 6
    const-string v0, "completedEvent"

    .line 7
    .line 8
    invoke-virtual {p1, v0, p0}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public onSwipeStarted()V
    .locals 0

    .line 1
    return-void
.end method

.method public onViewSettled()V
    .locals 0

    .line 1
    return-void
.end method
