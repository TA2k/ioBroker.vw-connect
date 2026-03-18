.class public Lcom/salesforce/marketingcloud/push/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/b$a;
    }
.end annotation


# static fields
.field public static final c:Lcom/salesforce/marketingcloud/push/b$a;

.field private static final d:Ljava/lang/String;

.field public static final e:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.INTENT_KEY_DATA_NOTIFICATION_MESSAGE"

.field public static final f:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.INTENT_KEY_ANALYTIC_TYPE"

.field public static final g:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.INTENT_KEY_ANALYTIC_CLICKED_ID"

.field public static final h:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.INTENT_KEY_ANALYTIC_TITLE"


# instance fields
.field private final a:Landroid/content/Context;

.field private final b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/b$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/b$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/push/b;->c:Lcom/salesforce/marketingcloud/push/b$a;

    .line 8
    .line 9
    const-string v0, "IntentProvider"

    .line 10
    .line 11
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lcom/salesforce/marketingcloud/push/b;->d:Ljava/lang/String;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "message"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/b;->a:Landroid/content/Context;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/b;->b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 17
    .line 18
    return-void
.end method

.method public static final synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/b;->d:Ljava/lang/String;

    return-object v0
.end method


# virtual methods
.method public final a([Lcom/salesforce/marketingcloud/push/data/a;ILjava/lang/String;Ljava/lang/String;)Landroid/app/PendingIntent;
    .locals 8

    const-string v0, "clickedId"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    if-eqz p1, :cond_b

    .line 2
    invoke-static {p1}, Lkotlin/jvm/internal/m;->j([Ljava/lang/Object;)Landroidx/collection/d1;

    move-result-object p1

    :cond_0
    invoke-virtual {p1}, Landroidx/collection/d1;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_b

    invoke-virtual {p1}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/push/data/a;

    .line 3
    instance-of v2, v1, Lcom/salesforce/marketingcloud/push/data/a$g;

    if-eqz v2, :cond_1

    check-cast v1, Lcom/salesforce/marketingcloud/push/data/a$g;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/a$g;->l()Ljava/lang/String;

    move-result-object v1

    .line 4
    new-instance v2, Llx0/l;

    const-string v3, "url"

    invoke-direct {v2, v1, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_0

    .line 5
    :cond_1
    instance-of v2, v1, Lcom/salesforce/marketingcloud/push/data/a$c;

    if-eqz v2, :cond_2

    check-cast v1, Lcom/salesforce/marketingcloud/push/data/a$c;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/a$c;->l()Ljava/lang/String;

    move-result-object v1

    .line 6
    new-instance v2, Llx0/l;

    const-string v3, "deeplink"

    invoke-direct {v2, v1, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_0

    .line 7
    :cond_2
    instance-of v2, v1, Lcom/salesforce/marketingcloud/push/data/a$a;

    if-eqz v2, :cond_3

    check-cast v1, Lcom/salesforce/marketingcloud/push/data/a$a;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/a$a;->l()Ljava/lang/String;

    move-result-object v1

    .line 8
    new-instance v2, Llx0/l;

    const-string v3, "cloud_page"

    invoke-direct {v2, v1, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_0

    .line 9
    :cond_3
    instance-of v1, v1, Lcom/salesforce/marketingcloud/push/data/a$e;

    if-eqz v1, :cond_4

    .line 10
    new-instance v2, Llx0/l;

    const-string v1, "app_open"

    invoke-direct {v2, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_0

    .line 11
    :cond_4
    new-instance v2, Llx0/l;

    const-string v1, "action"

    invoke-direct {v2, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 12
    :goto_0
    iget-object v1, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 13
    check-cast v1, Ljava/lang/String;

    .line 14
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 15
    check-cast v2, Ljava/lang/String;

    .line 16
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/b;->a:Landroid/content/Context;

    .line 17
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v4

    invoke-virtual {v4}, Ljava/util/UUID;->hashCode()I

    move-result v4

    .line 18
    iget-object v5, p0, Lcom/salesforce/marketingcloud/push/b;->a:Landroid/content/Context;

    invoke-virtual {v5}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v5

    iget-object v6, p0, Lcom/salesforce/marketingcloud/push/b;->a:Landroid/content/Context;

    invoke-virtual {v6}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v5, v6}, Landroid/content/pm/PackageManager;->getLaunchIntentForPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object v5

    const/high16 v6, 0x8000000

    .line 19
    invoke-static {v6}, Lcom/salesforce/marketingcloud/util/j;->a(I)I

    move-result v6

    .line 20
    invoke-static {v3, v4, v5, v6}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object v3

    const-wide/16 v4, 0xbb8

    const-wide/16 v6, 0x32

    .line 21
    invoke-static {v4, v5, v6, v7}, Lcom/salesforce/marketingcloud/util/j;->a(JJ)Z

    move-result v4

    if-eqz v4, :cond_a

    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    move-result-object v4

    if-eqz v4, :cond_a

    .line 22
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    move-result-object v4

    if-eqz v4, :cond_0

    if-eqz v1, :cond_5

    .line 23
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getMarketingCloudConfig()Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    move-result-object p1

    iget-object p1, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    if-eqz p1, :cond_6

    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/b;->a:Landroid/content/Context;

    invoke-interface {p1, v0, v1, v2}, Lcom/salesforce/marketingcloud/UrlHandler;->handleUrl(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Landroid/app/PendingIntent;

    move-result-object v0

    goto :goto_1

    :cond_5
    move-object v0, v3

    :cond_6
    :goto_1
    if-eqz v0, :cond_9

    .line 24
    iget-object p1, p0, Lcom/salesforce/marketingcloud/push/b;->a:Landroid/content/Context;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/b;->b:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 25
    new-instance v1, Landroid/os/Bundle;

    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    .line 26
    const-string v2, "com.salesforce.marketingcloud.notifications.INTENT_KEY_ANALYTIC_TYPE"

    invoke-virtual {v1, v2, p2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 27
    const-string p2, "com.salesforce.marketingcloud.notifications.INTENT_KEY_ANALYTIC_CLICKED_ID"

    invoke-virtual {v1, p2, p3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    if-eqz p4, :cond_7

    .line 28
    const-string p2, "com.salesforce.marketingcloud.notifications.INTENT_KEY_ANALYTIC_TITLE"

    invoke-virtual {v1, p2, p4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    :cond_7
    const/4 p2, 0x1

    .line 29
    invoke-static {p1, v0, p0, p2, v1}, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->redirectIntentForAnalytics(Landroid/content/Context;Landroid/app/PendingIntent;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ZLandroid/os/Bundle;)Landroid/app/PendingIntent;

    move-result-object p0

    if-nez p0, :cond_8

    goto :goto_2

    :cond_8
    return-object p0

    :cond_9
    :goto_2
    return-object v3

    .line 30
    :cond_a
    sget-object p0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object p1, Lcom/salesforce/marketingcloud/push/b;->d:Ljava/lang/String;

    sget-object p2, Lcom/salesforce/marketingcloud/push/b$b;->b:Lcom/salesforce/marketingcloud/push/b$b;

    invoke-virtual {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-object v3

    :cond_b
    return-object v0
.end method
