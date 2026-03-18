.class Lcom/salesforce/marketingcloud/notifications/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;


# instance fields
.field final a:I

.field private final b:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;

.field private final c:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;

.field private final d:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;


# direct methods
.method public constructor <init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lcom/salesforce/marketingcloud/notifications/b;->b:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;

    .line 5
    .line 6
    iput-object p3, p0, Lcom/salesforce/marketingcloud/notifications/b;->c:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;

    .line 7
    .line 8
    iput-object p4, p0, Lcom/salesforce/marketingcloud/notifications/b;->d:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;

    .line 9
    .line 10
    iput p1, p0, Lcom/salesforce/marketingcloud/notifications/b;->a:I

    .line 11
    .line 12
    return-void
.end method

.method private static a(Ljava/lang/String;)Landroid/graphics/Bitmap;
    .locals 6

    .line 80
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    const-string v1, "Fetching Large Icon: "

    .line 81
    invoke-static {v1, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x0

    .line 82
    new-array v3, v2, [Ljava/lang/Object;

    invoke-static {v0, v1, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 83
    sget-object v1, Lcom/salesforce/marketingcloud/push/i;->a:Lcom/salesforce/marketingcloud/push/i;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/i;->a()Lcom/salesforce/marketingcloud/media/o;

    move-result-object v1

    .line 84
    const-string v3, "\n"

    .line 85
    invoke-static {p0, v3}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    if-eqz v1, :cond_0

    .line 86
    invoke-virtual {v1, v3}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object v4

    if-eqz v4, :cond_0

    .line 87
    new-array p0, v2, [Ljava/lang/Object;

    const-string v1, "Large Icon found in cache. Returning cached bitmap."

    invoke-static {v0, v1, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v4

    .line 88
    :cond_0
    const-string v4, "Downloading Large Icon from network: "

    .line 89
    invoke-static {v4, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    .line 90
    new-array v5, v2, [Ljava/lang/Object;

    invoke-static {v0, v4, v5}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 91
    sget-object v4, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    invoke-virtual {v4, p0}, Lcom/salesforce/marketingcloud/media/q;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object p0

    if-eqz v1, :cond_1

    .line 92
    new-array v2, v2, [Ljava/lang/Object;

    const-string v4, "Updating memory cache with downloaded Large Icon."

    invoke-static {v0, v4, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 93
    invoke-virtual {v1, v3, p0}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/lang/String;Landroid/graphics/Bitmap;)V

    return-object p0

    .line 94
    :cond_1
    new-array v1, v2, [Ljava/lang/Object;

    const-string v2, "ImageHandler is null. Unable to cache the downloaded image."

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object p0
.end method

.method public static a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Ljava/lang/String;I)Landroidx/core/app/x;
    .locals 10

    .line 1
    new-instance v0, Landroidx/core/app/x;

    invoke-direct {v0, p0, p2}, Landroidx/core/app/x;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    move-result-object p2

    iget p2, p2, Landroid/content/pm/ApplicationInfo;->icon:I

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-lez p2, :cond_1

    .line 3
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p2

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    move-result-object v3

    iget v3, v3, Landroid/content/pm/ApplicationInfo;->icon:I

    invoke-static {p2, v3}, Landroid/graphics/BitmapFactory;->decodeResource(Landroid/content/res/Resources;I)Landroid/graphics/Bitmap;

    move-result-object p2

    if-nez p2, :cond_0

    move-object v3, v1

    goto :goto_0

    .line 4
    :cond_0
    new-instance v3, Landroidx/core/graphics/drawable/IconCompat;

    invoke-direct {v3, v2}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 5
    iput-object p2, v3, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 6
    :goto_0
    iput-object v3, v0, Landroidx/core/app/x;->h:Landroidx/core/graphics/drawable/IconCompat;

    :cond_1
    if-lez p3, :cond_2

    .line 7
    iget-object p2, v0, Landroidx/core/app/x;->y:Landroid/app/Notification;

    iput p3, p2, Landroid/app/Notification;->icon:I

    .line 8
    :cond_2
    iget-object p2, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    if-eqz p2, :cond_3

    .line 9
    invoke-static {p2}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p2

    iput-object p2, v0, Landroidx/core/app/x;->e:Ljava/lang/CharSequence;

    .line 10
    :cond_3
    iget-object p2, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    const/4 p3, 0x0

    .line 11
    :try_start_0
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_5

    .line 12
    sget-object v3, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    iget-object v4, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    invoke-virtual {v3, v4}, Lcom/salesforce/marketingcloud/media/q;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object v3

    .line 13
    new-instance v4, Landroidx/core/app/u;

    .line 14
    invoke-direct {v4}, Landroidx/core/app/a0;-><init>()V

    if-nez v3, :cond_4

    move-object v5, v1

    goto :goto_1

    .line 15
    :cond_4
    new-instance v5, Landroidx/core/graphics/drawable/IconCompat;

    invoke-direct {v5, v2}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 16
    iput-object v3, v5, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 17
    :goto_1
    iput-object v5, v4, Landroidx/core/app/u;->e:Landroidx/core/graphics/drawable/IconCompat;

    .line 18
    invoke-static {p2}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object v3

    iput-object v3, v4, Landroidx/core/app/a0;->d:Ljava/lang/Object;

    .line 19
    iput-boolean v2, v4, Landroidx/core/app/a0;->a:Z

    .line 20
    invoke-virtual {v0, v4}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V
    :try_end_0
    .catch Lcom/salesforce/marketingcloud/push/a; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move v3, v2

    goto :goto_5

    :catchall_0
    move-exception p0

    goto/16 :goto_c

    :catch_0
    move-exception v3

    goto :goto_3

    :cond_5
    :goto_2
    move v3, p3

    goto :goto_5

    .line 21
    :goto_3
    :try_start_1
    sget-object v4, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    const-string v5, "Unable to load notification image %s"

    iget-object v6, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    filled-new-array {v6}, [Ljava/lang/Object;

    move-result-object v6

    invoke-static {v4, v3, v5, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 22
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    if-eqz v3, :cond_6

    invoke-static {v3}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    move-result v3

    if-lez v3, :cond_6

    .line 23
    iget-object p2, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 24
    const-string v3, "Using mediaAltText as alert text"

    new-array v5, p3, [Ljava/lang/Object;

    invoke-static {v4, v3, v5}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_4

    .line 25
    :cond_6
    const-string v3, "mediaAltText is null or blank, keep original alert text"

    new-array v5, p3, [Ljava/lang/Object;

    invoke-static {v4, v3, v5}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    :goto_4
    new-instance v3, Landroidx/core/app/v;

    .line 27
    invoke-direct {v3}, Landroidx/core/app/a0;-><init>()V

    .line 28
    invoke-static {p2}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object v4

    iput-object v4, v3, Landroidx/core/app/v;->e:Ljava/lang/CharSequence;

    .line 29
    iget-object v4, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 30
    invoke-static {v4}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object v4

    iput-object v4, v3, Landroidx/core/app/a0;->c:Ljava/lang/Object;

    .line 31
    invoke-virtual {v0, v3}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_2

    .line 32
    :goto_5
    invoke-virtual {v0, p2}, Landroidx/core/app/x;->c(Ljava/lang/CharSequence;)V

    .line 33
    invoke-virtual {v0, p2}, Landroidx/core/app/x;->g(Ljava/lang/CharSequence;)V

    const/16 v4, 0x8

    .line 34
    invoke-virtual {v0, v4, v2}, Landroidx/core/app/x;->d(IZ)V

    const/16 v4, 0x10

    .line 35
    invoke-virtual {v0, v4, v2}, Landroidx/core/app/x;->d(IZ)V

    .line 36
    iget-object v4, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    if-eqz v4, :cond_d

    .line 37
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->getLargeIcon()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_a

    .line 38
    invoke-static {p2}, Landroid/webkit/URLUtil;->isValidUrl(Ljava/lang/String;)Z

    move-result v3

    if-eqz v3, :cond_8

    .line 39
    :try_start_2
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    sget v5, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_large_icon_size:I

    invoke-virtual {v3, v5}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v3

    .line 40
    invoke-static {p2}, Lcom/salesforce/marketingcloud/notifications/b;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object v5

    invoke-static {v5, v3, v3, p3}, Landroid/graphics/Bitmap;->createScaledBitmap(Landroid/graphics/Bitmap;IIZ)Landroid/graphics/Bitmap;

    move-result-object v3

    if-nez v3, :cond_7

    move-object v5, v1

    goto :goto_6

    .line 41
    :cond_7
    new-instance v5, Landroidx/core/graphics/drawable/IconCompat;

    invoke-direct {v5, v2}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 42
    iput-object v3, v5, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 43
    :goto_6
    iput-object v5, v0, Landroidx/core/app/x;->h:Landroidx/core/graphics/drawable/IconCompat;
    :try_end_2
    .catch Lcom/salesforce/marketingcloud/push/a; {:try_start_2 .. :try_end_2} :catch_1

    goto :goto_8

    :catch_1
    move-exception v3

    .line 44
    sget-object v5, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string v6, "Unable to load notification large icon: %s"

    invoke-static {v5, v3, v6, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_8

    .line 45
    :cond_8
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    sget-object v5, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    .line 46
    invoke-virtual {v5, p0, p2}, Lcom/salesforce/marketingcloud/media/q;->a(Landroid/content/Context;Ljava/lang/String;)I

    move-result p2

    .line 47
    invoke-static {v3, p2}, Landroid/graphics/BitmapFactory;->decodeResource(Landroid/content/res/Resources;I)Landroid/graphics/Bitmap;

    move-result-object p2

    if-nez p2, :cond_9

    move-object v3, v1

    goto :goto_7

    .line 48
    :cond_9
    new-instance v3, Landroidx/core/graphics/drawable/IconCompat;

    invoke-direct {v3, v2}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 49
    iput-object p2, v3, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 50
    :goto_7
    iput-object v3, v0, Landroidx/core/app/x;->h:Landroidx/core/graphics/drawable/IconCompat;

    .line 51
    :cond_a
    :goto_8
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->getSmallIcon()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_b

    .line 52
    sget-object v3, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    invoke-virtual {v3, p0, p2}, Lcom/salesforce/marketingcloud/media/q;->a(Landroid/content/Context;Ljava/lang/String;)I

    move-result p2

    .line 53
    iget-object v3, v0, Landroidx/core/app/x;->y:Landroid/app/Notification;

    iput p2, v3, Landroid/app/Notification;->icon:I

    .line 54
    :cond_b
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->getButtons()Lcom/salesforce/marketingcloud/push/buttons/a;

    move-result-object p2

    if-eqz p2, :cond_c

    .line 55
    invoke-static {p2}, Lcom/salesforce/marketingcloud/push/buttons/a;->a(Lcom/salesforce/marketingcloud/push/buttons/a;)Z

    move-result v3

    if-eqz v3, :cond_c

    .line 56
    new-instance v3, Lcom/salesforce/marketingcloud/push/b;

    invoke-direct {v3, p0, p1}, Lcom/salesforce/marketingcloud/push/b;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 57
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/buttons/a;->k()Ljava/util/List;

    move-result-object p2

    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_9
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_c

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lcom/salesforce/marketingcloud/push/buttons/a$c;

    .line 58
    new-instance v5, Landroidx/core/app/r;

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->p()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v6

    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/push/data/c;->n()Ljava/lang/String;

    move-result-object v6

    .line 59
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->h()Ljava/util/List;

    move-result-object v7

    new-array v8, p3, [Lcom/salesforce/marketingcloud/push/data/a;

    invoke-interface {v7, v8}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v7

    check-cast v7, [Lcom/salesforce/marketingcloud/push/data/a;

    .line 60
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->d()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->p()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v4

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/push/data/c;->n()Ljava/lang/String;

    move-result-object v4

    const/16 v9, 0x6f

    .line 61
    invoke-virtual {v3, v7, v9, v8, v4}, Lcom/salesforce/marketingcloud/push/b;->a([Lcom/salesforce/marketingcloud/push/data/a;ILjava/lang/String;Ljava/lang/String;)Landroid/app/PendingIntent;

    move-result-object v4

    invoke-direct {v5, p3, v6, v4}, Landroidx/core/app/r;-><init>(ILjava/lang/CharSequence;Landroid/app/PendingIntent;)V

    .line 62
    iget-object v4, v0, Landroidx/core/app/x;->b:Ljava/util/ArrayList;

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_9

    .line 63
    :cond_c
    sget-object p2, Lcom/salesforce/marketingcloud/push/i;->a:Lcom/salesforce/marketingcloud/push/i;

    invoke-virtual {p2, p0, p1, v0}, Lcom/salesforce/marketingcloud/push/i;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Landroidx/core/app/x;)V

    goto :goto_a

    :cond_d
    if-nez v3, :cond_e

    .line 64
    new-instance v3, Landroidx/core/app/v;

    .line 65
    invoke-direct {v3}, Landroidx/core/app/a0;-><init>()V

    .line 66
    invoke-static {p2}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p2

    iput-object p2, v3, Landroidx/core/app/v;->e:Ljava/lang/CharSequence;

    .line 67
    iget-object p2, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 68
    invoke-static {p2}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p2

    iput-object p2, v3, Landroidx/core/app/a0;->c:Ljava/lang/Object;

    .line 69
    invoke-virtual {v0, v3}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V

    .line 70
    :cond_e
    :goto_a
    sget-object p2, Lcom/salesforce/marketingcloud/notifications/b$a;->a:[I

    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    move-result v3

    aget p2, p2, v3

    if-eq p2, v2, :cond_11

    const/4 p0, 0x2

    if-eq p2, p0, :cond_10

    const/4 p0, 0x3

    if-eq p2, p0, :cond_f

    goto :goto_b

    .line 71
    :cond_f
    invoke-virtual {v0, v1}, Landroidx/core/app/x;->e(Landroid/net/Uri;)V

    .line 72
    sget-object p0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    new-array p1, p3, [Ljava/lang/Object;

    const-string p2, "No sound was set for notification."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_b

    .line 73
    :cond_10
    sget-object p0, Landroid/provider/Settings$System;->DEFAULT_NOTIFICATION_URI:Landroid/net/Uri;

    invoke-virtual {v0, p0}, Landroidx/core/app/x;->e(Landroid/net/Uri;)V

    goto :goto_b

    .line 74
    :cond_11
    iget-object p1, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    if-eqz p1, :cond_12

    .line 75
    sget-object p2, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    sget-object p3, Landroid/provider/Settings$System;->DEFAULT_NOTIFICATION_URI:Landroid/net/Uri;

    invoke-virtual {p2, p0, p1, p3}, Lcom/salesforce/marketingcloud/media/q;->a(Landroid/content/Context;Ljava/lang/String;Landroid/net/Uri;)Landroid/net/Uri;

    move-result-object p0

    invoke-virtual {v0, p0}, Landroidx/core/app/x;->e(Landroid/net/Uri;)V

    goto :goto_b

    .line 76
    :cond_12
    invoke-virtual {v0, v1}, Landroidx/core/app/x;->e(Landroid/net/Uri;)V

    :goto_b
    return-object v0

    .line 77
    :goto_c
    invoke-virtual {v0, p2}, Landroidx/core/app/x;->c(Ljava/lang/CharSequence;)V

    .line 78
    invoke-virtual {v0, p2}, Landroidx/core/app/x;->g(Ljava/lang/CharSequence;)V

    .line 79
    throw p0
.end method

.method public static a(Landroid/content/Context;Z)Ljava/lang/String;
    .locals 3

    .line 108
    invoke-static {}, Lcom/salesforce/marketingcloud/util/j;->c()Z

    move-result v0

    const-string v1, "com.salesforce.marketingcloud.DEFAULT_FOREGROUND_CHANNEL"

    if-eqz v0, :cond_1

    .line 109
    const-string v0, "notification"

    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/NotificationManager;

    if-eqz v0, :cond_1

    .line 110
    invoke-virtual {v0, v1}, Landroid/app/NotificationManager;->getNotificationChannel(Ljava/lang/String;)Landroid/app/NotificationChannel;

    move-result-object v2

    if-eqz v2, :cond_0

    if-eqz p1, :cond_1

    .line 111
    :cond_0
    new-instance p1, Landroid/app/NotificationChannel;

    sget v2, Lcom/salesforce/marketingcloud/R$string;->mcsdk_foreground_notification_channel_name:I

    .line 112
    invoke-virtual {p0, v2}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p0

    const/4 v2, 0x3

    invoke-direct {p1, v1, p0, v2}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    const/4 p0, 0x0

    .line 113
    invoke-virtual {p1, p0}, Landroid/app/NotificationChannel;->enableLights(Z)V

    .line 114
    invoke-virtual {p1, p0}, Landroid/app/NotificationChannel;->enableVibration(Z)V

    .line 115
    invoke-virtual {p1, p0}, Landroid/app/NotificationChannel;->setShowBadge(Z)V

    const/4 v2, 0x0

    .line 116
    invoke-virtual {p1, v2, v2}, Landroid/app/NotificationChannel;->setSound(Landroid/net/Uri;Landroid/media/AudioAttributes;)V

    .line 117
    invoke-virtual {p1, p0}, Landroid/app/NotificationChannel;->setLockscreenVisibility(I)V

    .line 118
    invoke-virtual {v0, p1}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    :cond_1
    return-object v1
.end method

.method public static b(Landroid/content/Context;Z)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/util/j;->c()Z

    move-result v0

    const-string v1, "com.salesforce.marketingcloud.DEFAULT_CHANNEL"

    if-eqz v0, :cond_1

    .line 2
    const-string v0, "notification"

    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/NotificationManager;

    if-eqz v0, :cond_1

    .line 3
    invoke-virtual {v0, v1}, Landroid/app/NotificationManager;->getNotificationChannel(Ljava/lang/String;)Landroid/app/NotificationChannel;

    move-result-object v2

    if-eqz v2, :cond_0

    if-eqz p1, :cond_1

    .line 4
    :cond_0
    new-instance p1, Landroid/app/NotificationChannel;

    sget v2, Lcom/salesforce/marketingcloud/R$string;->mcsdk_default_notification_channel_name:I

    .line 5
    invoke-virtual {p0, v2}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p0

    const/4 v2, 0x3

    invoke-direct {p1, v1, p0, v2}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    const/4 p0, 0x0

    .line 6
    invoke-virtual {p1, p0}, Landroid/app/NotificationChannel;->enableLights(Z)V

    .line 7
    invoke-virtual {p1, p0}, Landroid/app/NotificationChannel;->enableVibration(Z)V

    const/4 v2, 0x1

    .line 8
    invoke-virtual {p1, v2}, Landroid/app/NotificationChannel;->setShowBadge(Z)V

    .line 9
    invoke-virtual {p1, p0}, Landroid/app/NotificationChannel;->setLockscreenVisibility(I)V

    .line 10
    invoke-virtual {v0, p1}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    :cond_1
    return-object v1
.end method


# virtual methods
.method public a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Ljava/lang/String;
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "NewApi"
        }
    .end annotation

    .line 119
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/b;->d:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;

    const/4 v0, 0x0

    if-eqz p0, :cond_0

    .line 120
    :try_start_0
    invoke-interface {p0, p1, p2}, Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;->getNotificationChannelId(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Ljava/lang/String;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p0

    .line 121
    sget-object p2, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    new-array v1, v0, [Ljava/lang/Object;

    const-string v2, "Exception thrown while app determined channel id for notification message."

    invoke-static {p2, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    const/4 p0, 0x0

    :goto_0
    if-nez p0, :cond_1

    .line 122
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/notifications/b;->a(Landroid/content/Context;Z)Ljava/lang/String;

    .line 123
    const-string p0, "com.salesforce.marketingcloud.DEFAULT_FOREGROUND_CHANNEL"

    :cond_1
    return-object p0
.end method

.method public b(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Ljava/lang/String;
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "NewApi"
        }
    .end annotation

    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/b;->d:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;

    const/4 v0, 0x0

    if-eqz p0, :cond_0

    .line 12
    :try_start_0
    invoke-interface {p0, p1, p2}, Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;->getNotificationChannelId(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Ljava/lang/String;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p0

    .line 13
    sget-object p2, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    new-array v1, v0, [Ljava/lang/Object;

    const-string v2, "Exception thrown while app determined channel id for notification message."

    invoke-static {p2, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    const/4 p0, 0x0

    :goto_0
    if-nez p0, :cond_1

    .line 14
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/notifications/b;->b(Landroid/content/Context;Z)Ljava/lang/String;

    .line 15
    const-string p0, "com.salesforce.marketingcloud.DEFAULT_CHANNEL"

    :cond_1
    return-object p0
.end method

.method public c(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroid/app/PendingIntent;
    .locals 3

    .line 1
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/b;->b:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0, p1, p2}, Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;->getNotificationPendingIntent(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroid/app/PendingIntent;

    .line 6
    .line 7
    .line 8
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    return-object p0

    .line 10
    :catch_0
    move-exception p0

    .line 11
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    new-array v1, v1, [Ljava/lang/Object;

    .line 15
    .line 16
    const-string v2, "Missing FLAG_IMMUTABLE or FLAG_MUTABLE flag in PendingIntent"

    .line 17
    .line 18
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    const/high16 p0, 0x8000000

    .line 22
    .line 23
    invoke-static {p0}, Lcom/salesforce/marketingcloud/util/j;->a(I)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-virtual {v1, v2}, Landroid/content/pm/PackageManager;->getLaunchIntentForPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    if-eqz v1, :cond_1

    .line 40
    .line 41
    invoke-static {v1, p2}, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->a(Landroid/content/Intent;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroid/content/Intent;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v1, p0}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    invoke-static {p1, p0, v1, v0}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :cond_1
    const/4 p0, 0x0

    .line 58
    return-object p0
.end method

.method public setupNotificationBuilder(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroidx/core/app/x;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/b;->c:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    invoke-interface {v0, p1, p2}, Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;->setupNotificationBuilder(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroidx/core/app/x;

    .line 6
    .line 7
    .line 8
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    goto :goto_0

    .line 10
    :catch_0
    move-exception v0

    .line 11
    sget-object v1, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->d:Ljava/lang/String;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    new-array v2, v2, [Ljava/lang/Object;

    .line 15
    .line 16
    const-string v3, "Custom notification builder threw an exception.  Using default notification builder."

    .line 17
    .line 18
    invoke-static {v1, v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    const/4 v0, 0x0

    .line 22
    :goto_0
    if-nez v0, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/notifications/b;->b(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    iget v1, p0, Lcom/salesforce/marketingcloud/notifications/b;->a:I

    .line 29
    .line 30
    invoke-static {p1, p2, v0, v1}, Lcom/salesforce/marketingcloud/notifications/b;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Ljava/lang/String;I)Landroidx/core/app/x;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/notifications/b;->c(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroid/app/PendingIntent;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    const/4 v1, 0x1

    .line 41
    invoke-static {p1, p0, p2, v1}, Lcom/salesforce/marketingcloud/notifications/NotificationManager;->redirectIntentForAnalytics(Landroid/content/Context;Landroid/app/PendingIntent;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)Landroid/app/PendingIntent;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    iput-object p0, v0, Landroidx/core/app/x;->g:Landroid/app/PendingIntent;

    .line 46
    .line 47
    :cond_1
    return-object v0
.end method
