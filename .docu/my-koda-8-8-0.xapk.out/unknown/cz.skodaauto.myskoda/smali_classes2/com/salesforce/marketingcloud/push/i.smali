.class public final Lcom/salesforce/marketingcloud/push/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lcom/salesforce/marketingcloud/push/i;

.field private static b:Lcom/salesforce/marketingcloud/media/o;

.field private static final c:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/i;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/i;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/push/i;->a:Lcom/salesforce/marketingcloud/push/i;

    .line 7
    .line 8
    const-string v0, "RichFeatureRenderer"

    .line 9
    .line 10
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/push/i;->c:Ljava/lang/String;

    .line 15
    .line 16
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private final a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)I
    .locals 0

    .line 56
    iget-object p0, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    if-nez p0, :cond_1

    iget-object p0, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    if-eqz p0, :cond_0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->getViewTemplate()Lcom/salesforce/marketingcloud/push/data/Template;

    move-result-object p0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    if-nez p0, :cond_1

    .line 57
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_push_custom_button_layout:I

    return p0

    .line 58
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_push_layout:I

    return p0
.end method

.method private final a(Lcom/salesforce/marketingcloud/push/data/RichFeatures;)Z
    .locals 0

    .line 59
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->getViewTemplate()Lcom/salesforce/marketingcloud/push/data/Template;

    move-result-object p0

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public final a(Landroid/graphics/Bitmap;I)Landroid/graphics/Bitmap;
    .locals 6

    const-string p0, "<this>"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result p0

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v0

    sget-object v1, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    invoke-static {p0, v0, v1}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    move-result-object p0

    const-string v0, "createBitmap(...)"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    new-instance v0, Landroid/graphics/Canvas;

    invoke-direct {v0, p0}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 62
    new-instance v1, Landroid/graphics/Paint;

    invoke-direct {v1}, Landroid/graphics/Paint;-><init>()V

    .line 63
    new-instance v2, Landroid/graphics/Rect;

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v3

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v4

    const/4 v5, 0x0

    invoke-direct {v2, v5, v5, v3, v4}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 64
    new-instance v3, Landroid/graphics/RectF;

    invoke-direct {v3, v2}, Landroid/graphics/RectF;-><init>(Landroid/graphics/Rect;)V

    const/4 v4, 0x1

    .line 65
    invoke-virtual {v1, v4}, Landroid/graphics/Paint;->setAntiAlias(Z)V

    .line 66
    invoke-virtual {v0, v5, v5, v5, v5}, Landroid/graphics/Canvas;->drawARGB(IIII)V

    const/4 v4, -0x1

    .line 67
    invoke-virtual {v1, v4}, Landroid/graphics/Paint;->setColor(I)V

    int-to-float p2, p2

    .line 68
    invoke-virtual {v0, v3, p2, p2, v1}, Landroid/graphics/Canvas;->drawRoundRect(Landroid/graphics/RectF;FFLandroid/graphics/Paint;)V

    .line 69
    new-instance p2, Landroid/graphics/PorterDuffXfermode;

    sget-object v3, Landroid/graphics/PorterDuff$Mode;->SRC_IN:Landroid/graphics/PorterDuff$Mode;

    invoke-direct {p2, v3}, Landroid/graphics/PorterDuffXfermode;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    invoke-virtual {v1, p2}, Landroid/graphics/Paint;->setXfermode(Landroid/graphics/Xfermode;)Landroid/graphics/Xfermode;

    .line 70
    invoke-virtual {v0, p1, v2, v2, v1}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;Landroid/graphics/Rect;Landroid/graphics/Rect;Landroid/graphics/Paint;)V

    return-object p0
.end method

.method public final a()Lcom/salesforce/marketingcloud/media/o;
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/push/i;->b:Lcom/salesforce/marketingcloud/media/o;

    return-object p0
.end method

.method public final a(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Landroidx/core/app/x;)V
    .locals 9

    const-string v0, "context"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "message"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "builder"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    new-instance v1, Landroid/widget/RemoteViews;

    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/push/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)I

    move-result v2

    invoke-direct {v1, v0, v2}, Landroid/widget/RemoteViews;-><init>(Ljava/lang/String;I)V

    .line 4
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_alert:I

    const/4 v2, 0x0

    invoke-virtual {v1, v0, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 5
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_alert:I

    iget-object v3, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    invoke-virtual {v1, v0, v3}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 6
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_title:I

    invoke-virtual {v1, v0, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 7
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_title:I

    iget-object v3, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    invoke-virtual {v1, v0, v3}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 8
    iget-object v0, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->getLargeIcon()Ljava/lang/String;

    move-result-object v3

    if-eqz v3, :cond_1

    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/push/i;->a:Lcom/salesforce/marketingcloud/push/i;

    iget-object v4, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    invoke-direct {v0, v4}, Lcom/salesforce/marketingcloud/push/i;->a(Lcom/salesforce/marketingcloud/push/data/RichFeatures;)Z

    move-result v4

    if-eqz v4, :cond_1

    .line 10
    sget v4, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_large_icon:I

    invoke-virtual {v1, v4, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 11
    invoke-static {v3}, Landroid/webkit/URLUtil;->isValidUrl(Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_0

    .line 12
    :try_start_0
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v4

    sget v5, Lcom/salesforce/marketingcloud/R$dimen;->notification_large_icon_width:I

    invoke-virtual {v4, v5}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v4

    .line 13
    sget v5, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_large_icon:I

    .line 14
    sget-object v6, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    invoke-virtual {v6, v3}, Lcom/salesforce/marketingcloud/media/q;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object v6

    invoke-static {v6, v4, v4, v2}, Landroid/graphics/Bitmap;->createScaledBitmap(Landroid/graphics/Bitmap;IIZ)Landroid/graphics/Bitmap;

    move-result-object v4

    const-string v6, "createScaledBitmap(...)"

    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v6

    sget v7, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_carousel_image_radius:I

    invoke-virtual {v6, v7}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v6

    invoke-virtual {v0, v4, v6}, Lcom/salesforce/marketingcloud/push/i;->a(Landroid/graphics/Bitmap;I)Landroid/graphics/Bitmap;

    move-result-object v0

    .line 16
    invoke-virtual {v1, v5, v0}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V
    :try_end_0
    .catch Lcom/salesforce/marketingcloud/push/a; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    .line 17
    sget-object v4, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v5, Lcom/salesforce/marketingcloud/push/i;->c:Ljava/lang/String;

    new-instance v6, Lcom/salesforce/marketingcloud/push/i$a;

    invoke-direct {v6, v3}, Lcom/salesforce/marketingcloud/push/i$a;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v5, v0, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    goto :goto_0

    .line 18
    :cond_0
    sget v4, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_large_icon:I

    .line 19
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v5

    .line 20
    sget-object v6, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    invoke-virtual {v6, p1, v3}, Lcom/salesforce/marketingcloud/media/q;->a(Landroid/content/Context;Ljava/lang/String;)I

    move-result v3

    .line 21
    invoke-static {v5, v3}, Landroid/graphics/BitmapFactory;->decodeResource(Landroid/content/res/Resources;I)Landroid/graphics/Bitmap;

    move-result-object v3

    const-string v5, "decodeResource(...)"

    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v5

    sget v6, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_carousel_image_radius:I

    invoke-virtual {v5, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v5

    invoke-virtual {v0, v3, v5}, Lcom/salesforce/marketingcloud/push/i;->a(Landroid/graphics/Bitmap;I)Landroid/graphics/Bitmap;

    move-result-object v0

    .line 23
    invoke-virtual {v1, v4, v0}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V

    .line 24
    :cond_1
    :goto_0
    iget-object v0, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    if-eqz v0, :cond_4

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_2

    goto/16 :goto_3

    .line 25
    :cond_2
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_big_image:I

    invoke-virtual {v1, v0, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 26
    iget-object v2, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    .line 27
    :try_start_1
    sget-object v0, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    iget-object v3, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    invoke-virtual {v0, v3}, Lcom/salesforce/marketingcloud/media/q;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object v0

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    sget v4, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_carousel_image_radius:I

    invoke-virtual {v3, v4}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v3

    invoke-virtual {p0, v0, v3}, Lcom/salesforce/marketingcloud/push/i;->a(Landroid/graphics/Bitmap;I)Landroid/graphics/Bitmap;

    move-result-object p0

    .line 28
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_big_image:I

    invoke-virtual {v1, v0, p0}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V

    .line 29
    new-instance v0, Landroidx/core/app/u;

    .line 30
    invoke-direct {v0}, Landroidx/core/app/a0;-><init>()V

    const/4 v3, 0x1

    if-nez p0, :cond_3

    const/4 p0, 0x0

    goto :goto_1

    .line 31
    :cond_3
    new-instance v4, Landroidx/core/graphics/drawable/IconCompat;

    invoke-direct {v4, v3}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 32
    iput-object p0, v4, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    move-object p0, v4

    .line 33
    :goto_1
    iput-object p0, v0, Landroidx/core/app/u;->e:Landroidx/core/graphics/drawable/IconCompat;

    .line 34
    invoke-static {v2}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p0

    iput-object p0, v0, Landroidx/core/app/a0;->d:Ljava/lang/Object;

    .line 35
    iput-boolean v3, v0, Landroidx/core/app/a0;->a:Z

    .line 36
    invoke-virtual {p3, v0}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V
    :try_end_1
    .catch Lcom/salesforce/marketingcloud/push/a; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 37
    invoke-virtual {p3, v2}, Landroidx/core/app/x;->c(Ljava/lang/CharSequence;)V

    .line 38
    invoke-virtual {p3, v2}, Landroidx/core/app/x;->g(Ljava/lang/CharSequence;)V

    goto :goto_3

    :catchall_0
    move-exception v0

    move-object p0, v0

    goto :goto_2

    :catch_1
    move-exception v0

    move-object p0, v0

    .line 39
    :try_start_2
    sget-object v0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v3, Lcom/salesforce/marketingcloud/push/i;->c:Ljava/lang/String;

    new-instance v4, Lcom/salesforce/marketingcloud/push/i$b;

    invoke-direct {v4, p2}, Lcom/salesforce/marketingcloud/push/i$b;-><init>(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    invoke-virtual {v0, v3, p0, v4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 40
    iget-object v2, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 41
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_big_image:I

    const/16 v0, 0x8

    invoke-virtual {v1, p0, v0}, Landroid/widget/RemoteViews;->setViewVisibility(II)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 42
    invoke-virtual {p3, v2}, Landroidx/core/app/x;->c(Ljava/lang/CharSequence;)V

    .line 43
    invoke-virtual {p3, v2}, Landroidx/core/app/x;->g(Ljava/lang/CharSequence;)V

    goto :goto_3

    .line 44
    :goto_2
    invoke-virtual {p3, v2}, Landroidx/core/app/x;->c(Ljava/lang/CharSequence;)V

    .line 45
    invoke-virtual {p3, v2}, Landroidx/core/app/x;->g(Ljava/lang/CharSequence;)V

    throw p0

    .line 46
    :cond_4
    :goto_3
    iget-object p0, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    if-eqz p0, :cond_7

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->getButtons()Lcom/salesforce/marketingcloud/push/buttons/a;

    move-result-object p0

    if-eqz p0, :cond_7

    .line 47
    sget-object v0, Lcom/salesforce/marketingcloud/push/buttons/a;->f:Lcom/salesforce/marketingcloud/push/buttons/a$a;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/push/buttons/a$a;->a(Lcom/salesforce/marketingcloud/push/buttons/a;)Z

    move-result v0

    if-nez v0, :cond_5

    .line 48
    sget-object v2, Lcom/salesforce/marketingcloud/push/k$a;->a:Lcom/salesforce/marketingcloud/push/k$a$a;

    sget-object v3, Lcom/salesforce/marketingcloud/push/data/Template$Type;->RichButtons:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    const/16 v7, 0x8

    const/4 v8, 0x0

    const/4 v6, 0x0

    move-object v4, p1

    move-object v5, p2

    invoke-static/range {v2 .. v8}, Lcom/salesforce/marketingcloud/push/k$a$a;->a(Lcom/salesforce/marketingcloud/push/k$a$a;Lcom/salesforce/marketingcloud/push/data/Template$Type;Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/media/o;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/k;

    move-result-object p1

    invoke-interface {p1, v1, p0}, Lcom/salesforce/marketingcloud/push/k;->a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/data/Template;)Landroid/widget/RemoteViews;

    move-result-object p0

    .line 49
    iput-object p0, p3, Landroidx/core/app/x;->t:Landroid/widget/RemoteViews;

    goto :goto_4

    :cond_5
    move-object v4, p1

    move-object v5, p2

    move-object p0, v1

    :goto_4
    if-nez p0, :cond_6

    goto :goto_5

    :cond_6
    move-object v1, p0

    goto :goto_5

    :cond_7
    move-object v4, p1

    move-object v5, p2

    .line 50
    :goto_5
    iget-object p0, v5, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    if-eqz p0, :cond_8

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->getViewTemplate()Lcom/salesforce/marketingcloud/push/data/Template;

    move-result-object p0

    if-eqz p0, :cond_8

    .line 51
    new-instance p1, Landroidx/core/app/u;

    .line 52
    invoke-direct {p1}, Landroidx/core/app/a0;-><init>()V

    .line 53
    invoke-virtual {p3, p1}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V

    .line 54
    sget-object p1, Lcom/salesforce/marketingcloud/push/k$a;->a:Lcom/salesforce/marketingcloud/push/k$a$a;

    invoke-interface {p0}, Lcom/salesforce/marketingcloud/push/data/Template;->f()Lcom/salesforce/marketingcloud/push/data/Template$Type;

    move-result-object p2

    sget-object v0, Lcom/salesforce/marketingcloud/push/i;->b:Lcom/salesforce/marketingcloud/media/o;

    invoke-virtual {p1, p2, v4, v5, v0}, Lcom/salesforce/marketingcloud/push/k$a$a;->a(Lcom/salesforce/marketingcloud/push/data/Template$Type;Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/media/o;)Lcom/salesforce/marketingcloud/push/k;

    move-result-object p1

    invoke-interface {p1, v1, p0}, Lcom/salesforce/marketingcloud/push/k;->a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/data/Template;)Landroid/widget/RemoteViews;

    move-result-object p0

    .line 55
    iput-object p0, p3, Landroidx/core/app/x;->t:Landroid/widget/RemoteViews;

    :cond_8
    return-void
.end method

.method public final a(Lcom/salesforce/marketingcloud/media/o;)V
    .locals 0

    .line 2
    sput-object p1, Lcom/salesforce/marketingcloud/push/i;->b:Lcom/salesforce/marketingcloud/media/o;

    return-void
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/push/i;->c:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
