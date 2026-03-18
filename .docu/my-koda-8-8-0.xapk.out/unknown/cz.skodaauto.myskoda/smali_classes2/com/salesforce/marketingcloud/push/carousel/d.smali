.class public final Lcom/salesforce/marketingcloud/push/carousel/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/push/k;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lcom/salesforce/marketingcloud/push/k<",
        "Lcom/salesforce/marketingcloud/push/carousel/a;",
        ">;"
    }
.end annotation


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/push/carousel/b;

.field private final b:Landroid/content/Context;

.field private final c:Lcom/salesforce/marketingcloud/media/o;

.field private final d:Ljava/lang/String;

.field private final e:Lcom/salesforce/marketingcloud/push/style/a$b;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/push/carousel/b;Landroid/content/Context;Lcom/salesforce/marketingcloud/media/o;)V
    .locals 1

    .line 1
    const-string v0, "intentProvider"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "context"

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
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->a:Lcom/salesforce/marketingcloud/push/carousel/b;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    .line 17
    .line 18
    iput-object p3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->c:Lcom/salesforce/marketingcloud/media/o;

    .line 19
    .line 20
    const-string p1, "CarouselRenderer"

    .line 21
    .line 22
    invoke-static {p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    .line 27
    .line 28
    new-instance p1, Lcom/salesforce/marketingcloud/push/style/a$b;

    .line 29
    .line 30
    invoke-direct {p1, p2}, Lcom/salesforce/marketingcloud/push/style/a$b;-><init>(Landroid/content/Context;)V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->e:Lcom/salesforce/marketingcloud/push/style/a$b;

    .line 34
    .line 35
    return-void
.end method

.method private final a()I
    .locals 8

    .line 82
    new-instance v0, Lkotlin/jvm/internal/d0;

    .line 83
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 84
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v1

    invoke-virtual {v1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v1

    .line 85
    sget-object v2, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v5, Lcom/salesforce/marketingcloud/push/carousel/d$i;

    invoke-direct {v5, v1}, Lcom/salesforce/marketingcloud/push/carousel/d$i;-><init>(Landroid/util/DisplayMetrics;)V

    const/4 v6, 0x2

    const/4 v7, 0x0

    const/4 v4, 0x0

    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 86
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v5, Lcom/salesforce/marketingcloud/push/carousel/d$j;

    invoke-direct {v5, v1}, Lcom/salesforce/marketingcloud/push/carousel/d$j;-><init>(Landroid/util/DisplayMetrics;)V

    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 87
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v4, 0x1f

    if-lt v3, v4, :cond_0

    .line 88
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    sget v4, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_android_notification_padding:I

    invoke-virtual {v3, v4}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v3

    mul-int/lit8 v3, v3, 0x2

    .line 89
    iget-object v4, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v4

    sget v5, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_android_notification_margin:I

    invoke-virtual {v4, v5}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v4

    add-int/2addr v4, v3

    .line 90
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    sget v5, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_android_notification_pillar_margin:I

    invoke-virtual {v3, v5}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v3

    add-int/2addr v3, v4

    .line 91
    iput v3, v0, Lkotlin/jvm/internal/d0;->d:I

    .line 92
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v5, Lcom/salesforce/marketingcloud/push/carousel/d$k;

    invoke-direct {v5, v0}, Lcom/salesforce/marketingcloud/push/carousel/d$k;-><init>(Lkotlin/jvm/internal/d0;)V

    const/4 v6, 0x2

    const/4 v7, 0x0

    const/4 v4, 0x0

    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    goto :goto_0

    .line 93
    :cond_0
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    sget v4, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_android_notification_padding:I

    invoke-virtual {v3, v4}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v3

    mul-int/lit8 v3, v3, 0x2

    .line 94
    iput v3, v0, Lkotlin/jvm/internal/d0;->d:I

    .line 95
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v5, Lcom/salesforce/marketingcloud/push/carousel/d$l;

    invoke-direct {v5, v0}, Lcom/salesforce/marketingcloud/push/carousel/d$l;-><init>(Lkotlin/jvm/internal/d0;)V

    const/4 v6, 0x2

    const/4 v7, 0x0

    const/4 v4, 0x0

    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 96
    :goto_0
    iget p0, v1, Landroid/util/DisplayMetrics;->widthPixels:I

    iget v0, v0, Lkotlin/jvm/internal/d0;->d:I

    sub-int/2addr p0, v0

    rem-int/lit8 v0, p0, 0x2

    sub-int/2addr p0, v0

    return p0
.end method

.method public static final synthetic a(Lcom/salesforce/marketingcloud/push/carousel/d;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    return-object p0
.end method

.method private final a(Lcom/salesforce/marketingcloud/push/carousel/a$a;Landroid/widget/RemoteViews;)V
    .locals 2

    .line 3
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_image:I

    const/16 v0, 0x8

    invoke-virtual {p2, p0, v0}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->p()Lcom/salesforce/marketingcloud/push/data/b;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/b;->n()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object p0

    const/4 p1, 0x0

    if-eqz p0, :cond_0

    .line 5
    sget v1, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_alt_text:I

    invoke-virtual {p2, v1, p1}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 6
    sget v1, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_alt_text:I

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/c;->n()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p2, v1, p0}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 7
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_placeholder:I

    invoke-virtual {p2, p0, v0}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    if-nez p0, :cond_1

    .line 9
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_placeholder:I

    .line 10
    invoke-virtual {p2, p0, p1}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 11
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_alt_text:I

    invoke-virtual {p2, p0, v0}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    :cond_1
    return-void
.end method


# virtual methods
.method public final a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a;)I
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const-string v2, "remoteViews"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "template"

    move-object/from16 v3, p2

    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    iget-object v2, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    sget v4, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_carousel_image_height:I

    invoke-virtual {v2, v4}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v2

    .line 44
    new-instance v4, Lkotlin/jvm/internal/d0;

    .line 45
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 46
    iput v2, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 47
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/carousel/a;->l()Ljava/util/List;

    move-result-object v2

    .line 48
    instance-of v3, v2, Ljava/util/Collection;

    const/4 v5, 0x0

    const/4 v6, 0x0

    if-eqz v3, :cond_0

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v7

    if-eqz v7, :cond_0

    move v8, v6

    goto :goto_1

    .line 49
    :cond_0
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    move v8, v6

    :cond_1
    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_3

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 50
    invoke-virtual {v9}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->r()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v10

    if-eqz v10, :cond_1

    invoke-virtual {v9}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->q()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v9

    if-nez v9, :cond_1

    add-int/lit8 v8, v8, 0x1

    if-ltz v8, :cond_2

    goto :goto_0

    .line 51
    :cond_2
    invoke-static {}, Ljp/k1;->q()V

    throw v5

    :cond_3
    :goto_1
    if-eqz v3, :cond_4

    .line 52
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v7

    if-eqz v7, :cond_4

    move v9, v6

    goto :goto_3

    .line 53
    :cond_4
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    move v9, v6

    :cond_5
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_7

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 54
    invoke-virtual {v10}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->r()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v11

    if-nez v11, :cond_5

    invoke-virtual {v10}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->q()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v10

    if-eqz v10, :cond_5

    add-int/lit8 v9, v9, 0x1

    if-ltz v9, :cond_6

    goto :goto_2

    .line 55
    :cond_6
    invoke-static {}, Ljp/k1;->q()V

    throw v5

    :cond_7
    :goto_3
    if-eqz v3, :cond_8

    .line 56
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v7

    if-eqz v7, :cond_8

    move v10, v6

    goto :goto_5

    .line 57
    :cond_8
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    move v10, v6

    :cond_9
    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v11

    if-eqz v11, :cond_b

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 58
    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->r()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v12

    if-eqz v12, :cond_9

    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->q()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v11

    if-eqz v11, :cond_9

    add-int/lit8 v10, v10, 0x1

    if-ltz v10, :cond_a

    goto :goto_4

    .line 59
    :cond_a
    invoke-static {}, Ljp/k1;->q()V

    throw v5

    :cond_b
    :goto_5
    if-eqz v3, :cond_c

    .line 60
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_c

    goto :goto_7

    .line 61
    :cond_c
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_d
    :goto_6
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_f

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 62
    invoke-virtual {v7}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->r()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v11

    if-nez v11, :cond_d

    invoke-virtual {v7}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->q()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v7

    if-nez v7, :cond_d

    add-int/lit8 v6, v6, 0x1

    if-ltz v6, :cond_e

    goto :goto_6

    .line 63
    :cond_e
    invoke-static {}, Ljp/k1;->q()V

    throw v5

    .line 64
    :cond_f
    :goto_7
    sget-object v11, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    iget-object v12, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v14, Lcom/salesforce/marketingcloud/push/carousel/d$c;

    invoke-direct {v14, v8, v9, v10, v6}, Lcom/salesforce/marketingcloud/push/carousel/d$c;-><init>(IIII)V

    const/4 v15, 0x2

    const/16 v16, 0x0

    const/4 v13, 0x0

    invoke-static/range {v11 .. v16}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    if-lez v10, :cond_10

    .line 65
    iget-object v12, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v14, Lcom/salesforce/marketingcloud/push/carousel/d$d;

    invoke-direct {v14, v4}, Lcom/salesforce/marketingcloud/push/carousel/d$d;-><init>(Lkotlin/jvm/internal/d0;)V

    const/4 v15, 0x2

    const/16 v16, 0x0

    const/4 v13, 0x0

    invoke-static/range {v11 .. v16}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    goto/16 :goto_8

    .line 66
    :cond_10
    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v3

    const/16 v5, 0x8

    if-ne v6, v3, :cond_11

    .line 67
    iget v2, v4, Lkotlin/jvm/internal/d0;->d:I

    iget-object v3, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    sget v6, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_carousel_image_height_addendum:I

    invoke-virtual {v3, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v3

    mul-int/lit8 v3, v3, 0x2

    add-int/2addr v3, v2

    iput v3, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 68
    sget v2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_title:I

    invoke-virtual {v1, v2, v5}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 69
    sget v2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_subtitle:I

    invoke-virtual {v1, v2, v5}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 70
    iget-object v12, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v14, Lcom/salesforce/marketingcloud/push/carousel/d$e;

    invoke-direct {v14, v4}, Lcom/salesforce/marketingcloud/push/carousel/d$e;-><init>(Lkotlin/jvm/internal/d0;)V

    const/4 v15, 0x2

    const/16 v16, 0x0

    const/4 v13, 0x0

    invoke-static/range {v11 .. v16}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    goto :goto_8

    :cond_11
    add-int v3, v8, v6

    .line 71
    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v7

    if-ne v3, v7, :cond_12

    .line 72
    iget v2, v4, Lkotlin/jvm/internal/d0;->d:I

    iget-object v3, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    sget v6, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_carousel_image_height_addendum:I

    invoke-virtual {v3, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v3

    add-int/2addr v3, v2

    iput v3, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 73
    sget v2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_subtitle:I

    invoke-virtual {v1, v2, v5}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 74
    iget-object v12, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v14, Lcom/salesforce/marketingcloud/push/carousel/d$f;

    invoke-direct {v14, v4}, Lcom/salesforce/marketingcloud/push/carousel/d$f;-><init>(Lkotlin/jvm/internal/d0;)V

    const/4 v15, 0x2

    const/16 v16, 0x0

    const/4 v13, 0x0

    invoke-static/range {v11 .. v16}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    goto :goto_8

    :cond_12
    add-int/2addr v6, v9

    .line 75
    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v7

    if-ne v6, v7, :cond_13

    .line 76
    iget v2, v4, Lkotlin/jvm/internal/d0;->d:I

    iget-object v3, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    sget v6, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_carousel_image_height_addendum:I

    invoke-virtual {v3, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v3

    add-int/2addr v3, v2

    iput v3, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 77
    sget v2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_title:I

    invoke-virtual {v1, v2, v5}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 78
    iget-object v12, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v14, Lcom/salesforce/marketingcloud/push/carousel/d$g;

    invoke-direct {v14, v4}, Lcom/salesforce/marketingcloud/push/carousel/d$g;-><init>(Lkotlin/jvm/internal/d0;)V

    const/4 v15, 0x2

    const/16 v16, 0x0

    const/4 v13, 0x0

    invoke-static/range {v11 .. v16}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    goto :goto_8

    :cond_13
    add-int/2addr v3, v9

    .line 79
    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v1

    if-ne v3, v1, :cond_14

    .line 80
    iget-object v12, v0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v14, Lcom/salesforce/marketingcloud/push/carousel/d$h;

    invoke-direct {v14, v8, v9}, Lcom/salesforce/marketingcloud/push/carousel/d$h;-><init>(II)V

    const/4 v15, 0x2

    const/16 v16, 0x0

    const/4 v13, 0x0

    invoke-static/range {v11 .. v16}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 81
    :cond_14
    :goto_8
    iget v0, v4, Lkotlin/jvm/internal/d0;->d:I

    return v0
.end method

.method public final a(Landroid/graphics/drawable/Drawable;II)Landroid/graphics/Bitmap;
    .locals 9

    const-string v0, "background"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    sget-object v0, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    invoke-static {p2, p3, v0}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    move-result-object v0

    const-string v1, "createBitmap(...)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    new-instance v1, Landroid/graphics/Canvas;

    invoke-direct {v1, v0}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    const/4 v2, 0x0

    .line 14
    invoke-virtual {p1, v2, v2, p2, p3}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 15
    invoke-virtual {p1, v1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 16
    sget-object v3, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v6, Lcom/salesforce/marketingcloud/push/carousel/d$m;

    invoke-direct {v6, v0}, Lcom/salesforce/marketingcloud/push/carousel/d$m;-><init>(Landroid/graphics/Bitmap;)V

    const/4 v7, 0x2

    const/4 v8, 0x0

    const/4 v5, 0x0

    invoke-static/range {v3 .. v8}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 17
    sget-object p1, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    invoke-virtual {p1, v0, p3, p2}, Lcom/salesforce/marketingcloud/media/q;->a(Landroid/graphics/Bitmap;II)Landroid/graphics/Bitmap;

    move-result-object p1

    .line 18
    iget-object v4, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v6, Lcom/salesforce/marketingcloud/push/carousel/d$n;

    invoke-direct {v6, p1}, Lcom/salesforce/marketingcloud/push/carousel/d$n;-><init>(Landroid/graphics/Bitmap;)V

    invoke-static/range {v3 .. v8}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    return-object p1
.end method

.method public bridge synthetic a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/data/Template;)Landroid/widget/RemoteViews;
    .locals 0

    .line 2
    check-cast p2, Lcom/salesforce/marketingcloud/push/carousel/a;

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/carousel/d;->b(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a;)Landroid/widget/RemoteViews;

    move-result-object p0

    return-object p0
.end method

.method public final a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;Lcom/salesforce/marketingcloud/push/carousel/a;)Llx0/l;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/widget/RemoteViews;",
            "Lcom/salesforce/marketingcloud/push/carousel/a$a;",
            "Lcom/salesforce/marketingcloud/push/carousel/a;",
            ")",
            "Llx0/l;"
        }
    .end annotation

    const-string v0, "remoteViews"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "item"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p2, "template"

    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    new-instance p2, Lkotlin/jvm/internal/d0;

    .line 31
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 32
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/push/carousel/d;->a()I

    move-result v0

    iput v0, p2, Lkotlin/jvm/internal/d0;->d:I

    .line 33
    new-instance v0, Lkotlin/jvm/internal/d0;

    .line 34
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 35
    invoke-virtual {p0, p1, p3}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a;)I

    move-result p1

    iput p1, v0, Lkotlin/jvm/internal/d0;->d:I

    .line 36
    sget-object v1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v4, Lcom/salesforce/marketingcloud/push/carousel/d$a;

    invoke-direct {v4, v0, p2}, Lcom/salesforce/marketingcloud/push/carousel/d$a;-><init>(Lkotlin/jvm/internal/d0;Lkotlin/jvm/internal/d0;)V

    const/4 v5, 0x2

    const/4 v6, 0x0

    const/4 v3, 0x0

    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 37
    iget p1, p2, Lkotlin/jvm/internal/d0;->d:I

    div-int/lit8 p1, p1, 0x2

    iget p3, v0, Lkotlin/jvm/internal/d0;->d:I

    if-ge p1, p3, :cond_0

    .line 38
    iput p1, v0, Lkotlin/jvm/internal/d0;->d:I

    mul-int/lit8 p1, p1, 0x2

    .line 39
    iput p1, p2, Lkotlin/jvm/internal/d0;->d:I

    goto :goto_0

    :cond_0
    mul-int/lit8 p3, p3, 0x2

    .line 40
    iput p3, p2, Lkotlin/jvm/internal/d0;->d:I

    .line 41
    :goto_0
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v4, Lcom/salesforce/marketingcloud/push/carousel/d$b;

    invoke-direct {v4, v0, p2}, Lcom/salesforce/marketingcloud/push/carousel/d$b;-><init>(Lkotlin/jvm/internal/d0;Lkotlin/jvm/internal/d0;)V

    const/4 v5, 0x2

    const/4 v6, 0x0

    const/4 v3, 0x0

    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 42
    new-instance p0, Llx0/l;

    iget p1, v0, Lkotlin/jvm/internal/d0;->d:I

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    iget p2, p2, Lkotlin/jvm/internal/d0;->d:I

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-direct {p0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object p0
.end method

.method public final a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;)V
    .locals 3

    const-string v0, "remoteViews"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "item"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->h()Ljava/util/List;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 20
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->a:Lcom/salesforce/marketingcloud/push/carousel/b;

    const/4 v1, 0x0

    .line 21
    new-array v1, v1, [Lcom/salesforce/marketingcloud/push/data/a;

    invoke-interface {v0, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Lcom/salesforce/marketingcloud/push/data/a;

    .line 22
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d()Ljava/lang/String;

    move-result-object p2

    const/16 v1, 0x6e

    const/4 v2, 0x0

    .line 23
    invoke-virtual {p0, v0, v1, p2, v2}, Lcom/salesforce/marketingcloud/push/b;->a([Lcom/salesforce/marketingcloud/push/data/a;ILjava/lang/String;Ljava/lang/String;)Landroid/app/PendingIntent;

    move-result-object p0

    .line 24
    sget p2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_carousel:I

    invoke-virtual {p1, p2, p0}, Landroid/widget/RemoteViews;->setOnClickPendingIntent(ILandroid/app/PendingIntent;)V

    :cond_0
    return-void
.end method

.method public final a(Landroid/graphics/Bitmap;Landroid/graphics/Bitmap;)Z
    .locals 7

    const-string v0, "backgroundImage"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "foregroundImage"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p0

    sget v0, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_carousel_image_radius:I

    invoke-virtual {p0, v0}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result p0

    .line 26
    invoke-virtual {p2}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v0

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v1

    const/4 v2, 0x1

    if-gt v0, v1, :cond_2

    invoke-virtual {p2}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v0

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v1

    if-le v0, v1, :cond_0

    goto :goto_0

    .line 27
    :cond_0
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v0

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v1

    mul-int/2addr v1, v0

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v0

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result p1

    mul-int/2addr p1, v0

    add-int/2addr p1, v1

    int-to-double v0, p1

    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v0

    .line 28
    invoke-virtual {p2}, Landroid/graphics/Bitmap;->getWidth()I

    move-result p1

    invoke-virtual {p2}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v3

    mul-int/2addr v3, p1

    invoke-virtual {p2}, Landroid/graphics/Bitmap;->getHeight()I

    move-result p1

    invoke-virtual {p2}, Landroid/graphics/Bitmap;->getHeight()I

    move-result p2

    mul-int/2addr p2, p1

    add-int/2addr p2, v3

    int-to-double p1, p2

    invoke-static {p1, p2}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide p1

    mul-int/lit8 p0, p0, 0x2

    int-to-double v3, p0

    const-wide/high16 v5, 0x4000000000000000L    # 2.0

    .line 29
    invoke-static {v5, v6}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v5

    mul-double/2addr v5, v3

    sub-double/2addr v0, v5

    cmpl-double p0, p1, v0

    if-lez p0, :cond_1

    return v2

    :cond_1
    const/4 p0, 0x0

    return p0

    :cond_2
    :goto_0
    return v2
.end method

.method public b(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a;)Landroid/widget/RemoteViews;
    .locals 3

    const-string v0, "remoteViews"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "template"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->l()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->m()I

    move-result v0

    if-ltz v0, :cond_0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->m()I

    move-result v0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->l()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v0, v1, :cond_0

    .line 2
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->l()Ljava/util/List;

    move-result-object v0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->m()I

    move-result v1

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 3
    sget v1, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_carousel:I

    const/4 v2, 0x0

    invoke-virtual {p1, v1, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 4
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/push/carousel/d;->c(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;)V

    .line 5
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/push/carousel/d;->b(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;)V

    .line 6
    invoke-virtual {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/push/carousel/d;->b(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;Lcom/salesforce/marketingcloud/push/carousel/a;)V

    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/carousel/d;->d(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a;)V

    .line 8
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/carousel/d;->c(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a;)V

    .line 9
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;)V

    return-object p1

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Carousel template must have at least one item"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public final b(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;)V
    .locals 5

    const-string v0, "remoteViews"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "item"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->q()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v0

    if-eqz v0, :cond_4

    .line 12
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_subtitle:I

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 13
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_subtitle:I

    .line 14
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->e:Lcom/salesforce/marketingcloud/push/style/a$b;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->q()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v2

    const/4 v3, 0x2

    const/4 v4, 0x0

    invoke-static {v1, v2, v4, v3, v4}, Lcom/salesforce/marketingcloud/push/style/a;->a(Lcom/salesforce/marketingcloud/push/style/a;Ljava/lang/Object;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/push/data/c;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/Style$b;->o()Landroid/text/Spanned;

    move-result-object v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->q()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v1

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/c;->n()Ljava/lang/String;

    move-result-object v1

    .line 15
    :goto_0
    invoke-virtual {p1, v0, v1}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 16
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1f

    if-lt v0, v1, :cond_1

    .line 17
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->q()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object p0

    if-eqz p0, :cond_3

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/Style$b;->e()Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    move-result-object p0

    if-eqz p0, :cond_3

    .line 18
    sget p2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_subtitle:I

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/Style$Alignment;->toGravity()I

    move-result p0

    const-string v0, "setGravity"

    invoke-virtual {p1, p2, v0, p0}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    return-void

    .line 19
    :cond_1
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->q()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object p1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object p1

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/Style$b;->e()Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    move-result-object p1

    goto :goto_1

    :cond_2
    move-object p1, v4

    :goto_1
    if-eqz p1, :cond_3

    .line 20
    sget-object p1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    sget-object p2, Lcom/salesforce/marketingcloud/push/carousel/d$q;->b:Lcom/salesforce/marketingcloud/push/carousel/d$q;

    invoke-virtual {p1, p0, v4, p2}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    :cond_3
    return-void

    .line 21
    :cond_4
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_subtitle:I

    const/4 p2, 0x4

    invoke-virtual {p1, p0, p2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    return-void
.end method

.method public final b(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;Lcom/salesforce/marketingcloud/push/carousel/a;)V
    .locals 6

    const-string v0, "remoteViews"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "item"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "template"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;Lcom/salesforce/marketingcloud/push/carousel/a;)Llx0/l;

    move-result-object v0

    .line 23
    iget-object v1, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 24
    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    .line 25
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 26
    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    .line 27
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    sget v3, Lcom/salesforce/marketingcloud/R$drawable;->mcsdk_carousel_bg:I

    iget-object v4, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v4}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v4

    invoke-virtual {v2, v3, v4}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    move-result-object v2

    .line 28
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->p()Lcom/salesforce/marketingcloud/push/data/b;

    move-result-object v3

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/data/b;->a()Lcom/salesforce/marketingcloud/push/data/Style;

    move-result-object v3

    const/4 v4, 0x0

    if-eqz v3, :cond_0

    invoke-interface {v3}, Lcom/salesforce/marketingcloud/push/data/Style;->i()Ljava/lang/String;

    move-result-object v3

    goto :goto_0

    :cond_0
    move-object v3, v4

    :goto_0
    if-eqz v3, :cond_1

    .line 29
    new-instance p3, Landroid/graphics/BlendModeColorFilter;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->p()Lcom/salesforce/marketingcloud/push/data/b;

    move-result-object v3

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/data/b;->a()Lcom/salesforce/marketingcloud/push/data/Style;

    move-result-object v3

    invoke-interface {v3}, Lcom/salesforce/marketingcloud/push/data/Style;->i()Ljava/lang/String;

    move-result-object v3

    invoke-static {v3}, Landroid/graphics/Color;->parseColor(Ljava/lang/String;)I

    move-result v3

    sget-object v5, Landroid/graphics/BlendMode;->SRC_ATOP:Landroid/graphics/BlendMode;

    invoke-direct {p3, v3, v5}, Landroid/graphics/BlendModeColorFilter;-><init>(ILandroid/graphics/BlendMode;)V

    .line 30
    invoke-virtual {v2, p3}, Landroid/graphics/drawable/Drawable;->setColorFilter(Landroid/graphics/ColorFilter;)V

    .line 31
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    invoke-virtual {p0, v2, v0, v1}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Landroid/graphics/drawable/Drawable;II)Landroid/graphics/Bitmap;

    move-result-object p3

    .line 32
    sget v3, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_bg:I

    invoke-virtual {p1, v3, p3}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V

    goto :goto_2

    .line 33
    :cond_1
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/push/carousel/a;->a()Lcom/salesforce/marketingcloud/push/data/Style;

    move-result-object v3

    if-eqz v3, :cond_2

    invoke-interface {v3}, Lcom/salesforce/marketingcloud/push/data/Style;->i()Ljava/lang/String;

    move-result-object v3

    goto :goto_1

    :cond_2
    move-object v3, v4

    :goto_1
    if-eqz v3, :cond_3

    .line 34
    new-instance v3, Landroid/graphics/BlendModeColorFilter;

    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/push/carousel/a;->a()Lcom/salesforce/marketingcloud/push/data/Style;

    move-result-object p3

    invoke-interface {p3}, Lcom/salesforce/marketingcloud/push/data/Style;->i()Ljava/lang/String;

    move-result-object p3

    invoke-static {p3}, Landroid/graphics/Color;->parseColor(Ljava/lang/String;)I

    move-result p3

    sget-object v5, Landroid/graphics/BlendMode;->SRC_ATOP:Landroid/graphics/BlendMode;

    invoke-direct {v3, p3, v5}, Landroid/graphics/BlendModeColorFilter;-><init>(ILandroid/graphics/BlendMode;)V

    .line 35
    invoke-virtual {v2, v3}, Landroid/graphics/drawable/Drawable;->setColorFilter(Landroid/graphics/ColorFilter;)V

    .line 36
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    invoke-virtual {p0, v2, v0, v1}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Landroid/graphics/drawable/Drawable;II)Landroid/graphics/Bitmap;

    move-result-object p3

    .line 37
    sget v3, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_bg:I

    invoke-virtual {p1, v3, p3}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V

    goto :goto_2

    :cond_3
    move-object p3, v4

    :goto_2
    if-nez p3, :cond_4

    .line 38
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    invoke-virtual {p0, v2, v0, v1}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Landroid/graphics/drawable/Drawable;II)Landroid/graphics/Bitmap;

    move-result-object p3

    .line 39
    sget v2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_bg:I

    invoke-virtual {p1, v2, p3}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V

    .line 40
    :cond_4
    :try_start_0
    sget v2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_image:I

    const/4 v3, 0x0

    invoke-virtual {p1, v2, v3}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 41
    sget v2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_placeholder:I

    const/16 v3, 0x8

    invoke-virtual {p1, v2, v3}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 42
    sget v2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_alt_text:I

    invoke-virtual {p1, v2, v3}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 43
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->c:Lcom/salesforce/marketingcloud/media/o;

    if-eqz v2, :cond_5

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->p()Lcom/salesforce/marketingcloud/push/data/b;

    move-result-object v3

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/data/b;->o()Ljava/lang/String;

    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\n"

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object v4

    goto :goto_3

    :catch_0
    move-exception p3

    goto :goto_4

    :cond_5
    :goto_3
    if-nez v4, :cond_7

    .line 44
    invoke-direct {p0, p2, p1}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Lcom/salesforce/marketingcloud/push/carousel/a$a;Landroid/widget/RemoteViews;)V

    .line 45
    iget-object p3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->c:Lcom/salesforce/marketingcloud/media/o;

    if-eqz p3, :cond_6

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->p()Lcom/salesforce/marketingcloud/push/data/b;

    move-result-object v0

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/push/data/b;->o()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p3, v0}, Lcom/salesforce/marketingcloud/media/o;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/media/u;

    move-result-object p3

    if-eqz p3, :cond_6

    sget-object v0, Lcom/salesforce/marketingcloud/media/o$c;->c:Lcom/salesforce/marketingcloud/media/o$c;

    invoke-virtual {p3, v0}, Lcom/salesforce/marketingcloud/media/u;->a(Lcom/salesforce/marketingcloud/media/o$c;)Lcom/salesforce/marketingcloud/media/u;

    move-result-object p3

    if-eqz p3, :cond_6

    new-instance v0, Lcom/salesforce/marketingcloud/push/carousel/d$o;

    invoke-direct {v0, p0, p2}, Lcom/salesforce/marketingcloud/push/carousel/d$o;-><init>(Lcom/salesforce/marketingcloud/push/carousel/d;Lcom/salesforce/marketingcloud/push/carousel/a$a;)V

    invoke-virtual {p3, v0}, Lcom/salesforce/marketingcloud/media/u;->a(Lcom/salesforce/marketingcloud/media/f;)V

    :cond_6
    return-void

    .line 46
    :cond_7
    sget-object v2, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    invoke-virtual {v2, v4, v1, v0}, Lcom/salesforce/marketingcloud/media/q;->a(Landroid/graphics/Bitmap;II)Landroid/graphics/Bitmap;

    move-result-object v0

    .line 47
    invoke-virtual {p0, p3, v0}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Landroid/graphics/Bitmap;Landroid/graphics/Bitmap;)Z

    move-result p3

    if-eqz p3, :cond_8

    .line 48
    sget p3, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_image:I

    .line 49
    sget-object v1, Lcom/salesforce/marketingcloud/push/i;->a:Lcom/salesforce/marketingcloud/push/i;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    sget v3, Lcom/salesforce/marketingcloud/R$dimen;->mcsdk_push_carousel_image_radius:I

    invoke-virtual {v2, v3}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result v2

    invoke-virtual {v1, v0, v2}, Lcom/salesforce/marketingcloud/push/i;->a(Landroid/graphics/Bitmap;I)Landroid/graphics/Bitmap;

    move-result-object v0

    .line 50
    invoke-virtual {p1, p3, v0}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V

    return-void

    .line 51
    :cond_8
    sget p3, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_image:I

    invoke-virtual {p1, p3, v0}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 52
    :goto_4
    sget-object v0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    new-instance v2, Lcom/salesforce/marketingcloud/push/carousel/d$p;

    invoke-direct {v2, p2}, Lcom/salesforce/marketingcloud/push/carousel/d$p;-><init>(Lcom/salesforce/marketingcloud/push/carousel/a$a;)V

    invoke-virtual {v0, v1, p3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 53
    invoke-direct {p0, p2, p1}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Lcom/salesforce/marketingcloud/push/carousel/a$a;Landroid/widget/RemoteViews;)V

    return-void
.end method

.method public final c(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;)V
    .locals 4

    const-string v0, "remoteViews"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "item"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->r()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v0

    if-eqz v0, :cond_4

    .line 2
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_title:I

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 3
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_title:I

    .line 4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->e:Lcom/salesforce/marketingcloud/push/style/a$b;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->r()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v2

    sget-object v3, Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;->B:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    invoke-virtual {v1, v2, v3}, Lcom/salesforce/marketingcloud/push/style/a$b;->a(Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;)Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v1

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/Style$b;->o()Landroid/text/Spanned;

    move-result-object v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->r()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v1

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/c;->n()Ljava/lang/String;

    move-result-object v1

    .line 5
    :goto_0
    invoke-virtual {p1, v0, v1}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 6
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1f

    if-lt v0, v1, :cond_1

    .line 7
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->r()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object p0

    if-eqz p0, :cond_3

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/Style$b;->e()Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    move-result-object p0

    if-eqz p0, :cond_3

    .line 8
    sget p2, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_title:I

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/Style$Alignment;->toGravity()I

    move-result p0

    const-string v0, "setGravity"

    invoke-virtual {p1, p2, v0, p0}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    return-void

    .line 9
    :cond_1
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->r()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object p1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object p1

    const/4 p2, 0x0

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/Style$b;->e()Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    move-result-object p1

    goto :goto_1

    :cond_2
    move-object p1, p2

    :goto_1
    if-eqz p1, :cond_3

    .line 10
    sget-object p1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->d:Ljava/lang/String;

    sget-object v0, Lcom/salesforce/marketingcloud/push/carousel/d$r;->b:Lcom/salesforce/marketingcloud/push/carousel/d$r;

    invoke-virtual {p1, p0, p2, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    :cond_3
    return-void

    .line 11
    :cond_4
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_title:I

    const/4 p2, 0x4

    invoke-virtual {p1, p0, p2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    return-void
.end method

.method public final c(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a;)V
    .locals 3

    const-string v0, "remoteViews"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "template"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_previous:I

    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->a:Lcom/salesforce/marketingcloud/push/carousel/b;

    .line 13
    const-string v2, "com.salesforce.marketingcloud.notifications.ACTION_CAROUSEL_PREVIOUS"

    invoke-virtual {v1, v2, p2}, Lcom/salesforce/marketingcloud/push/carousel/b;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/carousel/a;)Landroid/app/PendingIntent;

    move-result-object v1

    .line 14
    invoke-virtual {p1, v0, v1}, Landroid/widget/RemoteViews;->setOnClickPendingIntent(ILandroid/app/PendingIntent;)V

    .line 15
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_next:I

    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->a:Lcom/salesforce/marketingcloud/push/carousel/b;

    .line 16
    const-string v1, "com.salesforce.marketingcloud.notifications.ACTION_CAROUSEL_NEXT"

    invoke-virtual {p0, v1, p2}, Lcom/salesforce/marketingcloud/push/carousel/b;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/carousel/a;)Landroid/app/PendingIntent;

    move-result-object p0

    .line 17
    invoke-virtual {p1, v0, p0}, Landroid/widget/RemoteViews;->setOnClickPendingIntent(ILandroid/app/PendingIntent;)V

    .line 18
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_next_unselected:I

    const/4 v0, 0x0

    invoke-virtual {p1, p0, v0}, Landroid/widget/RemoteViews;->setOnClickPendingIntent(ILandroid/app/PendingIntent;)V

    .line 19
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_previous_unselected:I

    invoke-virtual {p1, p0, v0}, Landroid/widget/RemoteViews;->setOnClickPendingIntent(ILandroid/app/PendingIntent;)V

    .line 20
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->m()I

    move-result p0

    const/4 v0, 0x4

    const/16 v1, 0x8

    const/4 v2, 0x0

    if-nez p0, :cond_0

    .line 21
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_previous:I

    invoke-virtual {p1, p0, v0}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 22
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_previous_unselected:I

    invoke-virtual {p1, p0, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 23
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_next:I

    invoke-virtual {p1, p0, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 24
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_next_unselected:I

    invoke-virtual {p1, p0, v1}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    return-void

    .line 25
    :cond_0
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->l()Ljava/util/List;

    move-result-object p2

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result p2

    add-int/lit8 p2, p2, -0x1

    if-ne p0, p2, :cond_1

    .line 26
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_previous:I

    invoke-virtual {p1, p0, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 27
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_previous_unselected:I

    invoke-virtual {p1, p0, v1}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 28
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_next:I

    invoke-virtual {p1, p0, v0}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 29
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_next_unselected:I

    invoke-virtual {p1, p0, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    return-void

    .line 30
    :cond_1
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_previous:I

    invoke-virtual {p1, p0, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 31
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_previous_unselected:I

    invoke-virtual {p1, p0, v1}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 32
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_next:I

    invoke-virtual {p1, p0, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 33
    sget p0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_carousel_next_unselected:I

    invoke-virtual {p1, p0, v1}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    return-void
.end method

.method public final d(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a;)V
    .locals 5

    .line 1
    const-string v0, "remoteViews"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "template"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget v0, Lcom/salesforce/marketingcloud/R$id;->mcsdk_dot_container:I

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/widget/RemoteViews;->removeAllViews(I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->l()Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v1, 0x0

    .line 25
    :goto_0
    if-ge v1, v0, :cond_1

    .line 26
    .line 27
    new-instance v2, Landroid/widget/RemoteViews;

    .line 28
    .line 29
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/carousel/d;->b:Landroid/content/Context;

    .line 30
    .line 31
    invoke-virtual {v3}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    sget v4, Lcom/salesforce/marketingcloud/R$layout;->mcsdk_dot_view:I

    .line 36
    .line 37
    invoke-direct {v2, v3, v4}, Landroid/widget/RemoteViews;-><init>(Ljava/lang/String;I)V

    .line 38
    .line 39
    .line 40
    sget v3, Lcom/salesforce/marketingcloud/R$id;->mcsdk_dot_image:I

    .line 41
    .line 42
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/carousel/a;->m()I

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    if-ne v1, v4, :cond_0

    .line 47
    .line 48
    sget v4, Lcom/salesforce/marketingcloud/R$drawable;->mcsdk_dot_selected:I

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_0
    sget v4, Lcom/salesforce/marketingcloud/R$drawable;->mcsdk_dot_unselected:I

    .line 52
    .line 53
    :goto_1
    invoke-virtual {v2, v3, v4}, Landroid/widget/RemoteViews;->setImageViewResource(II)V

    .line 54
    .line 55
    .line 56
    sget v3, Lcom/salesforce/marketingcloud/R$id;->mcsdk_dot_container:I

    .line 57
    .line 58
    invoke-virtual {p1, v3, v2}, Landroid/widget/RemoteViews;->addView(ILandroid/widget/RemoteViews;)V

    .line 59
    .line 60
    .line 61
    add-int/lit8 v1, v1, 0x1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    return-void
.end method
