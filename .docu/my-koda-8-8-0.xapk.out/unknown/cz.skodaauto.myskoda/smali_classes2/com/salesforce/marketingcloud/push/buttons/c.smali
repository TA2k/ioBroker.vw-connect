.class public final Lcom/salesforce/marketingcloud/push/buttons/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/push/k;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lcom/salesforce/marketingcloud/push/k<",
        "Lcom/salesforce/marketingcloud/push/buttons/a;",
        ">;"
    }
.end annotation


# instance fields
.field private final a:Landroid/content/Context;

.field private final b:Lcom/salesforce/marketingcloud/push/b;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/push/b;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "richButtonIntentProvider"

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
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->b:Lcom/salesforce/marketingcloud/push/b;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/buttons/a;)Landroid/widget/RemoteViews;
    .locals 13

    const-string v0, "remoteViews"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "template"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/buttons/a;->k()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_8

    .line 3
    new-instance v0, Lcom/salesforce/marketingcloud/push/style/a$b;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/style/a$b;-><init>(Landroid/content/Context;)V

    .line 4
    sget v1, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_custom_buttons:I

    const/4 v2, 0x0

    invoke-virtual {p1, v1, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 5
    sget v1, Lcom/salesforce/marketingcloud/R$id;->mcsdk_push_button_list:I

    invoke-virtual {p1, v1, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 6
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/push/buttons/a;->k()Ljava/util/List;

    move-result-object p2

    .line 7
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    move v1, v2

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_7

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    add-int/lit8 v4, v1, 0x1

    const/4 v5, 0x0

    if-ltz v1, :cond_6

    check-cast v3, Lcom/salesforce/marketingcloud/push/buttons/a$c;

    .line 8
    iget-object v6, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v6

    const-string v7, "mcsdk_btn_item_"

    .line 9
    invoke-static {v1, v7}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v7

    .line 10
    iget-object v8, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    invoke-virtual {v8}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v8

    const-string v9, "id"

    invoke-virtual {v6, v7, v9, v8}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    move-result v6

    .line 11
    invoke-virtual {p1, v6, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 12
    iget-object v7, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->b:Lcom/salesforce/marketingcloud/push/b;

    .line 13
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->h()Ljava/util/List;

    move-result-object v8

    if-eqz v8, :cond_0

    .line 14
    new-array v10, v2, [Lcom/salesforce/marketingcloud/push/data/a;

    invoke-interface {v8, v10}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v8

    check-cast v8, [Lcom/salesforce/marketingcloud/push/data/a;

    goto :goto_1

    :cond_0
    move-object v8, v5

    .line 15
    :goto_1
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->d()Ljava/lang/String;

    move-result-object v10

    .line 16
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->p()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v11

    if-eqz v11, :cond_1

    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/push/data/c;->n()Ljava/lang/String;

    move-result-object v11

    goto :goto_2

    :cond_1
    move-object v11, v5

    :goto_2
    const/16 v12, 0x6f

    .line 17
    invoke-virtual {v7, v8, v12, v10, v11}, Lcom/salesforce/marketingcloud/push/b;->a([Lcom/salesforce/marketingcloud/push/data/a;ILjava/lang/String;Ljava/lang/String;)Landroid/app/PendingIntent;

    move-result-object v7

    .line 18
    invoke-virtual {p1, v6, v7}, Landroid/widget/RemoteViews;->setOnClickPendingIntent(ILandroid/app/PendingIntent;)V

    .line 19
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->p()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v6

    if-eqz v6, :cond_3

    .line 20
    iget-object v7, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    invoke-virtual {v7}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v7

    const-string v8, "mcsdk_btn_title_"

    .line 21
    invoke-static {v1, v8}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v8

    .line 22
    iget-object v10, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    invoke-virtual {v10}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v10

    invoke-virtual {v7, v8, v9, v10}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    move-result v7

    .line 23
    invoke-virtual {p1, v7, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    const/4 v8, 0x2

    .line 24
    invoke-static {v0, v6, v5, v8, v5}, Lcom/salesforce/marketingcloud/push/style/a;->a(Lcom/salesforce/marketingcloud/push/style/a;Ljava/lang/Object;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Lcom/salesforce/marketingcloud/push/data/c;

    invoke-virtual {v8}, Lcom/salesforce/marketingcloud/push/data/c;->m()Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object v8

    if-eqz v8, :cond_2

    invoke-virtual {v8}, Lcom/salesforce/marketingcloud/push/data/Style$b;->o()Landroid/text/Spanned;

    move-result-object v8

    if-eqz v8, :cond_2

    goto :goto_3

    :cond_2
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/push/data/c;->n()Ljava/lang/String;

    move-result-object v8

    :goto_3
    invoke-virtual {p1, v7, v8}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 25
    :cond_3
    iget-object v6, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v6

    const-string v7, "mcsdk_btn_img_"

    .line 26
    invoke-static {v1, v7}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 27
    iget-object v7, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    invoke-virtual {v7}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v6, v1, v9, v7}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    move-result v1

    .line 28
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->o()Ljava/lang/String;

    move-result-object v3

    if-eqz v3, :cond_5

    .line 29
    invoke-virtual {p1, v1, v2}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 30
    sget-object v6, Lcom/salesforce/marketingcloud/media/q;->a:Lcom/salesforce/marketingcloud/media/q;

    iget-object v7, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    invoke-virtual {v6, v7, v3}, Lcom/salesforce/marketingcloud/media/q;->a(Landroid/content/Context;Ljava/lang/String;)I

    move-result v3

    .line 31
    iget-object v6, p0, Lcom/salesforce/marketingcloud/push/buttons/c;->a:Landroid/content/Context;

    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v6

    .line 32
    invoke-static {v6, v3}, Landroid/graphics/BitmapFactory;->decodeResource(Landroid/content/res/Resources;I)Landroid/graphics/Bitmap;

    move-result-object v3

    if-eqz v3, :cond_4

    .line 33
    invoke-virtual {p1, v1, v3}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V

    .line 34
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    :cond_4
    if-nez v5, :cond_5

    const/16 v3, 0x8

    .line 35
    invoke-virtual {p1, v1, v3}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    :cond_5
    move v1, v4

    goto/16 :goto_0

    .line 36
    :cond_6
    invoke-static {}, Ljp/k1;->r()V

    throw v5

    :cond_7
    return-object p1

    .line 37
    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Rich Buttons template must have at least one item"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public bridge synthetic a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/data/Template;)Landroid/widget/RemoteViews;
    .locals 0

    .line 1
    check-cast p2, Lcom/salesforce/marketingcloud/push/buttons/a;

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/buttons/c;->a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/buttons/a;)Landroid/widget/RemoteViews;

    move-result-object p0

    return-object p0
.end method
