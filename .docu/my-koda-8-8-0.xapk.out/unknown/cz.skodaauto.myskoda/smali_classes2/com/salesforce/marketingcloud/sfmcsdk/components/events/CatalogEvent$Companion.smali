.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000<\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002J\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\u0007\u001a\u0004\u0018\u00010\u00082\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\t\u001a\u0004\u0018\u00010\n2\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\u000b\u001a\u0004\u0018\u00010\u000c2\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\r\u001a\u0004\u0018\u00010\u000e2\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\u000f\u001a\u0004\u0018\u00010\u00102\u0006\u0010\u0005\u001a\u00020\u0006H\u0007J\u0012\u0010\u0011\u001a\u0004\u0018\u00010\u00122\u0006\u0010\u0005\u001a\u00020\u0006H\u0007\u00a8\u0006\u0013"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;",
        "",
        "()V",
        "comment",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CommentCatalogEvent;",
        "catalogObject",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;",
        "favorite",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/FavoriteCatalogEvent;",
        "quickView",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/QuickViewCatalogEvent;",
        "review",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReviewCatalogEvent;",
        "share",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShareCatalogEvent;",
        "view",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogEvent;",
        "viewDetail",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogDetailEvent;",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final comment(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CommentCatalogEvent;
    .locals 0

    .line 1
    const-string p0, "catalogObject"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CommentCatalogEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CommentCatalogEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final favorite(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/FavoriteCatalogEvent;
    .locals 0

    .line 1
    const-string p0, "catalogObject"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/FavoriteCatalogEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/FavoriteCatalogEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final quickView(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/QuickViewCatalogEvent;
    .locals 0

    .line 1
    const-string p0, "catalogObject"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/QuickViewCatalogEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/QuickViewCatalogEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final review(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReviewCatalogEvent;
    .locals 0

    .line 1
    const-string p0, "catalogObject"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReviewCatalogEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReviewCatalogEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final share(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShareCatalogEvent;
    .locals 0

    .line 1
    const-string p0, "catalogObject"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShareCatalogEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShareCatalogEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final view(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogEvent;
    .locals 0

    .line 1
    const-string p0, "catalogObject"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final viewDetail(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogDetailEvent;
    .locals 0

    .line 1
    const-string p0, "catalogObject"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogDetailEvent;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogDetailEvent;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :catch_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method
