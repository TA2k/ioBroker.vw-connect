.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;
.super Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00086\u0018\u0000 \t2\u00020\u0001:\u0001\tB\u0017\u0008\u0004\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0002\u0010\u0006R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0007\u0010\u0008\u0082\u0001\u0007\n\u000b\u000c\r\u000e\u000f\u0010\u00a8\u0006\u0011"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;",
        "name",
        "",
        "catalogObject",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;",
        "(Ljava/lang/String;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V",
        "getCatalogObject",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;",
        "Companion",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CommentCatalogEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/FavoriteCatalogEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/QuickViewCatalogEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReviewCatalogEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShareCatalogEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogDetailEvent;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogEvent;",
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


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;


# instance fields
.field private final catalogObject:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EngagementEvent;-><init>(Ljava/lang/String;Lkotlin/jvm/internal/g;)V

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->catalogObject:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)V

    return-void
.end method

.method public static final comment(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CommentCatalogEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;->comment(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CommentCatalogEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final favorite(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/FavoriteCatalogEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;->favorite(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/FavoriteCatalogEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final quickView(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/QuickViewCatalogEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;->quickView(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/QuickViewCatalogEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final review(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReviewCatalogEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;->review(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ReviewCatalogEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final share(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShareCatalogEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;->share(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ShareCatalogEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final view(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;->view(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final viewDetail(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogDetailEvent;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent$Companion;->viewDetail(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/ViewCatalogDetailEvent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method


# virtual methods
.method public final getCatalogObject()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogEvent;->catalogObject:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/CatalogObject;

    .line 2
    .line 3
    return-object p0
.end method
