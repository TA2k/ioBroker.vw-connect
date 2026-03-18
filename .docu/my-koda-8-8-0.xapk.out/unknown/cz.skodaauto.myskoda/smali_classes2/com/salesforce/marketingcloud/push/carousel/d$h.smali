.class final Lcom/salesforce/marketingcloud/push/carousel/d$h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/push/carousel/d;->a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a;)I
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/jvm/internal/n;",
        "Lay0/a;"
    }
.end annotation


# instance fields
.field final synthetic b:I

.field final synthetic c:I


# direct methods
.method public constructor <init>(II)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/push/carousel/d$h;->b:I

    .line 2
    .line 3
    iput p2, p0, Lcom/salesforce/marketingcloud/push/carousel/d$h;->c:I

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/push/carousel/d$h;->b:I

    .line 2
    .line 3
    iget p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d$h;->c:I

    .line 4
    .line 5
    const-string v1, "captionsOnly :"

    .line 6
    .line 7
    const-string v2, " and subCaptionOnly "

    .line 8
    .line 9
    invoke-static {v1, v2, v0, p0}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/carousel/d$h;->a()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
