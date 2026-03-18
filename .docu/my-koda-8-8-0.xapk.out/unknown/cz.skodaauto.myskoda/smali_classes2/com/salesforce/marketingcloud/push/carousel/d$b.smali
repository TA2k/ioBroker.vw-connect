.class final Lcom/salesforce/marketingcloud/push/carousel/d$b;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/push/carousel/d;->a(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;Lcom/salesforce/marketingcloud/push/carousel/a;)Llx0/l;
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
.field final synthetic b:Lkotlin/jvm/internal/d0;

.field final synthetic c:Lkotlin/jvm/internal/d0;


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/d0;Lkotlin/jvm/internal/d0;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/d$b;->b:Lkotlin/jvm/internal/d0;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/carousel/d$b;->c:Lkotlin/jvm/internal/d0;

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
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/d$b;->b:Lkotlin/jvm/internal/d0;

    .line 2
    .line 3
    iget v0, v0, Lkotlin/jvm/internal/d0;->d:I

    .line 4
    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d$b;->c:Lkotlin/jvm/internal/d0;

    .line 6
    .line 7
    iget p0, p0, Lkotlin/jvm/internal/d0;->d:I

    .line 8
    .line 9
    const-string v1, "ratio adjusted safe dimension::imageHeight "

    .line 10
    .line 11
    const-string v2, " , imageWidth "

    .line 12
    .line 13
    invoke-static {v1, v2, v0, p0}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/carousel/d$b;->a()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
