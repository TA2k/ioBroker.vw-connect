.class final Lcom/salesforce/marketingcloud/media/q$b;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/media/q;->a(Landroid/graphics/Bitmap;II)Landroid/graphics/Bitmap;
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

.field final synthetic d:F


# direct methods
.method public constructor <init>(IIF)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/media/q$b;->b:I

    .line 2
    .line 3
    iput p2, p0, Lcom/salesforce/marketingcloud/media/q$b;->c:I

    .line 4
    .line 5
    iput p3, p0, Lcom/salesforce/marketingcloud/media/q$b;->d:F

    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 5

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/media/q$b;->b:I

    .line 2
    .line 3
    iget v1, p0, Lcom/salesforce/marketingcloud/media/q$b;->c:I

    .line 4
    .line 5
    iget p0, p0, Lcom/salesforce/marketingcloud/media/q$b;->d:F

    .line 6
    .line 7
    const-string v2, " targetHeight:"

    .line 8
    .line 9
    const-string v3, " for aspectRatio "

    .line 10
    .line 11
    const-string v4, "scaleBitmapToFit Width target dimension targetWidth:"

    .line 12
    .line 13
    invoke-static {v0, v1, v4, v2, v3}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/media/q$b;->a()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
