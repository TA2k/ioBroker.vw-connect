.class final Lcom/salesforce/marketingcloud/push/carousel/d$c;
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

.field final synthetic d:I

.field final synthetic e:I


# direct methods
.method public constructor <init>(IIII)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/push/carousel/d$c;->b:I

    .line 2
    .line 3
    iput p2, p0, Lcom/salesforce/marketingcloud/push/carousel/d$c;->c:I

    .line 4
    .line 5
    iput p3, p0, Lcom/salesforce/marketingcloud/push/carousel/d$c;->d:I

    .line 6
    .line 7
    iput p4, p0, Lcom/salesforce/marketingcloud/push/carousel/d$c;->e:I

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 6

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/push/carousel/d$c;->b:I

    .line 2
    .line 3
    iget v1, p0, Lcom/salesforce/marketingcloud/push/carousel/d$c;->c:I

    .line 4
    .line 5
    iget v2, p0, Lcom/salesforce/marketingcloud/push/carousel/d$c;->d:I

    .line 6
    .line 7
    iget p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d$c;->e:I

    .line 8
    .line 9
    const-string v3, " subCaptionOnly"

    .line 10
    .line 11
    const-string v4, " captionWithSubCaption"

    .line 12
    .line 13
    const-string v5, " getCarouselImageHeight captionsOnly"

    .line 14
    .line 15
    invoke-static {v0, v1, v5, v3, v4}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v1, " noCaptionSubCaption "

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, " "

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/carousel/d$c;->a()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
