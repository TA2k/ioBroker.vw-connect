.class Lcom/salesforce/marketingcloud/messages/iam/c$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/animation/Animation$AnimationListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/iam/c;->onCreateAnimation(IZI)Landroid/view/animation/Animation;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic a:Z

.field final synthetic b:Lcom/salesforce/marketingcloud/messages/iam/c;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/c;Z)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/c$a;->b:Lcom/salesforce/marketingcloud/messages/iam/c;

    .line 2
    .line 3
    iput-boolean p2, p0, Lcom/salesforce/marketingcloud/messages/iam/c$a;->a:Z

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public onAnimationEnd(Landroid/view/animation/Animation;)V
    .locals 2

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/c$a;->b:Lcom/salesforce/marketingcloud/messages/iam/c;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getView()Landroid/view/View;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-virtual {p1, v0, v1}, Landroid/view/View;->setLayerType(ILandroid/graphics/Paint;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    iget-boolean p1, p0, Lcom/salesforce/marketingcloud/messages/iam/c$a;->a:Z

    .line 15
    .line 16
    if-nez p1, :cond_1

    .line 17
    .line 18
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/c$a;->b:Lcom/salesforce/marketingcloud/messages/iam/c;

    .line 19
    .line 20
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Landroid/app/Activity;->finish()V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public onAnimationRepeat(Landroid/view/animation/Animation;)V
    .locals 0

    .line 1
    return-void
.end method

.method public onAnimationStart(Landroid/view/animation/Animation;)V
    .locals 0

    .line 1
    return-void
.end method
