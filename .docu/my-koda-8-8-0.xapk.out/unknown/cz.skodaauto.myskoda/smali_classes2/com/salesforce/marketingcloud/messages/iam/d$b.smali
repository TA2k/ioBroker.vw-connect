.class Lcom/salesforce/marketingcloud/messages/iam/d$b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic b:Landroid/view/View;

.field final synthetic c:I

.field final synthetic d:Landroid/view/View;

.field final synthetic e:Lcom/salesforce/marketingcloud/messages/iam/d;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/d;Landroid/view/View;ILandroid/view/View;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/d$b;->e:Lcom/salesforce/marketingcloud/messages/iam/d;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/d$b;->b:Landroid/view/View;

    .line 4
    .line 5
    iput p3, p0, Lcom/salesforce/marketingcloud/messages/iam/d$b;->c:I

    .line 6
    .line 7
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/iam/d$b;->d:Landroid/view/View;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public run()V
    .locals 3

    .line 1
    new-instance v0, Landroid/graphics/Rect;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/d$b;->b:Landroid/view/View;

    .line 7
    .line 8
    invoke-virtual {v1, v0}, Landroid/view/View;->getHitRect(Landroid/graphics/Rect;)V

    .line 9
    .line 10
    .line 11
    iget v1, v0, Landroid/graphics/Rect;->top:I

    .line 12
    .line 13
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/iam/d$b;->c:I

    .line 14
    .line 15
    sub-int/2addr v1, v2

    .line 16
    iput v1, v0, Landroid/graphics/Rect;->top:I

    .line 17
    .line 18
    iget v1, v0, Landroid/graphics/Rect;->left:I

    .line 19
    .line 20
    sub-int/2addr v1, v2

    .line 21
    iput v1, v0, Landroid/graphics/Rect;->left:I

    .line 22
    .line 23
    iget v1, v0, Landroid/graphics/Rect;->bottom:I

    .line 24
    .line 25
    add-int/2addr v1, v2

    .line 26
    iput v1, v0, Landroid/graphics/Rect;->bottom:I

    .line 27
    .line 28
    iget v1, v0, Landroid/graphics/Rect;->right:I

    .line 29
    .line 30
    add-int/2addr v1, v2

    .line 31
    iput v1, v0, Landroid/graphics/Rect;->right:I

    .line 32
    .line 33
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/d$b;->d:Landroid/view/View;

    .line 34
    .line 35
    new-instance v2, Landroid/view/TouchDelegate;

    .line 36
    .line 37
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/d$b;->b:Landroid/view/View;

    .line 38
    .line 39
    invoke-direct {v2, v0, p0}, Landroid/view/TouchDelegate;-><init>(Landroid/graphics/Rect;Landroid/view/View;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v1, v2}, Landroid/view/View;->setTouchDelegate(Landroid/view/TouchDelegate;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method
