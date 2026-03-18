.class public final Lw0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/s0;


# instance fields
.field public a:Landroid/animation/ValueAnimator;

.field public final synthetic b:Lw0/m;


# direct methods
.method public constructor <init>(Lw0/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw0/l;->b:Lw0/m;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final clear()V
    .locals 2

    .line 1
    const-string v0, "ScreenFlashView"

    .line 2
    .line 3
    const-string v1, "ScreenFlash#clear"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lw0/l;->a:Landroid/animation/ValueAnimator;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/animation/ValueAnimator;->cancel()V

    .line 13
    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    iput-object v0, p0, Lw0/l;->a:Landroid/animation/ValueAnimator;

    .line 17
    .line 18
    :cond_0
    const/4 v0, 0x0

    .line 19
    iget-object p0, p0, Lw0/l;->b:Lw0/m;

    .line 20
    .line 21
    invoke-virtual {p0, v0}, Landroid/view/View;->setAlpha(F)V

    .line 22
    .line 23
    .line 24
    invoke-static {p0, v0}, Lw0/m;->a(Lw0/m;F)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
