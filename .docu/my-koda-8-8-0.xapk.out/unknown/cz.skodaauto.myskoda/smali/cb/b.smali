.class public final Lcb/b;
.super Landroid/graphics/drawable/Animatable2$AnimationCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Llq/a;


# direct methods
.method public constructor <init>(Llq/a;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcb/b;->a:Llq/a;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/graphics/drawable/Animatable2$AnimationCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onAnimationEnd(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcb/b;->a:Llq/a;

    .line 2
    .line 3
    iget-object p0, p0, Llq/a;->b:Llq/c;

    .line 4
    .line 5
    iget-object p0, p0, Llq/c;->r:Landroid/content/res/ColorStateList;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1, p0}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final onAnimationStart(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcb/b;->a:Llq/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Llq/a;->a(Landroid/graphics/drawable/Drawable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
