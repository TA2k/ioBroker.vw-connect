.class public final synthetic Lw3/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/ViewTreeObserver$OnTouchModeChangeListener;


# instance fields
.field public final synthetic d:Lw3/t;


# direct methods
.method public synthetic constructor <init>(Lw3/t;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw3/k;->d:Lw3/t;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onTouchModeChanged(Z)V
    .locals 1

    .line 1
    iget-object p0, p0, Lw3/k;->d:Lw3/t;

    .line 2
    .line 3
    iget-object p0, p0, Lw3/t;->B1:Lm3/c;

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 p1, 0x2

    .line 10
    :goto_0
    iget-object p0, p0, Lm3/c;->a:Ll2/j1;

    .line 11
    .line 12
    new-instance v0, Lm3/a;

    .line 13
    .line 14
    invoke-direct {v0, p1}, Lm3/a;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
