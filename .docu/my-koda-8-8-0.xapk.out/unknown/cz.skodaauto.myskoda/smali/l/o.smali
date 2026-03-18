.class public final Ll/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/ActionProvider$VisibilityListener;


# instance fields
.field public a:Lj1/a;

.field public final b:Landroid/view/ActionProvider;


# direct methods
.method public constructor <init>(Ll/s;Landroid/view/ActionProvider;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Ll/o;->b:Landroid/view/ActionProvider;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onActionProviderVisibilityChanged(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll/o;->a:Lj1/a;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ll/n;

    .line 8
    .line 9
    iget-object p0, p0, Ll/n;->n:Ll/l;

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    iput-boolean p1, p0, Ll/l;->h:Z

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Ll/l;->p(Z)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method
