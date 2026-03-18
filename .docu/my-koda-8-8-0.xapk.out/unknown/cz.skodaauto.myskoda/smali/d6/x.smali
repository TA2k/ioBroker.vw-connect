.class public final Ld6/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ld6/w;


# direct methods
.method public constructor <init>(Landroidx/core/widget/NestedScrollView;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 5
    .line 6
    const/16 v1, 0x23

    .line 7
    .line 8
    if-lt v0, v1, :cond_0

    .line 9
    .line 10
    new-instance v0, Ld6/v;

    .line 11
    .line 12
    invoke-direct {v0, p1}, Ld6/v;-><init>(Landroidx/core/widget/NestedScrollView;)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Ld6/x;->a:Ld6/w;

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance p1, Lmb/e;

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    invoke-direct {p1, v0}, Lmb/e;-><init>(I)V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Ld6/x;->a:Ld6/w;

    .line 25
    .line 26
    return-void
.end method
