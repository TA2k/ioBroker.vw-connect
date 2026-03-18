.class public abstract Landroidx/fragment/app/t0;
.super Landroidx/fragment/app/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Landroidx/fragment/app/o0;

.field public final e:Landroidx/fragment/app/o0;

.field public final f:Landroid/os/Handler;

.field public final g:Landroidx/fragment/app/k1;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/o0;)V
    .locals 1

    .line 1
    new-instance v0, Landroid/os/Handler;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Landroidx/fragment/app/t0;->d:Landroidx/fragment/app/o0;

    .line 10
    .line 11
    iput-object p1, p0, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 12
    .line 13
    iput-object v0, p0, Landroidx/fragment/app/t0;->f:Landroid/os/Handler;

    .line 14
    .line 15
    new-instance p1, Landroidx/fragment/app/k1;

    .line 16
    .line 17
    invoke-direct {p1}, Landroidx/fragment/app/j1;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Landroidx/fragment/app/t0;->g:Landroidx/fragment/app/k1;

    .line 21
    .line 22
    return-void
.end method
