.class public final Landroidx/lifecycle/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/j0;


# instance fields
.field public final a:Landroidx/lifecycle/g0;

.field public final b:Lh0/g1;

.field public c:I


# direct methods
.method public constructor <init>(Landroidx/lifecycle/g0;Lh0/g1;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Landroidx/lifecycle/h0;->c:I

    .line 6
    .line 7
    iput-object p1, p0, Landroidx/lifecycle/h0;->a:Landroidx/lifecycle/g0;

    .line 8
    .line 9
    iput-object p2, p0, Landroidx/lifecycle/h0;->b:Lh0/g1;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, Landroidx/lifecycle/h0;->c:I

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/lifecycle/h0;->a:Landroidx/lifecycle/g0;

    .line 4
    .line 5
    iget v1, v1, Landroidx/lifecycle/g0;->g:I

    .line 6
    .line 7
    if-eq v0, v1, :cond_0

    .line 8
    .line 9
    iput v1, p0, Landroidx/lifecycle/h0;->c:I

    .line 10
    .line 11
    iget-object p0, p0, Landroidx/lifecycle/h0;->b:Lh0/g1;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lh0/g1;->a(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public final b()V
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/h0;->a:Landroidx/lifecycle/g0;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Landroidx/lifecycle/g0;->i(Landroidx/lifecycle/j0;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
