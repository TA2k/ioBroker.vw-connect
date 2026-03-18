.class public final Landroidx/fragment/app/f0;
.super Landroidx/fragment/app/h0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lp/a;

.field public final synthetic b:Ljava/util/concurrent/atomic/AtomicReference;

.field public final synthetic c:Lf/a;

.field public final synthetic d:Le/b;

.field public final synthetic e:Landroidx/fragment/app/j0;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/j0;Lp/a;Ljava/util/concurrent/atomic/AtomicReference;Lf/a;Le/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/fragment/app/f0;->e:Landroidx/fragment/app/j0;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/fragment/app/f0;->a:Lp/a;

    .line 7
    .line 8
    iput-object p3, p0, Landroidx/fragment/app/f0;->b:Ljava/util/concurrent/atomic/AtomicReference;

    .line 9
    .line 10
    iput-object p4, p0, Landroidx/fragment/app/f0;->c:Lf/a;

    .line 11
    .line 12
    iput-object p5, p0, Landroidx/fragment/app/f0;->d:Le/b;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/f0;->e:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->generateActivityResultKey()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget-object v2, p0, Landroidx/fragment/app/f0;->a:Lp/a;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-interface {v2, v3}, Lp/a;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    check-cast v2, Le/h;

    .line 15
    .line 16
    iget-object v3, p0, Landroidx/fragment/app/f0;->c:Lf/a;

    .line 17
    .line 18
    iget-object v4, p0, Landroidx/fragment/app/f0;->d:Le/b;

    .line 19
    .line 20
    invoke-virtual {v2, v1, v0, v3, v4}, Le/h;->c(Ljava/lang/String;Landroidx/lifecycle/x;Lf/a;Le/b;)Le/g;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget-object p0, p0, Landroidx/fragment/app/f0;->b:Ljava/util/concurrent/atomic/AtomicReference;

    .line 25
    .line 26
    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
