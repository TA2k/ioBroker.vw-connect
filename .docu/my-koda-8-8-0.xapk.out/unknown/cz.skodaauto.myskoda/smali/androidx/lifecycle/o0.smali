.class public final Landroidx/lifecycle/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final synthetic d:Landroidx/lifecycle/p;

.field public final synthetic e:Lkotlin/jvm/internal/f0;

.field public final synthetic f:Lvy0/b0;

.field public final synthetic g:Landroidx/lifecycle/p;

.field public final synthetic h:Lvy0/l;

.field public final synthetic i:Lez0/c;

.field public final synthetic j:Lrx0/i;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/p;Lkotlin/jvm/internal/f0;Lvy0/b0;Landroidx/lifecycle/p;Lvy0/l;Lez0/c;Lay0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/lifecycle/o0;->d:Landroidx/lifecycle/p;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/lifecycle/o0;->e:Lkotlin/jvm/internal/f0;

    .line 7
    .line 8
    iput-object p3, p0, Landroidx/lifecycle/o0;->f:Lvy0/b0;

    .line 9
    .line 10
    iput-object p4, p0, Landroidx/lifecycle/o0;->g:Landroidx/lifecycle/p;

    .line 11
    .line 12
    iput-object p5, p0, Landroidx/lifecycle/o0;->h:Lvy0/l;

    .line 13
    .line 14
    iput-object p6, p0, Landroidx/lifecycle/o0;->i:Lez0/c;

    .line 15
    .line 16
    check-cast p7, Lrx0/i;

    .line 17
    .line 18
    iput-object p7, p0, Landroidx/lifecycle/o0;->j:Lrx0/i;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 3

    .line 1
    iget-object p1, p0, Landroidx/lifecycle/o0;->d:Landroidx/lifecycle/p;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/lifecycle/o0;->e:Lkotlin/jvm/internal/f0;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-ne p2, p1, :cond_0

    .line 7
    .line 8
    new-instance p1, La7/k;

    .line 9
    .line 10
    iget-object p2, p0, Landroidx/lifecycle/o0;->i:Lez0/c;

    .line 11
    .line 12
    iget-object v2, p0, Landroidx/lifecycle/o0;->j:Lrx0/i;

    .line 13
    .line 14
    invoke-direct {p1, p2, v2, v1}, La7/k;-><init>(Lez0/c;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    const/4 p2, 0x3

    .line 18
    iget-object p0, p0, Landroidx/lifecycle/o0;->f:Lvy0/b0;

    .line 19
    .line 20
    invoke-static {p0, v1, v1, p1, p2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    iput-object p0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 25
    .line 26
    return-void

    .line 27
    :cond_0
    iget-object p1, p0, Landroidx/lifecycle/o0;->g:Landroidx/lifecycle/p;

    .line 28
    .line 29
    if-ne p2, p1, :cond_2

    .line 30
    .line 31
    iget-object p1, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p1, Lvy0/i1;

    .line 34
    .line 35
    if-eqz p1, :cond_1

    .line 36
    .line 37
    invoke-interface {p1, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    iput-object v1, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 41
    .line 42
    :cond_2
    sget-object p1, Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;

    .line 43
    .line 44
    if-ne p2, p1, :cond_3

    .line 45
    .line 46
    iget-object p0, p0, Landroidx/lifecycle/o0;->h:Lvy0/l;

    .line 47
    .line 48
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :cond_3
    return-void
.end method
