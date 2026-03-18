.class public final Lmf/d;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lyj/b;

.field public final e:Ll20/g;

.field public final f:Lyy0/l1;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;


# direct methods
.method public constructor <init>(Lyj/b;Ll20/g;Lyy0/l1;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmf/d;->d:Lyj/b;

    .line 5
    .line 6
    iput-object p2, p0, Lmf/d;->e:Ll20/g;

    .line 7
    .line 8
    iput-object p3, p0, Lmf/d;->f:Lyy0/l1;

    .line 9
    .line 10
    new-instance p1, Llc/q;

    .line 11
    .line 12
    sget-object p2, Llc/a;->c:Llc/c;

    .line 13
    .line 14
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Lmf/d;->g:Lyy0/c2;

    .line 22
    .line 23
    iput-object p1, p0, Lmf/d;->h:Lyy0/c2;

    .line 24
    .line 25
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    new-instance p2, Lm70/i0;

    .line 30
    .line 31
    const/16 p3, 0x9

    .line 32
    .line 33
    const/4 v0, 0x0

    .line 34
    invoke-direct {p2, p0, v0, p3}, Lm70/i0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p0, 0x3

    .line 38
    invoke-static {p1, v0, v0, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    new-instance v0, Llc/q;

    .line 2
    .line 3
    sget-object v1, Llc/a;->c:Llc/c;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lmf/d;->g:Lyy0/c2;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-virtual {v1, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v1, Lk20/a;

    .line 22
    .line 23
    const/16 v3, 0x19

    .line 24
    .line 25
    invoke-direct {v1, p0, v2, v3}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x3

    .line 29
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    return-void
.end method
