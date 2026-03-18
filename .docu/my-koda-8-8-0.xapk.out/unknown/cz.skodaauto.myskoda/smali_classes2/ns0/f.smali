.class public final Lns0/f;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lks0/e;

.field public final i:Lks0/v;

.field public final j:Lks0/x;

.field public final k:Lks0/a;

.field public final l:Lks0/i;

.field public final m:Lks0/g;

.field public final n:Lug0/b;

.field public final o:Lkf0/i;

.field public final p:Lzd0/a;

.field public final q:Lrq0/f;

.field public final r:Lij0/a;

.field public s:Z

.field public t:Z

.field public u:Z


# direct methods
.method public constructor <init>(Lks0/e;Lks0/v;Lks0/x;Lks0/a;Lks0/i;Lks0/g;Lug0/b;Lkf0/i;Lzd0/a;Lrq0/f;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lns0/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lns0/d;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lns0/f;->h:Lks0/e;

    .line 11
    .line 12
    iput-object p2, p0, Lns0/f;->i:Lks0/v;

    .line 13
    .line 14
    iput-object p3, p0, Lns0/f;->j:Lks0/x;

    .line 15
    .line 16
    iput-object p4, p0, Lns0/f;->k:Lks0/a;

    .line 17
    .line 18
    iput-object p5, p0, Lns0/f;->l:Lks0/i;

    .line 19
    .line 20
    iput-object p6, p0, Lns0/f;->m:Lks0/g;

    .line 21
    .line 22
    iput-object p7, p0, Lns0/f;->n:Lug0/b;

    .line 23
    .line 24
    iput-object p8, p0, Lns0/f;->o:Lkf0/i;

    .line 25
    .line 26
    iput-object p9, p0, Lns0/f;->p:Lzd0/a;

    .line 27
    .line 28
    iput-object p10, p0, Lns0/f;->q:Lrq0/f;

    .line 29
    .line 30
    iput-object p11, p0, Lns0/f;->r:Lij0/a;

    .line 31
    .line 32
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    new-instance p2, Lns0/c;

    .line 37
    .line 38
    const/4 p3, 0x0

    .line 39
    const/4 p4, 0x0

    .line 40
    invoke-direct {p2, p0, p4, p3}, Lns0/c;-><init>(Lns0/f;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    const/4 p3, 0x3

    .line 44
    invoke-static {p1, p4, p4, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 45
    .line 46
    .line 47
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    new-instance p2, Lna/e;

    .line 52
    .line 53
    const/16 p5, 0x8

    .line 54
    .line 55
    invoke-direct {p2, p0, p4, p5}, Lna/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 56
    .line 57
    .line 58
    invoke-static {p1, p4, p4, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public static final h(Lns0/f;Lne0/s;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lns0/f;->p:Lzd0/a;

    .line 2
    .line 3
    instance-of v1, p1, Lne0/d;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    check-cast p1, Lns0/d;

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    new-instance p1, Lns0/d;

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    invoke-direct {p1, v0}, Lns0/d;-><init>(Z)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    instance-of v1, p1, Lne0/c;

    .line 27
    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    check-cast p1, Lne0/t;

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Lzd0/a;->a(Lne0/t;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_1
    instance-of v1, p1, Lne0/e;

    .line 37
    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    new-instance v1, Lns0/a;

    .line 41
    .line 42
    const/4 v2, 0x0

    .line 43
    invoke-direct {v1, p0, v2}, Lns0/a;-><init>(Lns0/f;I)V

    .line 44
    .line 45
    .line 46
    invoke-static {p0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 47
    .line 48
    .line 49
    check-cast p1, Lne0/t;

    .line 50
    .line 51
    invoke-virtual {v0, p1}, Lzd0/a;->a(Lne0/t;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_2
    new-instance p0, La8/r0;

    .line 56
    .line 57
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 58
    .line 59
    .line 60
    throw p0
.end method
