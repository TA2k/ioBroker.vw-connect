.class public final Lz40/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/x0;

.field public final b:Lal0/h0;

.field public final c:Lal0/q0;

.field public final d:Lal0/j;

.field public final e:Lal0/c;

.field public final f:Lwj0/x;

.field public final g:Lwj0/g;

.field public final h:Lyy0/i;


# direct methods
.method public constructor <init>(Lwj0/k;Lal0/x0;Lal0/h0;Lal0/q0;Lal0/j;Lal0/c;Lwj0/x;Lwj0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lz40/c;->a:Lal0/x0;

    .line 5
    .line 6
    iput-object p3, p0, Lz40/c;->b:Lal0/h0;

    .line 7
    .line 8
    iput-object p4, p0, Lz40/c;->c:Lal0/q0;

    .line 9
    .line 10
    iput-object p5, p0, Lz40/c;->d:Lal0/j;

    .line 11
    .line 12
    iput-object p6, p0, Lz40/c;->e:Lal0/c;

    .line 13
    .line 14
    iput-object p7, p0, Lz40/c;->f:Lwj0/x;

    .line 15
    .line 16
    iput-object p8, p0, Lz40/c;->g:Lwj0/g;

    .line 17
    .line 18
    invoke-virtual {p1}, Lwj0/k;->invoke()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, Lyy0/i;

    .line 23
    .line 24
    new-instance p2, Lrz/k;

    .line 25
    .line 26
    const/16 p3, 0x16

    .line 27
    .line 28
    invoke-direct {p2, p1, p3}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 29
    .line 30
    .line 31
    new-instance p1, Lxy/f;

    .line 32
    .line 33
    const/16 p3, 0x18

    .line 34
    .line 35
    invoke-direct {p1, p3}, Lxy/f;-><init>(I)V

    .line 36
    .line 37
    .line 38
    new-instance p3, Lv2/k;

    .line 39
    .line 40
    const/16 p4, 0x12

    .line 41
    .line 42
    invoke-direct {p3, p4, p1}, Lv2/k;-><init>(ILay0/k;)V

    .line 43
    .line 44
    .line 45
    new-instance p1, Le71/e;

    .line 46
    .line 47
    const/4 p4, 0x0

    .line 48
    invoke-direct {p1, p3, p2, p4}, Le71/e;-><init>(Lay0/k;Lyy0/i;Lkotlin/coroutines/Continuation;)V

    .line 49
    .line 50
    .line 51
    new-instance p2, Lyy0/m1;

    .line 52
    .line 53
    invoke-direct {p2, p1}, Lyy0/m1;-><init>(Lay0/o;)V

    .line 54
    .line 55
    .line 56
    invoke-static {p2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    iput-object p1, p0, Lz40/c;->h:Lyy0/i;

    .line 61
    .line 62
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lz40/c;->a:Lal0/x0;

    .line 7
    .line 8
    invoke-virtual {v1}, Lal0/x0;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Lyy0/i;

    .line 13
    .line 14
    new-instance v2, Lqa0/a;

    .line 15
    .line 16
    const/16 v3, 0x1d

    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    invoke-direct {v2, p0, v4, v3}, Lqa0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {v1, v2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    new-instance v2, Lru0/j;

    .line 27
    .line 28
    invoke-direct {v2, v4, v0, p0}, Lru0/j;-><init>(Lkotlin/coroutines/Continuation;Lkotlin/jvm/internal/f0;Lz40/c;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1, v2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-static {p0}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const/4 v0, -0x1

    .line 40
    invoke-static {p0, v0}, Lyy0/u;->g(Lyy0/i;I)Lyy0/i;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method
