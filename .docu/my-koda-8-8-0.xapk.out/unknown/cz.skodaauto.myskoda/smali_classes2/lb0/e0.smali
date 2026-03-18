.class public final Llb0/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Ljb0/x;

.field public final c:Lsf0/a;

.field public final d:Lkf0/j0;

.field public final e:Lko0/f;

.field public final f:Ljb0/e0;


# direct methods
.method public constructor <init>(Lkf0/m;Ljb0/x;Lsf0/a;Lkf0/j0;Lko0/f;Ljb0/e0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llb0/e0;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Llb0/e0;->b:Ljb0/x;

    .line 7
    .line 8
    iput-object p3, p0, Llb0/e0;->c:Lsf0/a;

    .line 9
    .line 10
    iput-object p4, p0, Llb0/e0;->d:Lkf0/j0;

    .line 11
    .line 12
    iput-object p5, p0, Llb0/e0;->e:Lko0/f;

    .line 13
    .line 14
    iput-object p6, p0, Llb0/e0;->f:Ljb0/e0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a(Lqr0/q;)Lyy0/m1;
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Llb0/e0;->a:Lkf0/m;

    .line 7
    .line 8
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    new-instance v1, Llb0/d0;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-direct {v1, p0, v3, v2}, Llb0/d0;-><init>(Llb0/e0;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {v0, v1}, Llp/sf;->c(Lyy0/m1;Lay0/n;)Lyy0/m1;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    new-instance v1, Le71/e;

    .line 24
    .line 25
    const/4 v2, 0x4

    .line 26
    invoke-direct {v1, v2, p1, v3, p0}, Le71/e;-><init>(ILjava/lang/Object;Lkotlin/coroutines/Continuation;Ltr0/d;)V

    .line 27
    .line 28
    .line 29
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    new-instance v0, Li50/p;

    .line 34
    .line 35
    const/16 v1, 0x1a

    .line 36
    .line 37
    invoke-direct {v0, p0, v3, v1}, Li50/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v0, p1}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    iget-object v0, p0, Llb0/e0;->c:Lsf0/a;

    .line 45
    .line 46
    invoke-static {p1, v0, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    new-instance v0, Llb0/d0;

    .line 51
    .line 52
    const/4 v1, 0x1

    .line 53
    invoke-direct {v0, p0, v3, v1}, Llb0/d0;-><init>(Llb0/e0;Lkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v0, p1}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lqr0/q;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Llb0/e0;->a(Lqr0/q;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
