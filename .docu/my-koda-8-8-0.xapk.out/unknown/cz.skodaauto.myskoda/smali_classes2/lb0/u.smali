.class public final Llb0/u;
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


# direct methods
.method public constructor <init>(Lkf0/m;Ljb0/x;Lsf0/a;Lkf0/j0;Lko0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llb0/u;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Llb0/u;->b:Ljb0/x;

    .line 7
    .line 8
    iput-object p3, p0, Llb0/u;->c:Lsf0/a;

    .line 9
    .line 10
    iput-object p4, p0, Llb0/u;->d:Lkf0/j0;

    .line 11
    .line 12
    iput-object p5, p0, Llb0/u;->e:Lko0/f;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/List;)Lyy0/m1;
    .locals 4

    .line 1
    iget-object v0, p0, Llb0/u;->a:Lkf0/m;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Llb0/t;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct {v1, p0, v3, v2}, Llb0/t;-><init>(Llb0/u;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Llp/sf;->c(Lyy0/m1;Lay0/n;)Lyy0/m1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v1, Lac/k;

    .line 19
    .line 20
    check-cast p1, Ljava/util/ArrayList;

    .line 21
    .line 22
    const/16 v2, 0x17

    .line 23
    .line 24
    invoke-direct {v1, v2, p0, p1, v3}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance v0, Li50/p;

    .line 32
    .line 33
    const/16 v1, 0x17

    .line 34
    .line 35
    invoke-direct {v0, p0, v3, v1}, Li50/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    invoke-static {v0, p1}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iget-object v0, p0, Llb0/u;->c:Lsf0/a;

    .line 43
    .line 44
    invoke-static {p1, v0, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    new-instance v0, Llb0/t;

    .line 49
    .line 50
    const/4 v1, 0x1

    .line 51
    invoke-direct {v0, p0, v3, v1}, Llb0/t;-><init>(Llb0/u;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    invoke-static {v0, p1}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/util/List;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Llb0/u;->a(Ljava/util/List;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
