.class public final Lty/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lsf0/a;

.field public final c:Lkf0/j0;

.field public final d:Lry/k;

.field public final e:Lko0/f;


# direct methods
.method public constructor <init>(Lkf0/m;Lkf0/j0;Lko0/f;Lry/k;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lty/o;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p5, p0, Lty/o;->b:Lsf0/a;

    .line 7
    .line 8
    iput-object p2, p0, Lty/o;->c:Lkf0/j0;

    .line 9
    .line 10
    iput-object p4, p0, Lty/o;->d:Lry/k;

    .line 11
    .line 12
    iput-object p3, p0, Lty/o;->e:Lko0/f;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/List;)Lyy0/m1;
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lty/o;->a:Lkf0/m;

    .line 7
    .line 8
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    new-instance v1, Lty/n;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-direct {v1, p0, v3, v2}, Lty/n;-><init>(Lty/o;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {v0, v1}, Llp/sf;->c(Lyy0/m1;Lay0/n;)Lyy0/m1;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    new-instance v1, Lo20/c;

    .line 24
    .line 25
    const/16 v2, 0x13

    .line 26
    .line 27
    invoke-direct {v1, v2, p0, p1, v3}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    new-instance v0, Ls10/a0;

    .line 35
    .line 36
    const/4 v1, 0x5

    .line 37
    invoke-direct {v0, p0, v3, v1}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v0, p1}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    iget-object v0, p0, Lty/o;->b:Lsf0/a;

    .line 45
    .line 46
    invoke-static {p1, v0, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    new-instance v0, Lty/n;

    .line 51
    .line 52
    const/4 v1, 0x1

    .line 53
    invoke-direct {v0, p0, v3, v1}, Lty/n;-><init>(Lty/o;Lkotlin/coroutines/Continuation;I)V

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
    check-cast v0, Ljava/util/List;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lty/o;->a(Ljava/util/List;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
