.class public final Lqc0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/b0;

.field public final b:Lif0/f0;

.field public final c:Lqc0/c;

.field public final d:Lqc0/b;


# direct methods
.method public constructor <init>(Lkf0/b0;Lif0/f0;Lqc0/c;Lqc0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqc0/e;->a:Lkf0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lqc0/e;->b:Lif0/f0;

    .line 7
    .line 8
    iput-object p3, p0, Lqc0/e;->c:Lqc0/c;

    .line 9
    .line 10
    iput-object p4, p0, Lqc0/e;->d:Lqc0/b;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lqc0/e;->a:Lkf0/b0;

    .line 4
    .line 5
    invoke-virtual {p1}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lyy0/i;

    .line 10
    .line 11
    new-instance p2, Lrz/k;

    .line 12
    .line 13
    const/16 v0, 0x15

    .line 14
    .line 15
    invoke-direct {p2, p1, v0}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 16
    .line 17
    .line 18
    invoke-static {p2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    new-instance p2, Lqa0/a;

    .line 23
    .line 24
    const/4 v0, 0x1

    .line 25
    const/4 v1, 0x0

    .line 26
    invoke-direct {p2, v1, p0, v0}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {p1, p2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-static {p1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    new-instance p2, Llb0/y;

    .line 38
    .line 39
    const/4 v0, 0x7

    .line 40
    invoke-direct {p2, v0, p1, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    new-instance p1, Lo20/c;

    .line 44
    .line 45
    invoke-direct {p1, v1, p0}, Lo20/c;-><init>(Lkotlin/coroutines/Continuation;Lqc0/e;)V

    .line 46
    .line 47
    .line 48
    invoke-static {p2, p1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
