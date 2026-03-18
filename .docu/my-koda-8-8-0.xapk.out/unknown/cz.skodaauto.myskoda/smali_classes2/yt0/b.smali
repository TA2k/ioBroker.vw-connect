.class public final Lyt0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwt0/b;


# direct methods
.method public constructor <init>(Lwt0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyt0/b;->a:Lwt0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lzt0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lyt0/b;->b(Lzt0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lzt0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lvy0/l;

    .line 2
    .line 3
    invoke-static {p2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, v1, p2}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lvy0/l;->q()V

    .line 12
    .line 13
    .line 14
    new-instance p2, Lag/t;

    .line 15
    .line 16
    const/16 v1, 0x12

    .line 17
    .line 18
    iget-object p0, p0, Lyt0/b;->a:Lwt0/b;

    .line 19
    .line 20
    invoke-direct {p2, p0, v1}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, p2}, Lvy0/l;->s(Lay0/k;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lwt0/b;->a:Lyy0/q1;

    .line 27
    .line 28
    new-instance p2, Lzt0/b;

    .line 29
    .line 30
    new-instance v1, Lwt0/a;

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    invoke-direct {v1, v0, v2}, Lwt0/a;-><init>(Lvy0/l;I)V

    .line 34
    .line 35
    .line 36
    invoke-direct {p2, p1, v1}, Lzt0/b;-><init>(Lzt0/a;Lwt0/a;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, p2}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Lvy0/l;->p()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 47
    .line 48
    return-object p0
.end method
