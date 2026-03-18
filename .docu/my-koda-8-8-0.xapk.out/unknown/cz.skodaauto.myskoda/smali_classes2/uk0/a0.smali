.class public final Luk0/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lal0/s0;

.field public final b:Lal0/p0;

.field public final c:Lwj0/r;

.field public final d:Luk0/h;

.field public final e:Luk0/r;


# direct methods
.method public constructor <init>(Lal0/s0;Lal0/p0;Lwj0/r;Luk0/h;Luk0/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/a0;->a:Lal0/s0;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/a0;->b:Lal0/p0;

    .line 7
    .line 8
    iput-object p3, p0, Luk0/a0;->c:Lwj0/r;

    .line 9
    .line 10
    iput-object p4, p0, Luk0/a0;->d:Luk0/h;

    .line 11
    .line 12
    iput-object p5, p0, Luk0/a0;->e:Luk0/r;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Luk0/a0;->a:Lal0/s0;

    .line 4
    .line 5
    invoke-virtual {p1}, Lal0/s0;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lyy0/i;

    .line 10
    .line 11
    iget-object p2, p0, Luk0/a0;->b:Lal0/p0;

    .line 12
    .line 13
    invoke-virtual {p2}, Lal0/p0;->invoke()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    check-cast p2, Lyy0/i;

    .line 18
    .line 19
    iget-object v0, p0, Luk0/a0;->c:Lwj0/r;

    .line 20
    .line 21
    invoke-virtual {v0}, Lwj0/r;->invoke()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lyy0/i;

    .line 26
    .line 27
    new-instance v1, Li50/y;

    .line 28
    .line 29
    const/4 v2, 0x2

    .line 30
    const/4 v3, 0x0

    .line 31
    invoke-direct {v1, p0, v3, v2}, Li50/y;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    invoke-static {p1, p2, v0, v1}, Lyy0/u;->m(Lyy0/i;Lyy0/i;Lyy0/i;Lay0/p;)Lyy0/f1;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-static {p1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    new-instance p2, Ltr0/e;

    .line 43
    .line 44
    const/16 v0, 0xe

    .line 45
    .line 46
    invoke-direct {p2, p1, v3, p0, v0}, Ltr0/e;-><init>(Lyy0/i;Lkotlin/coroutines/Continuation;Ltr0/c;I)V

    .line 47
    .line 48
    .line 49
    new-instance p0, Lyy0/m1;

    .line 50
    .line 51
    invoke-direct {p0, p2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 52
    .line 53
    .line 54
    return-object p0
.end method
