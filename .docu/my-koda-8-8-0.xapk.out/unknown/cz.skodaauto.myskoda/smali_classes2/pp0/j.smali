.class public final Lpp0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/k;

.field public final b:Lkf0/o;

.field public final c:Lpp0/c0;

.field public final d:Lnp0/c;

.field public final e:Lpp0/l0;


# direct methods
.method public constructor <init>(Lkf0/k;Lkf0/o;Lpp0/c0;Lnp0/c;Lpp0/l0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/j;->a:Lkf0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/j;->b:Lkf0/o;

    .line 7
    .line 8
    iput-object p3, p0, Lpp0/j;->c:Lpp0/c0;

    .line 9
    .line 10
    iput-object p4, p0, Lpp0/j;->d:Lnp0/c;

    .line 11
    .line 12
    iput-object p5, p0, Lpp0/j;->e:Lpp0/l0;

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
    iget-object p1, p0, Lpp0/j;->c:Lpp0/c0;

    .line 4
    .line 5
    check-cast p1, Lnp0/b;

    .line 6
    .line 7
    iget-object p1, p1, Lnp0/b;->i:Lyy0/l1;

    .line 8
    .line 9
    invoke-static {p1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iget-object p2, p0, Lpp0/j;->e:Lpp0/l0;

    .line 14
    .line 15
    invoke-virtual {p2}, Lpp0/l0;->invoke()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    check-cast p2, Lyy0/i;

    .line 20
    .line 21
    invoke-static {p2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    new-instance v0, Lal0/y0;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    const/16 v2, 0x13

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    invoke-direct {v0, v1, v3, v2}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    new-instance v1, Lbn0/f;

    .line 35
    .line 36
    const/4 v2, 0x5

    .line 37
    invoke-direct {v1, p1, p2, v0, v2}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 38
    .line 39
    .line 40
    new-instance p1, Lpp0/i;

    .line 41
    .line 42
    invoke-direct {p1, v3, p0}, Lpp0/i;-><init>(Lkotlin/coroutines/Continuation;Lpp0/j;)V

    .line 43
    .line 44
    .line 45
    invoke-static {v1, p1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0
.end method
