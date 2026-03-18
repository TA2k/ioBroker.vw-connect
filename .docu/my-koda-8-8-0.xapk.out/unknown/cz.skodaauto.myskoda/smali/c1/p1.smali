.class public final Lc1/p1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/t2;


# instance fields
.field public final d:Lc1/t1;

.field public e:Lay0/k;

.field public f:Lkotlin/jvm/internal/n;

.field public final synthetic g:Lc1/q1;


# direct methods
.method public constructor <init>(Lc1/q1;Lc1/t1;Lay0/k;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc1/p1;->g:Lc1/q1;

    .line 5
    .line 6
    iput-object p2, p0, Lc1/p1;->d:Lc1/t1;

    .line 7
    .line 8
    iput-object p3, p0, Lc1/p1;->e:Lay0/k;

    .line 9
    .line 10
    check-cast p4, Lkotlin/jvm/internal/n;

    .line 11
    .line 12
    iput-object p4, p0, Lc1/p1;->f:Lkotlin/jvm/internal/n;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lc1/r1;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lc1/p1;->f:Lkotlin/jvm/internal/n;

    .line 2
    .line 3
    invoke-interface {p1}, Lc1/r1;->a()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v1, p0, Lc1/p1;->g:Lc1/q1;

    .line 12
    .line 13
    iget-object v1, v1, Lc1/q1;->c:Lc1/w1;

    .line 14
    .line 15
    invoke-virtual {v1}, Lc1/w1;->g()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    iget-object v2, p0, Lc1/p1;->d:Lc1/t1;

    .line 20
    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    iget-object v1, p0, Lc1/p1;->f:Lkotlin/jvm/internal/n;

    .line 24
    .line 25
    invoke-interface {p1}, Lc1/r1;->b()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    invoke-interface {v1, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    iget-object p0, p0, Lc1/p1;->e:Lay0/k;

    .line 34
    .line 35
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Lc1/a0;

    .line 40
    .line 41
    invoke-virtual {v2, v1, v0, p0}, Lc1/t1;->e(Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_0
    iget-object p0, p0, Lc1/p1;->e:Lay0/k;

    .line 46
    .line 47
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Lc1/a0;

    .line 52
    .line 53
    invoke-virtual {v2, v0, p0}, Lc1/t1;->f(Ljava/lang/Object;Lc1/a0;)V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lc1/p1;->g:Lc1/q1;

    .line 2
    .line 3
    iget-object v0, v0, Lc1/q1;->c:Lc1/w1;

    .line 4
    .line 5
    invoke-virtual {v0}, Lc1/w1;->f()Lc1/r1;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0, v0}, Lc1/p1;->a(Lc1/r1;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lc1/p1;->d:Lc1/t1;

    .line 13
    .line 14
    iget-object p0, p0, Lc1/t1;->m:Ll2/j1;

    .line 15
    .line 16
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
