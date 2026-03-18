.class public final Llh/h;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lrx0/i;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/l1;

.field public g:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ldi/b;Lay0/n;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    check-cast p2, Lrx0/i;

    .line 5
    .line 6
    iput-object p2, p0, Llh/h;->d:Lrx0/i;

    .line 7
    .line 8
    new-instance v0, Llh/g;

    .line 9
    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v6, 0x0

    .line 12
    const-string v1, ""

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x0

    .line 16
    const/4 v4, 0x0

    .line 17
    invoke-direct/range {v0 .. v6}, Llh/g;-><init>(Ljava/lang/String;ZZZZZ)V

    .line 18
    .line 19
    .line 20
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    iput-object p2, p0, Llh/h;->e:Lyy0/c2;

    .line 25
    .line 26
    new-instance v0, Lyy0/l1;

    .line 27
    .line 28
    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Llh/h;->f:Lyy0/l1;

    .line 32
    .line 33
    iget-object p1, p1, Ldi/b;->b:Ljava/lang/String;

    .line 34
    .line 35
    if-nez p1, :cond_0

    .line 36
    .line 37
    const-string p1, ""

    .line 38
    .line 39
    :cond_0
    iput-object p1, p0, Llh/h;->g:Ljava/lang/String;

    .line 40
    .line 41
    invoke-virtual {p0, p1}, Llh/h;->a(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)V
    .locals 10

    .line 1
    :goto_0
    iget-object v0, p0, Llh/h;->e:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    move-object v2, v1

    .line 8
    check-cast v2, Llh/g;

    .line 9
    .line 10
    iget-object v3, p0, Llh/h;->g:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    xor-int/lit8 v4, v3, 0x1

    .line 17
    .line 18
    const/4 v8, 0x0

    .line 19
    const/16 v9, 0x30

    .line 20
    .line 21
    const/4 v5, 0x0

    .line 22
    const/4 v6, 0x0

    .line 23
    const/4 v7, 0x0

    .line 24
    move-object v3, p1

    .line 25
    invoke-static/range {v2 .. v9}, Llh/g;->a(Llh/g;Ljava/lang/String;ZZZZZI)Llh/g;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_0

    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    move-object p1, v3

    .line 37
    goto :goto_0
.end method

.method public final b(Llh/f;)V
    .locals 9

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Llh/d;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p1, Llh/d;

    .line 11
    .line 12
    iget-object p1, p1, Llh/d;->a:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Llh/h;->a(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    instance-of v0, p1, Llh/c;

    .line 19
    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    new-instance v0, Lk20/a;

    .line 27
    .line 28
    const/16 v1, 0xd

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-direct {v0, p0, v2, v1}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x3

    .line 35
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    instance-of p1, p1, Llh/e;

    .line 40
    .line 41
    if-eqz p1, :cond_3

    .line 42
    .line 43
    :cond_2
    iget-object p1, p0, Llh/h;->e:Lyy0/c2;

    .line 44
    .line 45
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    move-object v1, v0

    .line 50
    check-cast v1, Llh/g;

    .line 51
    .line 52
    const/4 v7, 0x0

    .line 53
    const/16 v8, 0x1f

    .line 54
    .line 55
    const/4 v2, 0x0

    .line 56
    const/4 v3, 0x0

    .line 57
    const/4 v4, 0x0

    .line 58
    const/4 v5, 0x0

    .line 59
    const/4 v6, 0x0

    .line 60
    invoke-static/range {v1 .. v8}, Llh/g;->a(Llh/g;Ljava/lang/String;ZZZZZI)Llh/g;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    if-eqz p1, :cond_2

    .line 69
    .line 70
    return-void

    .line 71
    :cond_3
    new-instance p0, La8/r0;

    .line 72
    .line 73
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 74
    .line 75
    .line 76
    throw p0
.end method
