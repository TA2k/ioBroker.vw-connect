.class public final Llz/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbn0/g;

.field public final b:Llz/e;

.field public final c:Ljr0/c;


# direct methods
.method public constructor <init>(Lbn0/g;Llz/e;Ljr0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llz/i;->a:Lbn0/g;

    .line 5
    .line 6
    iput-object p2, p0, Llz/i;->b:Llz/e;

    .line 7
    .line 8
    iput-object p3, p0, Llz/i;->c:Ljr0/c;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Llz/i;Lcn0/c;Lkr0/c;)V
    .locals 2

    .line 1
    iget-object p0, p0, Llz/i;->c:Ljr0/c;

    .line 2
    .line 3
    iget-object v0, p1, Lcn0/c;->b:Lcn0/b;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_1

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    if-eq v0, v1, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    invoke-static {p2, p1}, Llp/ge;->c(Lkr0/c;Lcn0/c;)Lkr0/b;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0, p1}, Ljr0/c;->a(Lkr0/b;)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    invoke-static {p2}, Lnm0/b;->j(Lkr0/c;)Lkr0/b;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p0, p1}, Ljr0/c;->a(Lkr0/b;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final b(Lmz/h;)Lyy0/x;
    .locals 5

    .line 1
    new-instance v0, Lbn0/c;

    .line 2
    .line 3
    iget-object v1, p1, Lmz/h;->d:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p1, Lmz/h;->e:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lbn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Llz/i;->a:Lbn0/g;

    .line 11
    .line 12
    invoke-virtual {v1, v0}, Lbn0/g;->a(Lbn0/c;)Lzy0/j;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    new-instance v1, Lbq0/i;

    .line 17
    .line 18
    const/16 v2, 0x1a

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-direct {v1, p0, v3, v2}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    new-instance v2, Lac/l;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lac/l;-><init>(Lzy0/j;Lay0/k;)V

    .line 27
    .line 28
    .line 29
    new-instance v0, Lal0/m0;

    .line 30
    .line 31
    const/4 v1, 0x2

    .line 32
    const/16 v4, 0x12

    .line 33
    .line 34
    invoke-direct {v0, v1, v3, v4}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    new-instance v1, Lne0/n;

    .line 38
    .line 39
    invoke-direct {v1, v0, v2}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 40
    .line 41
    .line 42
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    new-instance v1, Llb0/q0;

    .line 47
    .line 48
    const/4 v2, 0x5

    .line 49
    invoke-direct {v1, p0, v3, v2}, Llb0/q0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    new-instance v2, Lne0/n;

    .line 53
    .line 54
    const/4 v4, 0x5

    .line 55
    invoke-direct {v2, v0, v1, v4}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 56
    .line 57
    .line 58
    new-instance v0, Lal0/y0;

    .line 59
    .line 60
    const/16 v1, 0xf

    .line 61
    .line 62
    invoke-direct {v0, v1, p1, v3, p0}, Lal0/y0;-><init>(ILjava/lang/Object;Lkotlin/coroutines/Continuation;Ltr0/d;)V

    .line 63
    .line 64
    .line 65
    new-instance p0, Lyy0/x;

    .line 66
    .line 67
    invoke-direct {p0, v2, v0}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 68
    .line 69
    .line 70
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lmz/h;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Llz/i;->b(Lmz/h;)Lyy0/x;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
