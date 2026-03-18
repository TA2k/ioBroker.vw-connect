.class public final Lrt0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbn0/g;

.field public final b:Lrt0/j;

.field public final c:Ljr0/c;


# direct methods
.method public constructor <init>(Lbn0/g;Lrt0/j;Ljr0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrt0/o;->a:Lbn0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lrt0/o;->b:Lrt0/j;

    .line 7
    .line 8
    iput-object p3, p0, Lrt0/o;->c:Ljr0/c;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lrt0/o;Lcn0/c;Lkr0/c;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lrt0/o;->c:Ljr0/c;

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
.method public final b()Lyy0/x;
    .locals 6

    .line 1
    sget-object v0, Lst0/h;->d:[Lst0/h;

    .line 2
    .line 3
    new-instance v0, Lbn0/c;

    .line 4
    .line 5
    const-string v1, "vehicle-access"

    .line 6
    .line 7
    const-string v2, "lock-vehicle"

    .line 8
    .line 9
    invoke-direct {v0, v1, v2}, Lbn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lrt0/o;->a:Lbn0/g;

    .line 13
    .line 14
    invoke-virtual {v1, v0}, Lbn0/g;->a(Lbn0/c;)Lzy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v1, Lq10/k;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    const/4 v3, 0x5

    .line 22
    invoke-direct {v1, p0, v2, v3}, Lq10/k;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    new-instance v4, Lac/l;

    .line 26
    .line 27
    invoke-direct {v4, v0, v1}, Lac/l;-><init>(Lzy0/j;Lay0/k;)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Lal0/m0;

    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    const/16 v5, 0x18

    .line 34
    .line 35
    invoke-direct {v0, v1, v2, v5}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    new-instance v1, Lne0/n;

    .line 39
    .line 40
    invoke-direct {v1, v0, v4}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    new-instance v1, Lnz/g;

    .line 48
    .line 49
    const/16 v4, 0x1c

    .line 50
    .line 51
    invoke-direct {v1, p0, v2, v4}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    new-instance v4, Lne0/n;

    .line 55
    .line 56
    invoke-direct {v4, v0, v1, v3}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 57
    .line 58
    .line 59
    new-instance v0, Lbv0/d;

    .line 60
    .line 61
    invoke-direct {v0, p0, v2}, Lbv0/d;-><init>(Lrt0/o;Lkotlin/coroutines/Continuation;)V

    .line 62
    .line 63
    .line 64
    new-instance p0, Lyy0/x;

    .line 65
    .line 66
    invoke-direct {p0, v4, v0}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 67
    .line 68
    .line 69
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lst0/h;

    .line 4
    .line 5
    invoke-virtual {p0}, Lrt0/o;->b()Lyy0/x;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
