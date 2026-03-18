.class public final Lhv0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lhv0/z;

.field public final b:Lal0/x0;


# direct methods
.method public constructor <init>(Lhv0/z;Lal0/x0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhv0/t;->a:Lhv0/z;

    .line 5
    .line 6
    iput-object p2, p0, Lhv0/t;->b:Lal0/x0;

    .line 7
    .line 8
    return-void
.end method

.method public static final a(Lhv0/t;Lbl0/h0;)Liv0/f;
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 p1, 0x1

    .line 6
    if-eq p0, p1, :cond_3

    .line 7
    .line 8
    const/4 p1, 0x2

    .line 9
    if-eq p0, p1, :cond_2

    .line 10
    .line 11
    const/4 p1, 0x3

    .line 12
    if-eq p0, p1, :cond_1

    .line 13
    .line 14
    const/4 p1, 0x4

    .line 15
    if-eq p0, p1, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Liv0/h;->a:Liv0/h;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    sget-object p0, Liv0/i;->a:Liv0/i;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_2
    sget-object p0, Liv0/j;->a:Liv0/j;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_3
    sget-object p0, Liv0/c;->a:Liv0/c;

    .line 29
    .line 30
    return-object p0
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lhv0/t;->a:Lhv0/z;

    .line 2
    .line 3
    check-cast v0, Lfv0/c;

    .line 4
    .line 5
    iget-object v0, v0, Lfv0/c;->b:Lyy0/l1;

    .line 6
    .line 7
    iget-object v1, p0, Lhv0/t;->b:Lal0/x0;

    .line 8
    .line 9
    invoke-virtual {v1}, Lal0/x0;->invoke()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lyy0/i;

    .line 14
    .line 15
    new-instance v2, Lhk0/a;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    const/4 v4, 0x2

    .line 19
    invoke-direct {v2, p0, v3, v4}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    new-instance p0, Lbn0/f;

    .line 23
    .line 24
    const/4 v3, 0x5

    .line 25
    invoke-direct {p0, v0, v1, v2, v3}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 26
    .line 27
    .line 28
    new-instance v0, Lam0/i;

    .line 29
    .line 30
    const/4 v1, 0x7

    .line 31
    invoke-direct {v0, p0, v1}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method
