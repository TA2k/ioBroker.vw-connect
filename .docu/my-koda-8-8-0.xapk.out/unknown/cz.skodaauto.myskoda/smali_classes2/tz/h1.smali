.class public final Ltz/h1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lqd0/k1;

.field public final i:Ltr0/b;

.field public final j:Lqf0/g;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lqd0/o0;Lqd0/k1;Ltr0/b;Lqf0/g;Lij0/a;)V
    .locals 11

    .line 1
    new-instance v0, Ltz/f1;

    .line 2
    .line 3
    sget-object v6, Lrd0/v;->f:Lgy0/j;

    .line 4
    .line 5
    const/4 v7, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/16 v4, 0x64

    .line 10
    .line 11
    const-string v5, ""

    .line 12
    .line 13
    const/4 v8, 0x0

    .line 14
    const/4 v9, 0x0

    .line 15
    const/4 v10, 0x0

    .line 16
    invoke-direct/range {v0 .. v10}, Ltz/f1;-><init>(ZZZILjava/lang/String;Lgy0/j;ZLjava/lang/Integer;Ljava/lang/String;Lql0/g;)V

    .line 17
    .line 18
    .line 19
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 20
    .line 21
    .line 22
    iput-object p2, p0, Ltz/h1;->h:Lqd0/k1;

    .line 23
    .line 24
    iput-object p3, p0, Ltz/h1;->i:Ltr0/b;

    .line 25
    .line 26
    iput-object p4, p0, Ltz/h1;->j:Lqf0/g;

    .line 27
    .line 28
    move-object/from16 p2, p5

    .line 29
    .line 30
    iput-object p2, p0, Ltz/h1;->k:Lij0/a;

    .line 31
    .line 32
    new-instance p2, Lr60/t;

    .line 33
    .line 34
    const/4 p3, 0x0

    .line 35
    const/16 p4, 0x17

    .line 36
    .line 37
    invoke-direct {p2, p4, p1, p0, p3}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final h(ILjava/lang/Integer;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltz/h1;->k:Lij0/a;

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    new-array p1, p1, [Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljj0/f;

    .line 9
    .line 10
    const p2, 0x7f1203fc

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p2, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-le p1, v0, :cond_1

    .line 23
    .line 24
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p0, Ljj0/f;

    .line 29
    .line 30
    const p2, 0x7f120459

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, p2, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :cond_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-ne p1, v0, :cond_2

    .line 43
    .line 44
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    check-cast p0, Ljj0/f;

    .line 49
    .line 50
    const p2, 0x7f120453

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, p2, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :cond_2
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    check-cast p0, Ljj0/f;

    .line 63
    .line 64
    const p2, 0x7f120463

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0, p2, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method
