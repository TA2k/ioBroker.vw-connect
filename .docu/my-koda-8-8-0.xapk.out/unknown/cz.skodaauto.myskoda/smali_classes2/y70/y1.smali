.class public final Ly70/y1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lw70/r;

.field public final i:Lij0/a;


# direct methods
.method public constructor <init>(Lw70/r;Lw70/k;Lij0/a;)V
    .locals 12

    .line 1
    new-instance v0, Ly70/x1;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    invoke-direct/range {v0 .. v5}, Ly70/x1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Ly70/y1;->h:Lw70/r;

    .line 16
    .line 17
    iput-object p3, p0, Ly70/y1;->i:Lij0/a;

    .line 18
    .line 19
    invoke-virtual {p2}, Lw70/k;->invoke()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    check-cast p1, Lcq0/i;

    .line 24
    .line 25
    if-eqz p1, :cond_2

    .line 26
    .line 27
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    check-cast p2, Ly70/x1;

    .line 32
    .line 33
    iget-object v0, p1, Lcq0/i;->b:Ljava/util/ArrayList;

    .line 34
    .line 35
    new-instance v4, Lw81/c;

    .line 36
    .line 37
    const/16 p3, 0x1d

    .line 38
    .line 39
    invoke-direct {v4, p0, p3}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 40
    .line 41
    .line 42
    const/16 v5, 0x1f

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    const/4 v2, 0x0

    .line 46
    const/4 v3, 0x0

    .line 47
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    iget-object p3, p1, Lcq0/i;->c:Ljava/time/OffsetDateTime;

    .line 52
    .line 53
    const/4 v0, 0x0

    .line 54
    if-eqz p3, :cond_0

    .line 55
    .line 56
    invoke-static {p3}, Lvo/a;->i(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p3

    .line 60
    move-object v8, p3

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    move-object v8, v0

    .line 63
    :goto_0
    iget-object p3, p1, Lcq0/i;->d:Ljava/time/OffsetDateTime;

    .line 64
    .line 65
    if-eqz p3, :cond_1

    .line 66
    .line 67
    invoke-static {p3}, Lvo/a;->i(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    :cond_1
    move-object v9, v0

    .line 72
    iget-boolean v11, p1, Lcq0/i;->f:Z

    .line 73
    .line 74
    iget-object v10, p1, Lcq0/i;->e:Ljava/lang/String;

    .line 75
    .line 76
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    const-string p1, "serviceOperations"

    .line 80
    .line 81
    invoke-static {v7, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    new-instance v6, Ly70/x1;

    .line 85
    .line 86
    invoke-direct/range {v6 .. v11}, Ly70/x1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0, v6}, Lql0/j;->g(Lql0/h;)V

    .line 90
    .line 91
    .line 92
    :cond_2
    return-void
.end method
