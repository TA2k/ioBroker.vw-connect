.class public final Lyb0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/b0;

.field public final b:Lwr0/h;

.field public final c:Lcc0/g;

.field public final d:Lcc0/e;

.field public final e:Lyb0/c;


# direct methods
.method public constructor <init>(Lkf0/b0;Lwr0/h;Lcc0/g;Lcc0/e;Lyb0/c;Lyb0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyb0/l;->a:Lkf0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lyb0/l;->b:Lwr0/h;

    .line 7
    .line 8
    iput-object p3, p0, Lyb0/l;->c:Lcc0/g;

    .line 9
    .line 10
    iput-object p4, p0, Lyb0/l;->d:Lcc0/e;

    .line 11
    .line 12
    iput-object p5, p0, Lyb0/l;->e:Lyb0/c;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lyb0/i;)Lzy0/j;
    .locals 6

    .line 1
    iget-object v0, p1, Lyb0/i;->d:Lyb0/h;

    .line 2
    .line 3
    sget-object v1, Lyb0/e;->a:Lyb0/e;

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    new-instance v0, Lyy0/m;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const-string v2, "+"

    .line 15
    .line 16
    invoke-direct {v0, v2, v1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_0
    sget-object v1, Lyb0/f;->a:Lyb0/f;

    .line 21
    .line 22
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    iget-object v0, p0, Lyb0/l;->a:Lkf0/b0;

    .line 29
    .line 30
    invoke-virtual {v0}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    check-cast v0, Lyy0/i;

    .line 35
    .line 36
    new-instance v1, Lrz/k;

    .line 37
    .line 38
    const/16 v2, 0x13

    .line 39
    .line 40
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 41
    .line 42
    .line 43
    :goto_0
    move-object v0, v1

    .line 44
    goto :goto_1

    .line 45
    :cond_1
    instance-of v1, v0, Lyb0/g;

    .line 46
    .line 47
    if-eqz v1, :cond_4

    .line 48
    .line 49
    check-cast v0, Lyb0/g;

    .line 50
    .line 51
    iget-object v0, v0, Lyb0/g;->a:Ljava/lang/String;

    .line 52
    .line 53
    new-instance v1, Lyy0/m;

    .line 54
    .line 55
    const/4 v2, 0x0

    .line 56
    invoke-direct {v1, v0, v2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :goto_1
    iget-object v1, p1, Lyb0/i;->e:Lyb0/d;

    .line 61
    .line 62
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_3

    .line 67
    .line 68
    const/4 v2, 0x1

    .line 69
    if-ne v1, v2, :cond_2

    .line 70
    .line 71
    new-instance v1, Lyy0/m;

    .line 72
    .line 73
    const/4 v2, 0x0

    .line 74
    const-string v3, "ALL"

    .line 75
    .line 76
    invoke-direct {v1, v3, v2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_2
    new-instance p0, La8/r0;

    .line 81
    .line 82
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 83
    .line 84
    .line 85
    throw p0

    .line 86
    :cond_3
    iget-object v1, p0, Lyb0/l;->b:Lwr0/h;

    .line 87
    .line 88
    invoke-virtual {v1}, Lwr0/h;->invoke()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    check-cast v1, Lyy0/i;

    .line 93
    .line 94
    :goto_2
    new-instance v2, Lbn0/d;

    .line 95
    .line 96
    const/4 v3, 0x3

    .line 97
    const/4 v4, 0x1

    .line 98
    const/4 v5, 0x0

    .line 99
    invoke-direct {v2, v3, v5, v4}, Lbn0/d;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 100
    .line 101
    .line 102
    new-instance v3, Lbn0/f;

    .line 103
    .line 104
    const/4 v4, 0x5

    .line 105
    invoke-direct {v3, v0, v1, v2, v4}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 106
    .line 107
    .line 108
    new-instance v0, Lo20/c;

    .line 109
    .line 110
    const/16 v1, 0x17

    .line 111
    .line 112
    invoke-direct {v0, v1, p1, p0, v5}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 113
    .line 114
    .line 115
    invoke-static {v3, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    return-object p0

    .line 120
    :cond_4
    new-instance p0, La8/r0;

    .line 121
    .line 122
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 123
    .line 124
    .line 125
    throw p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lyb0/i;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lyb0/l;->a(Lyb0/i;)Lzy0/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
