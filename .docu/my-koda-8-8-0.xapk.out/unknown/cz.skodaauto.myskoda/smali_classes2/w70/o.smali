.class public final Lw70/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbq0/h;


# direct methods
.method public constructor <init>(Lbq0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/o;->a:Lbq0/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget-object p0, p0, Lw70/o;->a:Lbq0/h;

    .line 2
    .line 3
    check-cast p0, Lzp0/c;

    .line 4
    .line 5
    iget-object v0, p0, Lzp0/c;->j:Ljava/lang/String;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_6

    .line 9
    .line 10
    iget-object v2, p0, Lzp0/c;->h:Ljava/util/List;

    .line 11
    .line 12
    if-eqz v2, :cond_3

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Iterable;

    .line 15
    .line 16
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    :cond_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    if-eqz v3, :cond_1

    .line 25
    .line 26
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    move-object v4, v3

    .line 31
    check-cast v4, Lcq0/j;

    .line 32
    .line 33
    iget-object v4, v4, Lcq0/j;->a:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    if-eqz v4, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    move-object v3, v1

    .line 43
    :goto_0
    check-cast v3, Lcq0/j;

    .line 44
    .line 45
    if-nez v3, :cond_2

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    move-object v1, v3

    .line 49
    goto :goto_2

    .line 50
    :cond_3
    :goto_1
    iget-object p0, p0, Lzp0/c;->i:Ljava/util/List;

    .line 51
    .line 52
    if-eqz p0, :cond_6

    .line 53
    .line 54
    check-cast p0, Ljava/lang/Iterable;

    .line 55
    .line 56
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    :cond_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-eqz v2, :cond_5

    .line 65
    .line 66
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    move-object v3, v2

    .line 71
    check-cast v3, Lcq0/j;

    .line 72
    .line 73
    iget-object v3, v3, Lcq0/j;->a:Ljava/lang/String;

    .line 74
    .line 75
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-eqz v3, :cond_4

    .line 80
    .line 81
    move-object v1, v2

    .line 82
    :cond_5
    check-cast v1, Lcq0/j;

    .line 83
    .line 84
    :cond_6
    :goto_2
    if-eqz v1, :cond_7

    .line 85
    .line 86
    new-instance p0, Lne0/e;

    .line 87
    .line 88
    invoke-direct {p0, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    return-object p0

    .line 92
    :cond_7
    new-instance v2, Lne0/c;

    .line 93
    .line 94
    new-instance v3, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    const-string p0, "Booking detail is not available"

    .line 97
    .line 98
    invoke-direct {v3, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const/4 v6, 0x0

    .line 102
    const/16 v7, 0x1e

    .line 103
    .line 104
    const/4 v4, 0x0

    .line 105
    const/4 v5, 0x0

    .line 106
    invoke-direct/range {v2 .. v7}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 107
    .line 108
    .line 109
    return-object v2
.end method
