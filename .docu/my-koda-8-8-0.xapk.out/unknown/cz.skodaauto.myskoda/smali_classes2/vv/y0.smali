.class public final Lvv/y0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:Ljava/util/ArrayList;

.field public final synthetic g:Ljava/util/ArrayList;

.field public final synthetic h:J

.field public final synthetic i:F


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;Ljava/util/ArrayList;JF)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvv/y0;->f:Ljava/util/ArrayList;

    .line 2
    .line 3
    iput-object p2, p0, Lvv/y0;->g:Ljava/util/ArrayList;

    .line 4
    .line 5
    iput-wide p3, p0, Lvv/y0;->h:J

    .line 6
    .line 7
    iput p5, p0, Lvv/y0;->i:F

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lg3/d;

    .line 3
    .line 4
    const-string p1, "$this$drawBehind"

    .line 5
    .line 6
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget-object p1, p0, Lvv/y0;->f:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    const/4 v11, 0x0

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Ljava/lang/Number;

    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    invoke-static {v11, v1}, Ljp/bf;->a(FF)J

    .line 33
    .line 34
    .line 35
    move-result-wide v3

    .line 36
    invoke-interface {v0}, Lg3/d;->e()J

    .line 37
    .line 38
    .line 39
    move-result-wide v5

    .line 40
    invoke-static {v5, v6}, Ld3/e;->d(J)F

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    invoke-static {v2, v1}, Ljp/bf;->a(FF)J

    .line 45
    .line 46
    .line 47
    move-result-wide v5

    .line 48
    const/4 v9, 0x0

    .line 49
    const/16 v10, 0x1f0

    .line 50
    .line 51
    iget-wide v1, p0, Lvv/y0;->h:J

    .line 52
    .line 53
    iget v7, p0, Lvv/y0;->i:F

    .line 54
    .line 55
    const/4 v8, 0x0

    .line 56
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    iget-object p1, p0, Lvv/y0;->g:Ljava/util/ArrayList;

    .line 61
    .line 62
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_1

    .line 71
    .line 72
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    check-cast v1, Ljava/lang/Number;

    .line 77
    .line 78
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    invoke-static {v1, v11}, Ljp/bf;->a(FF)J

    .line 83
    .line 84
    .line 85
    move-result-wide v3

    .line 86
    invoke-interface {v0}, Lg3/d;->e()J

    .line 87
    .line 88
    .line 89
    move-result-wide v5

    .line 90
    invoke-static {v5, v6}, Ld3/e;->b(J)F

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    invoke-static {v1, v2}, Ljp/bf;->a(FF)J

    .line 95
    .line 96
    .line 97
    move-result-wide v5

    .line 98
    const/4 v9, 0x0

    .line 99
    const/16 v10, 0x1f0

    .line 100
    .line 101
    iget-wide v1, p0, Lvv/y0;->h:J

    .line 102
    .line 103
    iget v7, p0, Lvv/y0;->i:F

    .line 104
    .line 105
    const/4 v8, 0x0

    .line 106
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    return-object p0
.end method
