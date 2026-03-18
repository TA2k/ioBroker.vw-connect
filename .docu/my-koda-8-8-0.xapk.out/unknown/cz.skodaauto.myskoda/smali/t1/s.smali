.class public final synthetic Lt1/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lt1/p0;

.field public final synthetic e:Lc3/q;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Le2/w0;

.field public final synthetic i:Ll4/p;


# direct methods
.method public synthetic constructor <init>(Lt1/p0;Lc3/q;ZZLe2/w0;Ll4/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/s;->d:Lt1/p0;

    .line 5
    .line 6
    iput-object p2, p0, Lt1/s;->e:Lc3/q;

    .line 7
    .line 8
    iput-boolean p3, p0, Lt1/s;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lt1/s;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, Lt1/s;->h:Le2/w0;

    .line 13
    .line 14
    iput-object p6, p0, Lt1/s;->i:Ll4/p;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Ld3/b;

    .line 2
    .line 3
    iget-object v0, p0, Lt1/s;->d:Lt1/p0;

    .line 4
    .line 5
    invoke-virtual {v0}, Lt1/p0;->b()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    iget-object v1, p0, Lt1/s;->e:Lc3/q;

    .line 12
    .line 13
    invoke-static {v1}, Lc3/q;->b(Lc3/q;)V

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    iget-boolean v1, p0, Lt1/s;->f:Z

    .line 18
    .line 19
    if-nez v1, :cond_1

    .line 20
    .line 21
    iget-object v1, v0, Lt1/p0;->c:Lw3/b2;

    .line 22
    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    check-cast v1, Lw3/i1;

    .line 26
    .line 27
    invoke-virtual {v1}, Lw3/i1;->b()V

    .line 28
    .line 29
    .line 30
    :cond_1
    :goto_0
    invoke-virtual {v0}, Lt1/p0;->b()Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_3

    .line 35
    .line 36
    iget-boolean v1, p0, Lt1/s;->g:Z

    .line 37
    .line 38
    if-eqz v1, :cond_3

    .line 39
    .line 40
    invoke-virtual {v0}, Lt1/p0;->a()Lt1/c0;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    sget-object v2, Lt1/c0;->e:Lt1/c0;

    .line 45
    .line 46
    if-eq v1, v2, :cond_2

    .line 47
    .line 48
    invoke-virtual {v0}, Lt1/p0;->d()Lt1/j1;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    if-eqz v1, :cond_3

    .line 53
    .line 54
    iget-wide v2, p1, Ld3/b;->a:J

    .line 55
    .line 56
    iget-object p1, v0, Lt1/p0;->d:Lb81/a;

    .line 57
    .line 58
    iget-object v4, v0, Lt1/p0;->v:Lt1/r;

    .line 59
    .line 60
    const/4 v5, 0x1

    .line 61
    invoke-virtual {v1, v2, v3, v5}, Lt1/j1;->b(JZ)I

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    iget-object p0, p0, Lt1/s;->i:Ll4/p;

    .line 66
    .line 67
    invoke-interface {p0, v1}, Ll4/p;->E(I)I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    iget-object p1, p1, Lb81/a;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p1, Ll4/v;

    .line 74
    .line 75
    invoke-static {p0, p0}, Lg4/f0;->b(II)J

    .line 76
    .line 77
    .line 78
    move-result-wide v1

    .line 79
    const/4 p0, 0x5

    .line 80
    const/4 v3, 0x0

    .line 81
    invoke-static {p1, v3, v1, v2, p0}, Ll4/v;->a(Ll4/v;Lg4/g;JI)Ll4/v;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-virtual {v4, p0}, Lt1/r;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    iget-object p0, v0, Lt1/p0;->a:Lt1/v0;

    .line 89
    .line 90
    iget-object p0, p0, Lt1/v0;->a:Lg4/g;

    .line 91
    .line 92
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 93
    .line 94
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    if-lez p0, :cond_3

    .line 99
    .line 100
    sget-object p0, Lt1/c0;->f:Lt1/c0;

    .line 101
    .line 102
    iget-object p1, v0, Lt1/p0;->k:Ll2/j1;

    .line 103
    .line 104
    invoke-virtual {p1, p0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_2
    iget-object p0, p0, Lt1/s;->h:Le2/w0;

    .line 109
    .line 110
    invoke-virtual {p0, p1}, Le2/w0;->g(Ld3/b;)V

    .line 111
    .line 112
    .line 113
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object p0
.end method
