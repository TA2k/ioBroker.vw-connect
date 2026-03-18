.class public final Lh11/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh11/g;


# static fields
.field public static final a:Lhu/q;

.field public static final b:Lhu/q;

.field public static final c:Lhu/q;

.field public static final d:Lhu/q;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    invoke-static {}, Lhu/q;->f()Lh6/e;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/16 v1, 0x30

    .line 6
    .line 7
    const/16 v2, 0x39

    .line 8
    .line 9
    invoke-virtual {v0, v1, v2}, Lh6/e;->y(CC)V

    .line 10
    .line 11
    .line 12
    const/16 v3, 0x46

    .line 13
    .line 14
    const/16 v4, 0x41

    .line 15
    .line 16
    invoke-virtual {v0, v4, v3}, Lh6/e;->y(CC)V

    .line 17
    .line 18
    .line 19
    const/16 v3, 0x66

    .line 20
    .line 21
    const/16 v5, 0x61

    .line 22
    .line 23
    invoke-virtual {v0, v5, v3}, Lh6/e;->y(CC)V

    .line 24
    .line 25
    .line 26
    new-instance v3, Lhu/q;

    .line 27
    .line 28
    invoke-direct {v3, v0}, Lhu/q;-><init>(Lh6/e;)V

    .line 29
    .line 30
    .line 31
    sput-object v3, Lh11/e;->a:Lhu/q;

    .line 32
    .line 33
    invoke-static {}, Lhu/q;->f()Lh6/e;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-virtual {v0, v1, v2}, Lh6/e;->y(CC)V

    .line 38
    .line 39
    .line 40
    new-instance v3, Lhu/q;

    .line 41
    .line 42
    invoke-direct {v3, v0}, Lhu/q;-><init>(Lh6/e;)V

    .line 43
    .line 44
    .line 45
    sput-object v3, Lh11/e;->b:Lhu/q;

    .line 46
    .line 47
    invoke-static {}, Lhu/q;->f()Lh6/e;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    const/16 v3, 0x5a

    .line 52
    .line 53
    invoke-virtual {v0, v4, v3}, Lh6/e;->y(CC)V

    .line 54
    .line 55
    .line 56
    const/16 v3, 0x7a

    .line 57
    .line 58
    invoke-virtual {v0, v5, v3}, Lh6/e;->y(CC)V

    .line 59
    .line 60
    .line 61
    new-instance v3, Lhu/q;

    .line 62
    .line 63
    invoke-direct {v3, v0}, Lhu/q;-><init>(Lh6/e;)V

    .line 64
    .line 65
    .line 66
    sput-object v3, Lh11/e;->c:Lhu/q;

    .line 67
    .line 68
    invoke-virtual {v3}, Lhu/q;->J()Lh6/e;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    invoke-virtual {v0, v1, v2}, Lh6/e;->y(CC)V

    .line 73
    .line 74
    .line 75
    new-instance v1, Lhu/q;

    .line 76
    .line 77
    invoke-direct {v1, v0}, Lhu/q;-><init>(Lh6/e;)V

    .line 78
    .line 79
    .line 80
    sput-object v1, Lh11/e;->d:Lhu/q;

    .line 81
    .line 82
    return-void
.end method

.method public static b(Lb8/i;Lh11/h;)Lvp/y1;
    .locals 3

    .line 1
    invoke-virtual {p1}, Lh11/h;->n()Lb8/i;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1, p0, v0}, Lh11/h;->e(Lb8/i;Lb8/i;)Lbn/c;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Lbn/c;->i()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    new-instance v0, Lj11/y;

    .line 14
    .line 15
    invoke-static {p0}, Li11/b;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-direct {v0, p0}, Lj11/y;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1}, Lh11/h;->n()Lb8/i;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    new-instance p1, Lvp/y1;

    .line 27
    .line 28
    const/16 v1, 0x8

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-direct {p1, v0, p0, v2, v1}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    return-object p1
.end method


# virtual methods
.method public final a(Lg11/l;)Lvp/y1;
    .locals 3

    .line 1
    iget-object p0, p1, Lg11/l;->e:Lh11/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lh11/h;->m()C

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/16 v1, 0x23

    .line 15
    .line 16
    const/16 v2, 0x3b

    .line 17
    .line 18
    if-ne v0, v1, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 21
    .line 22
    .line 23
    const/16 v0, 0x78

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Lh11/h;->k(C)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    const/4 v1, 0x1

    .line 30
    if-nez v0, :cond_1

    .line 31
    .line 32
    const/16 v0, 0x58

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Lh11/h;->k(C)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    sget-object v0, Lh11/e;->b:Lhu/q;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Lh11/h;->g(Lhu/q;)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-gt v1, v0, :cond_3

    .line 48
    .line 49
    const/4 v1, 0x7

    .line 50
    if-gt v0, v1, :cond_3

    .line 51
    .line 52
    invoke-virtual {p0, v2}, Lh11/h;->k(C)Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-eqz v0, :cond_3

    .line 57
    .line 58
    invoke-static {p1, p0}, Lh11/e;->b(Lb8/i;Lh11/h;)Lvp/y1;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :cond_1
    :goto_0
    sget-object v0, Lh11/e;->a:Lhu/q;

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Lh11/h;->g(Lhu/q;)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-gt v1, v0, :cond_3

    .line 70
    .line 71
    const/4 v1, 0x6

    .line 72
    if-gt v0, v1, :cond_3

    .line 73
    .line 74
    invoke-virtual {p0, v2}, Lh11/h;->k(C)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-eqz v0, :cond_3

    .line 79
    .line 80
    invoke-static {p1, p0}, Lh11/e;->b(Lb8/i;Lh11/h;)Lvp/y1;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :cond_2
    sget-object v1, Lh11/e;->c:Lhu/q;

    .line 86
    .line 87
    iget-object v1, v1, Lhu/q;->e:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v1, Ljava/util/BitSet;

    .line 90
    .line 91
    invoke-virtual {v1, v0}, Ljava/util/BitSet;->get(I)Z

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-eqz v0, :cond_3

    .line 96
    .line 97
    sget-object v0, Lh11/e;->d:Lhu/q;

    .line 98
    .line 99
    invoke-virtual {p0, v0}, Lh11/h;->g(Lhu/q;)I

    .line 100
    .line 101
    .line 102
    invoke-virtual {p0, v2}, Lh11/h;->k(C)Z

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    if-eqz v0, :cond_3

    .line 107
    .line 108
    invoke-static {p1, p0}, Lh11/e;->b(Lb8/i;Lh11/h;)Lvp/y1;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    return-object p0

    .line 113
    :cond_3
    const/4 p0, 0x0

    .line 114
    return-object p0
.end method
