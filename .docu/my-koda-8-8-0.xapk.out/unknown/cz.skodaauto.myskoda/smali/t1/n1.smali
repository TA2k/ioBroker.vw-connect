.class public final Lt1/n1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Lb81/d;

.field public b:Lb81/d;

.field public c:I

.field public d:Ljava/lang/Long;

.field public e:Z


# virtual methods
.method public final a(Ll4/v;)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lt1/n1;->e:Z

    .line 3
    .line 4
    iget-object v0, p0, Lt1/n1;->a:Lb81/d;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Ll4/v;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object v0, v1

    .line 15
    :goto_0
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    goto/16 :goto_5

    .line 22
    .line 23
    :cond_1
    iget-object v0, p1, Ll4/v;->a:Lg4/g;

    .line 24
    .line 25
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v2, p0, Lt1/n1;->a:Lb81/d;

    .line 28
    .line 29
    if-eqz v2, :cond_2

    .line 30
    .line 31
    iget-object v2, v2, Lb81/d;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v2, Ll4/v;

    .line 34
    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    iget-object v2, v2, Ll4/v;->a:Lg4/g;

    .line 38
    .line 39
    iget-object v2, v2, Lg4/g;->e:Ljava/lang/String;

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    move-object v2, v1

    .line 43
    :goto_1
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_3

    .line 48
    .line 49
    iget-object p0, p0, Lt1/n1;->a:Lb81/d;

    .line 50
    .line 51
    if-eqz p0, :cond_8

    .line 52
    .line 53
    iput-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 54
    .line 55
    return-void

    .line 56
    :cond_3
    iget-object v0, p0, Lt1/n1;->a:Lb81/d;

    .line 57
    .line 58
    new-instance v2, Lb81/d;

    .line 59
    .line 60
    const/16 v3, 0x15

    .line 61
    .line 62
    invoke-direct {v2, v3, v0, p1}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iput-object v2, p0, Lt1/n1;->a:Lb81/d;

    .line 66
    .line 67
    iput-object v1, p0, Lt1/n1;->b:Lb81/d;

    .line 68
    .line 69
    iget v0, p0, Lt1/n1;->c:I

    .line 70
    .line 71
    iget-object p1, p1, Ll4/v;->a:Lg4/g;

    .line 72
    .line 73
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 74
    .line 75
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    add-int/2addr p1, v0

    .line 80
    iput p1, p0, Lt1/n1;->c:I

    .line 81
    .line 82
    const v0, 0x186a0

    .line 83
    .line 84
    .line 85
    if-le p1, v0, :cond_8

    .line 86
    .line 87
    iget-object p0, p0, Lt1/n1;->a:Lb81/d;

    .line 88
    .line 89
    if-eqz p0, :cond_4

    .line 90
    .line 91
    iget-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast p1, Lb81/d;

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_4
    move-object p1, v1

    .line 97
    :goto_2
    if-nez p1, :cond_5

    .line 98
    .line 99
    goto :goto_5

    .line 100
    :cond_5
    :goto_3
    if-eqz p0, :cond_6

    .line 101
    .line 102
    iget-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast p1, Lb81/d;

    .line 105
    .line 106
    if-eqz p1, :cond_6

    .line 107
    .line 108
    iget-object p1, p1, Lb81/d;->e:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast p1, Lb81/d;

    .line 111
    .line 112
    goto :goto_4

    .line 113
    :cond_6
    move-object p1, v1

    .line 114
    :goto_4
    if-eqz p1, :cond_7

    .line 115
    .line 116
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast p0, Lb81/d;

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_7
    if-eqz p0, :cond_8

    .line 122
    .line 123
    iput-object v1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 124
    .line 125
    :cond_8
    :goto_5
    return-void
.end method
