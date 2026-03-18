.class public final Lz4/c;
.super Ldy0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz4/e;


# direct methods
.method public constructor <init>(Lz4/e;F)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lz4/c;->d:I

    .line 3
    iput-object p1, p0, Lz4/c;->e:Lz4/e;

    .line 4
    new-instance p1, Lt4/f;

    invoke-direct {p1, p2}, Lt4/f;-><init>(F)V

    .line 5
    invoke-direct {p0, p1}, Ldy0/a;-><init>(Ljava/lang/Object;)V

    return-void
.end method

.method public constructor <init>(Lz4/e;Lz4/n;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lz4/c;->d:I

    .line 1
    iput-object p1, p0, Lz4/c;->e:Lz4/e;

    .line 2
    invoke-direct {p0, p2}, Ldy0/a;-><init>(Ljava/lang/Object;)V

    return-void
.end method


# virtual methods
.method public final afterChange(Lhy0/z;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 5

    .line 1
    iget v0, p0, Lz4/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p2, Lt4/f;

    .line 7
    .line 8
    iget p2, p2, Lt4/f;->d:F

    .line 9
    .line 10
    check-cast p3, Lt4/f;

    .line 11
    .line 12
    iget p2, p3, Lt4/f;->d:F

    .line 13
    .line 14
    invoke-static {p2}, Ljava/lang/Float;->isNaN(F)Z

    .line 15
    .line 16
    .line 17
    move-result p3

    .line 18
    if-nez p3, :cond_0

    .line 19
    .line 20
    iget-object p0, p0, Lz4/c;->e:Lz4/e;

    .line 21
    .line 22
    iget-object p0, p0, Lz4/e;->b:Ld5/f;

    .line 23
    .line 24
    invoke-interface {p1}, Lhy0/c;->getName()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    new-instance p3, Ld5/e;

    .line 29
    .line 30
    invoke-direct {p3, p2}, Ld5/e;-><init>(F)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, p1, p3}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    return-void

    .line 37
    :pswitch_0
    check-cast p2, Lz4/n;

    .line 38
    .line 39
    check-cast p3, Lz4/n;

    .line 40
    .line 41
    iget-object p0, p0, Lz4/c;->e:Lz4/e;

    .line 42
    .line 43
    iget-object p0, p0, Lz4/e;->b:Ld5/f;

    .line 44
    .line 45
    invoke-interface {p1}, Lhy0/c;->getName()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    const-string p2, "null cannot be cast to non-null type androidx.constraintlayout.compose.DimensionDescription"

    .line 50
    .line 51
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget-object p2, p3, Lz4/n;->a:Lb81/d;

    .line 55
    .line 56
    iget-object v0, p3, Lz4/n;->c:Lb81/d;

    .line 57
    .line 58
    iget-object v1, v0, Lb81/d;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v1, Ljava/lang/String;

    .line 61
    .line 62
    iget-object p3, p3, Lz4/n;->b:Lb81/d;

    .line 63
    .line 64
    iget-object v2, p3, Lb81/d;->e:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v2, Ljava/lang/String;

    .line 67
    .line 68
    if-nez v2, :cond_1

    .line 69
    .line 70
    if-nez v1, :cond_1

    .line 71
    .line 72
    invoke-virtual {p2}, Lb81/d;->f()Ld5/c;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    goto :goto_2

    .line 77
    :cond_1
    new-instance v3, Ld5/f;

    .line 78
    .line 79
    const/4 v4, 0x0

    .line 80
    new-array v4, v4, [C

    .line 81
    .line 82
    invoke-direct {v3, v4}, Ld5/b;-><init>([C)V

    .line 83
    .line 84
    .line 85
    if-nez v2, :cond_2

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_2
    const-string v2, "min"

    .line 89
    .line 90
    invoke-virtual {p3}, Lb81/d;->f()Ld5/c;

    .line 91
    .line 92
    .line 93
    move-result-object p3

    .line 94
    invoke-virtual {v3, v2, p3}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 95
    .line 96
    .line 97
    :goto_0
    if-nez v1, :cond_3

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_3
    const-string p3, "max"

    .line 101
    .line 102
    invoke-virtual {v0}, Lb81/d;->f()Ld5/c;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    invoke-virtual {v3, p3, v0}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 107
    .line 108
    .line 109
    :goto_1
    const-string p3, "value"

    .line 110
    .line 111
    invoke-virtual {p2}, Lb81/d;->f()Ld5/c;

    .line 112
    .line 113
    .line 114
    move-result-object p2

    .line 115
    invoke-virtual {v3, p3, p2}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 116
    .line 117
    .line 118
    move-object p2, v3

    .line 119
    :goto_2
    invoke-virtual {p0, p1, p2}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
