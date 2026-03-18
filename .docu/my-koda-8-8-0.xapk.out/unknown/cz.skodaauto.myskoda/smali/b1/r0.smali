.class public final Lb1/r0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lb1/s0;


# direct methods
.method public synthetic constructor <init>(Lb1/s0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb1/r0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/r0;->g:Lb1/s0;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lb1/r0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lc1/r1;

    .line 7
    .line 8
    sget-object v0, Lb1/i0;->d:Lb1/i0;

    .line 9
    .line 10
    sget-object v1, Lb1/i0;->e:Lb1/i0;

    .line 11
    .line 12
    invoke-interface {p1, v0, v1}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object p0, p0, Lb1/r0;->g:Lb1/s0;

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    iget-object p0, p0, Lb1/s0;->w:Lb1/t0;

    .line 21
    .line 22
    iget-object p0, p0, Lb1/t0;->a:Lb1/i1;

    .line 23
    .line 24
    iget-object p0, p0, Lb1/i1;->b:Lb1/g1;

    .line 25
    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    iget-object p0, p0, Lb1/g1;->b:Lc1/a0;

    .line 29
    .line 30
    if-nez p0, :cond_4

    .line 31
    .line 32
    :cond_0
    sget-object p0, Lb1/o0;->c:Lc1/f1;

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    sget-object v0, Lb1/i0;->f:Lb1/i0;

    .line 36
    .line 37
    invoke-interface {p1, v1, v0}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_3

    .line 42
    .line 43
    iget-object p0, p0, Lb1/s0;->x:Lb1/u0;

    .line 44
    .line 45
    iget-object p0, p0, Lb1/u0;->a:Lb1/i1;

    .line 46
    .line 47
    iget-object p0, p0, Lb1/i1;->b:Lb1/g1;

    .line 48
    .line 49
    if-eqz p0, :cond_2

    .line 50
    .line 51
    iget-object p0, p0, Lb1/g1;->b:Lc1/a0;

    .line 52
    .line 53
    if-nez p0, :cond_4

    .line 54
    .line 55
    :cond_2
    sget-object p0, Lb1/o0;->c:Lc1/f1;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_3
    sget-object p0, Lb1/o0;->c:Lc1/f1;

    .line 59
    .line 60
    :cond_4
    :goto_0
    return-object p0

    .line 61
    :pswitch_0
    check-cast p1, Lc1/r1;

    .line 62
    .line 63
    sget-object v0, Lb1/i0;->d:Lb1/i0;

    .line 64
    .line 65
    sget-object v1, Lb1/i0;->e:Lb1/i0;

    .line 66
    .line 67
    invoke-interface {p1, v0, v1}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    const/4 v2, 0x0

    .line 72
    iget-object p0, p0, Lb1/r0;->g:Lb1/s0;

    .line 73
    .line 74
    if-eqz v0, :cond_5

    .line 75
    .line 76
    iget-object p0, p0, Lb1/s0;->w:Lb1/t0;

    .line 77
    .line 78
    iget-object p0, p0, Lb1/t0;->a:Lb1/i1;

    .line 79
    .line 80
    iget-object p0, p0, Lb1/i1;->c:Lb1/c0;

    .line 81
    .line 82
    if-eqz p0, :cond_7

    .line 83
    .line 84
    iget-object v2, p0, Lb1/c0;->c:Lc1/a0;

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_5
    sget-object v0, Lb1/i0;->f:Lb1/i0;

    .line 88
    .line 89
    invoke-interface {p1, v1, v0}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    if-eqz p1, :cond_6

    .line 94
    .line 95
    iget-object p0, p0, Lb1/s0;->x:Lb1/u0;

    .line 96
    .line 97
    iget-object p0, p0, Lb1/u0;->a:Lb1/i1;

    .line 98
    .line 99
    iget-object p0, p0, Lb1/i1;->c:Lb1/c0;

    .line 100
    .line 101
    if-eqz p0, :cond_7

    .line 102
    .line 103
    iget-object v2, p0, Lb1/c0;->c:Lc1/a0;

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_6
    sget-object v2, Lb1/o0;->d:Lc1/f1;

    .line 107
    .line 108
    :cond_7
    :goto_1
    if-nez v2, :cond_8

    .line 109
    .line 110
    sget-object v2, Lb1/o0;->d:Lc1/f1;

    .line 111
    .line 112
    :cond_8
    return-object v2

    .line 113
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
